//! Recover functions from machine code: where each one starts and ends, its
//! basic blocks, its cyclomatic complexity, and the calls and jumps it makes.
//!
//! The input is an [`Image`]: the mapped bytes of a binary, the addresses
//! already known to start functions (entry points, symbols, exports, unwind
//! tables), and the import slots calls go through. [`object::image`] builds
//! one from ELF, PE and Mach-O bytes; callers with their own parser can fill
//! one in directly.
//!
//! ```no_run
//! # fn main() -> Result<(), funktion::object::Error> {
//! let bytes = std::fs::read("a.out").unwrap_or_default();
//! let image = funktion::object::image(&bytes)?;
//! for function in funktion::recover(&image).functions {
//!     println!("{:#x} {} blocks, complexity {}", function.entry, function.blocks, function.complexity);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Method
//!
//! Functions are found the way a recursive-descent disassembler finds them:
//! every known start is analysed, every direct call target inside executable
//! code becomes a function, and a linear sweep of the executable code adds the
//! targets of calls no analysed path reached. Each function is explored along
//! its direct jumps and branches; a jump to another function's start is a tail
//! call, not part of the function. Basic blocks end at branches, returns,
//! traps and calls that never return, and are split where a branch lands
//! inside them. Complexity is McCabe's `E - N + 2P` over that graph, with `P`
//! the blocks that leave it (returns, traps, indirect jumps).
//!
//! Recovery is a pure function of its input. It reads nothing but the image,
//! never panics, and bounds its work by [`Limits`], so hostile input costs at
//! most the configured budget.

mod arm;
mod arm64;
mod cfg;
pub mod cil;
mod decode;
mod loongarch;
mod m68k;
mod mips;
mod ppc;
mod riscv;
mod s390x;
mod sparc;
mod superh;
use std::borrow::Cow;
use std::ops::Range;

#[cfg(feature = "object")]
pub mod object;
mod table;
mod x86;

/// An instruction set funktion decodes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Arch {
    /// 32-bit x86.
    X86,
    /// 64-bit x86.
    X86_64,
    /// 64-bit Arm (A64).
    Arm64,
    /// 32-bit Arm, A32 and Thumb, little-endian. A Thumb address carries
    /// its mode in bit 0, as Arm symbol tables write it: seeds, function
    /// entries and branch targets in Thumb code are odd.
    Arm,
    /// 32-bit MIPS, big-endian.
    Mips,
    /// 32-bit MIPS, little-endian.
    MipsEl,
    /// 64-bit MIPS, big-endian.
    Mips64,
    /// 64-bit MIPS, little-endian.
    Mips64El,
    /// 32-bit MIPS Release 6, big-endian. Release 6 reuses opcodes earlier
    /// releases had for other instructions, for compact branches, which have
    /// no delay slot.
    MipsR6,
    /// 32-bit MIPS Release 6, little-endian.
    MipsR6El,
    /// 64-bit MIPS Release 6, big-endian.
    Mips64R6,
    /// 64-bit MIPS Release 6, little-endian.
    Mips64R6El,
    /// 64-bit IBM Z (z/Architecture).
    S390x,
    /// 32-bit SPARC.
    Sparc,
    /// 64-bit SPARC (V9).
    Sparc64,
    /// SuperH (SH-2, SH-3, SH-4), little-endian.
    SuperH,
    /// 32-bit PowerPC, big-endian.
    PowerPc,
    /// 64-bit PowerPC, big-endian (the ELFv1 ABI, with function
    /// descriptors).
    PowerPc64,
    /// 64-bit PowerPC, little-endian (the ELFv2 ABI).
    PowerPc64El,
    /// 32-bit RISC-V (RV32), with or without compressed instructions.
    RiscV32,
    /// 64-bit RISC-V (RV64).
    RiscV64,
    /// 64-bit LoongArch (LA64).
    LoongArch64,
    /// The Motorola 68000 family (68020 and later in practice).
    M68k,
}

impl Arch {
    /// Whether the instruction set stores words most significant byte
    /// first.
    #[must_use]
    pub const fn big_endian(self) -> bool {
        matches!(
            self,
            Self::Mips
                | Self::Mips64
                | Self::MipsR6
                | Self::Mips64R6
                | Self::S390x
                | Self::Sparc
                | Self::Sparc64
                | Self::PowerPc
                | Self::PowerPc64
                | Self::M68k
        )
    }

    /// Whether the instruction set is MIPS, of any release.
    pub(crate) const fn mips(self) -> bool {
        matches!(
            self,
            Self::Mips
                | Self::MipsEl
                | Self::Mips64
                | Self::Mips64El
                | Self::MipsR6
                | Self::MipsR6El
                | Self::Mips64R6
                | Self::Mips64R6El
        )
    }

    /// Whether the instruction set is MIPS Release 6.
    pub(crate) const fn mips_r6(self) -> bool {
        matches!(
            self,
            Self::MipsR6 | Self::MipsR6El | Self::Mips64R6 | Self::Mips64R6El
        )
    }

    /// Bytes in an address.
    #[must_use]
    pub const fn address_width(self) -> u8 {
        match self {
            Self::X86
            | Self::Arm
            | Self::Mips
            | Self::MipsEl
            | Self::MipsR6
            | Self::MipsR6El
            | Self::Sparc
            | Self::SuperH
            | Self::PowerPc
            | Self::RiscV32
            | Self::M68k => 4,
            Self::X86_64
            | Self::Arm64
            | Self::Mips64
            | Self::Mips64El
            | Self::Mips64R6
            | Self::Mips64R6El
            | Self::S390x
            | Self::Sparc64
            | Self::PowerPc64
            | Self::PowerPc64El
            | Self::RiscV64
            | Self::LoongArch64 => 8,
        }
    }
}

/// Bytes mapped at a virtual address.
#[derive(Clone, Debug)]
pub struct Segment<'a> {
    /// Virtual address of the first byte.
    pub addr: u64,
    /// The mapped bytes: borrowed from the file, or owned when a loader
    /// would have changed them (an object file's relocations applied).
    pub bytes: Cow<'a, [u8]>,
    /// Whether the bytes are code. Only code is decoded; other segments are
    /// read for jump tables.
    pub executable: bool,
}

/// Why an address is believed to start a function.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Origin {
    /// The program entry point.
    Entry,
    /// The `n`th initializer the loader runs (ELF `DT_INIT` and init arrays).
    Init(u32),
    /// The `n`th finalizer (ELF `DT_FINI` and fini arrays).
    Fini(u32),
    /// The `n`th TLS callback (PE).
    Tls(u32),
    /// A symbol-table entry naming a function, or a Go function-table
    /// (`.gopclntab`) entry.
    Symbol(String),
    /// An exported function.
    Export(String),
    /// The start of a range in an unwind table (ELF `.eh_frame`, PE
    /// `.pdata`): exact compiler output, present in stripped binaries.
    Unwind,
    /// Mach-O `LC_FUNCTION_STARTS`.
    FunctionStarts,
    /// A stub that jumps to an import: an ELF PLT entry, a Mach-O
    /// `__stubs` entry.
    Stub,
    /// A code address the program keeps in a table of addresses: a MIPS
    /// GOT entry, which holds every function whose address is taken
    /// (callbacks a stripped static binary reaches no other way).
    Pointer,
}

/// Code inside a function that no instruction branches to: a landing pad
/// the unwinder enters to run a destructor or a `catch`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Handler {
    /// The start of the function the handler belongs to.
    pub function: u64,
    /// The handler's first instruction.
    pub addr: u64,
}

/// An address believed to start a function, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Seed {
    /// The function's first instruction.
    pub addr: u64,
    /// Where the address came from.
    pub origin: Origin,
}

/// A pointer slot the loader fills with an imported function's address: a PE
/// import-address-table entry, an ELF GOT entry, a Mach-O symbol pointer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Import {
    /// Address of the slot.
    pub slot: u64,
    /// The imported symbol's name, as the binary spells it.
    pub name: String,
}

/// A binary to recover functions from.
#[derive(Clone, Debug)]
pub struct Image<'a> {
    /// The instruction set of the code segments.
    pub arch: Arch,
    /// Every mapped segment, code and data.
    pub segments: Vec<Segment<'a>>,
    /// Addresses known to start functions. Duplicates are harmless.
    pub seeds: Vec<Seed>,
    /// Import slots. Calls through them, and through stubs that only jump
    /// through them, are resolved to the import; calls to imports that never
    /// return end their basic block.
    pub imports: Vec<Import>,
    /// Landing pads, explored as part of the functions they belong to.
    pub handlers: Vec<Handler>,
    /// The code each function spans, by unwind tables that say so (ELF and
    /// Mach-O `.eh_frame`, x86-64 PE `.pdata`), each range starting at its
    /// function's entry. Code inside a range that no path reaches is
    /// explored too, after an indirect jump funktion cannot follow: the
    /// cases of a jump table without a bound.
    pub extents: Vec<Range<u64>>,
    /// The value 32-bit x86 position-independent PLT stubs address the GOT
    /// through (`jmp [ebx + disp]`), when the binary has one; on MIPS, the
    /// address `_gp` stands for, which GOT loads are offsets from; on 64-bit
    /// PowerPC, the TOC pointer `r2` holds (`.TOC.`).
    pub got: Option<u64>,
    /// Slots the loader fills with an address of this binary, and the
    /// address: ELF `RELATIVE` relocations of a position-independent
    /// executable, whose slots hold zero in the file (a GOT slot that holds
    /// a jump table's address, in 32-bit PowerPC PIC code).
    pub rebased: Vec<(u64, u64)>,
}

/// Bounds on the work [`recover_with`] does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Most functions recovered.
    pub functions: usize,
    /// Most instructions decoded, across the sweep and every function.
    pub instructions: usize,
    /// Most entries read from one jump table.
    pub table_entries: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            functions: 1 << 20,
            instructions: 1 << 27,
            table_entries: 512,
        }
    }
}

/// A recovered function.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Function {
    /// Address of the first instruction.
    pub entry: u64,
    /// Bytes from the lowest block start to the highest block end. Blocks
    /// need not be contiguous, so this can exceed the bytes they cover.
    pub size: u64,
    /// Basic blocks.
    pub blocks: u32,
    /// Control-flow edges between blocks, including edges that leave the
    /// function (tail calls) and one per jump-table entry.
    pub edges: u32,
    /// McCabe complexity, `edges - blocks + 2 * exits`.
    pub complexity: u32,
    /// Calls and jumps the function makes, in address order.
    pub refs: Vec<Ref>,
    /// The import slot this function only jumps through: a PLT entry, a
    /// Mach-O stub, an import thunk.
    pub thunk: Option<u64>,
    /// Every way its entry was found.
    pub found: Found,
}

/// A set of ways a function's entry was found. Several often agree; a
/// function found one way only is where tools tend to differ.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Found(u16);

impl Found {
    /// The program entry point.
    pub const ENTRY: Self = Self(1);
    /// An initializer, finalizer or TLS callback the loader runs.
    pub const LOADER: Self = Self(1 << 1);
    /// A symbol-table entry.
    pub const SYMBOL: Self = Self(1 << 2);
    /// An export.
    pub const EXPORT: Self = Self(1 << 3);
    /// An unwind-table range (ELF `.eh_frame`, PE `.pdata`).
    pub const UNWIND: Self = Self(1 << 4);
    /// Mach-O `LC_FUNCTION_STARTS`.
    pub const FUNCTION_STARTS: Self = Self(1 << 5);
    /// A direct call from a recovered function.
    pub const CALL: Self = Self(1 << 6);
    /// A direct call that a linear sweep of the code decoded. Without
    /// [`Found::CALL`], no recovered function makes the call, and the bytes
    /// may not be code at all.
    pub const SWEEP: Self = Self(1 << 7);
    /// A direct jump to code that sets up a stack frame, as only a
    /// function's first instructions do: a tail call.
    pub const TAIL_CALL: Self = Self(1 << 8);
    /// A stub that jumps to an import (an ELF PLT entry, a Mach-O stub).
    pub const STUB: Self = Self(1 << 9);
    /// The program's `main`: the first argument the entry point passes to
    /// the C runtime's start routine.
    pub const MAIN: Self = Self(1 << 10);
    /// A code address held in a table of addresses (a MIPS GOT entry).
    pub const POINTER: Self = Self(1 << 11);

    const NAMES: [(Self, &'static str); 12] = [
        (Self::ENTRY, "ENTRY"),
        (Self::LOADER, "LOADER"),
        (Self::SYMBOL, "SYMBOL"),
        (Self::EXPORT, "EXPORT"),
        (Self::UNWIND, "UNWIND"),
        (Self::FUNCTION_STARTS, "FUNCTION_STARTS"),
        (Self::CALL, "CALL"),
        (Self::SWEEP, "SWEEP"),
        (Self::TAIL_CALL, "TAIL_CALL"),
        (Self::STUB, "STUB"),
        (Self::MAIN, "MAIN"),
        (Self::POINTER, "POINTER"),
    ];

    /// Whether every way in `other` is in `self`.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Whether the set is empty.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The names of the ways in the set, as the constants spell them.
    pub fn names(self) -> impl Iterator<Item = &'static str> {
        Self::NAMES
            .into_iter()
            .filter(move |&(way, _)| self.contains(way))
            .map(|(_, name)| name)
    }
}

impl core::ops::BitOr for Found {
    type Output = Self;
    fn bitor(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

impl core::ops::BitOrAssign for Found {
    fn bitor_assign(&mut self, other: Self) {
        self.0 |= other.0;
    }
}

impl core::fmt::Debug for Found {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut names = self.names();
        match names.next() {
            None => f.write_str("Found(empty)"),
            Some(first) => {
                f.write_str(first)?;
                names.try_for_each(|name| write!(f, " | {name}"))
            }
        }
    }
}

impl From<&Origin> for Found {
    fn from(origin: &Origin) -> Self {
        match origin {
            Origin::Entry => Self::ENTRY,
            Origin::Init(_) | Origin::Fini(_) | Origin::Tls(_) => Self::LOADER,
            Origin::Symbol(_) => Self::SYMBOL,
            Origin::Export(_) => Self::EXPORT,
            Origin::Unwind => Self::UNWIND,
            Origin::FunctionStarts => Self::FUNCTION_STARTS,
            Origin::Stub => Self::STUB,
            Origin::Pointer => Self::POINTER,
        }
    }
}

/// A call or jump instruction and where it goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ref {
    /// Address of the instruction.
    pub from: u64,
    /// The target, or for a transfer through a fixed memory slot (an import
    /// table entry) the address of that slot.
    pub to: u64,
    /// What kind of transfer it is.
    pub kind: RefKind,
}

/// What a [`Ref`] does.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RefKind {
    /// A call.
    Call,
    /// An unconditional jump.
    Jump,
    /// A conditional branch.
    Branch,
    /// One entry of a jump table, from the jump that reads it.
    Case,
}

/// The result of [`recover`], with the facts that say how far to trust it.
/// A caller that falls back to another tool decides when from these: code
/// that recovery mostly does not cover (packed or encrypted code), paths
/// that run into bytes that do not decode (data, or the wrong instruction
/// set), and jumps whose targets are unknown.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Recovery {
    /// Functions in entry-address order.
    pub functions: Vec<Function>,
    /// Bytes of executable code in the image.
    pub code: u64,
    /// Bytes of executable code that lie in some function's instructions.
    pub covered: u64,
    /// Instructions on the paths functions take that do not decode.
    pub invalid: u64,
    /// Indirect jumps whose targets recovery could not determine.
    pub unresolved: u64,
    /// Whether a [`Limits`] bound stopped recovery early.
    pub truncated: bool,
}

/// Recover the functions of `image` under the default [`Limits`].
#[must_use]
pub fn recover(image: &Image<'_>) -> Recovery {
    recover_with(image, &Limits::default())
}

/// Recover the functions of `image`, doing no more work than `limits` allow.
#[must_use]
pub fn recover_with(image: &Image<'_>, limits: &Limits) -> Recovery {
    cfg::recover(image, limits)
}
