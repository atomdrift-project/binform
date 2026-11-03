//! binform answers, in-process, the questions filefacts and stng used to send
//! to rizin: where a binary's functions are, their basic blocks, complexity
//! and calls, and its imports. It does what rizin does for those two tools,
//! and nothing rizin does not.
//!
//! [`parse`] reads ELF, PE and Mach-O bytes into a [`Binary`]; [`functions`](fn@functions)
//! recovers its functions. Each is a pure function of its input: no I/O, no
//! threads, no global state, no panics, and work bounded by [`Limits`],
//! because the input is assumed hostile. A caller pays only for what it
//! calls.
//!
//! ```no_run
//! # fn main() -> Result<(), binform::Error> {
//! let bytes = std::fs::read("a.out").unwrap_or_default();
//! let bin = binform::parse(&bytes)?;
//! for f in binform::functions(&bin, &binform::Limits::DEFAULT).functions {
//!     println!("{:#x} {} blocks, complexity {}", f.entry, f.blocks, f.complexity);
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

#[doc(hidden)]
pub mod diagnostics;
mod calls;
mod functions;
mod isa;
mod layout;
mod syscalls;
#[cfg(test)]
mod tests;

use std::borrow::Cow;
use std::ops::Range;

pub use calls::{Call, Target, Value, calls};
pub use layout::{Error, parse};

/// binform's version, for cache keys: a cache of its answers is stale when
/// this changes.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// An instruction set binform decodes.
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
    /// OpenRISC 1000 (or1k), 32-bit, big-endian.
    OpenRisc,
    /// Xilinx MicroBlaze, 32-bit, big-endian.
    MicroBlaze,
    /// Xilinx MicroBlaze, 32-bit, little-endian.
    MicroBlazeEl,
    /// Synopsys ARCompact (ARC600, ARC700), little-endian.
    Arc,
    /// Synopsys ARCv2 (ARC EM, HS), little-endian.
    ArcV2,
    /// C-SKY ABIv1 (CK510, CK610), little-endian.
    CSky,
    /// Tensilica Xtensa (windowed ABI), little-endian.
    Xtensa,
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
                | Self::OpenRisc
                | Self::MicroBlaze
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
            | Self::M68k
            | Self::OpenRisc
            | Self::MicroBlaze
            | Self::MicroBlazeEl
            | Self::Arc
            | Self::ArcV2
            | Self::CSky
            | Self::Xtensa => 4,
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
pub(crate) struct Segment<'a> {
    /// Virtual address of the first byte.
    pub(crate) addr: u64,
    /// The mapped bytes: borrowed from the file, or owned when a loader
    /// would have changed them (an object file's relocations applied).
    pub(crate) bytes: Cow<'a, [u8]>,
    /// Whether the bytes are code. Only code is decoded; other segments are
    /// read for jump tables.
    pub(crate) executable: bool,
}

/// Why an address is believed to start a function.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Origin {
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
pub(crate) struct Handler {
    /// The start of the function the handler belongs to.
    pub(crate) function: u64,
    /// The handler's first instruction.
    pub(crate) addr: u64,
}

/// An address believed to start a function, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Seed {
    /// The function's first instruction.
    pub(crate) addr: u64,
    /// Where the address came from.
    pub(crate) origin: Origin,
}

/// A pointer slot the loader fills with an imported function's address: a PE
/// import-address-table entry, an ELF GOT entry, a Mach-O symbol pointer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Slot {
    /// Address of the slot.
    pub(crate) slot: u64,
    /// The imported symbol's name, as the binary spells it.
    pub(crate) name: String,
}

/// A container format binform reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Format {
    /// ELF: executables, shared objects and relocatable objects.
    Elf,
    /// PE/COFF images.
    Pe,
    /// Mach-O, thin or one slice of a universal file.
    MachO,
}

/// A section as the headers describe it: rizin's `iS`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Section {
    /// The header's name; Mach-O's is `__SEGMENT.__section`.
    pub name: String,
    /// Virtual address.
    pub addr: u64,
    /// Bytes in memory.
    pub size: u64,
    /// File offset of the bytes the file holds.
    pub offset: u64,
    /// Bytes the file holds: zero for zero-filled sections (`.bss`).
    pub file_size: u64,
    /// Mapped readable.
    pub readable: bool,
    /// Mapped writable.
    pub writable: bool,
    /// Mapped executable.
    pub executable: bool,
}

impl Section {
    /// Whether the loader maps it: ELF sections without `SHF_ALLOC` (symbol
    /// tables, debug information) are only in the file.
    #[must_use]
    pub const fn mapped(&self) -> bool {
        self.readable || self.writable || self.executable
    }
}

/// An imported symbol: rizin's `ii`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Import {
    /// The symbol's name as the binary spells it; `Ordinal_n` for a PE
    /// import by ordinal only.
    pub name: String,
    /// The library it binds to, where the format says: a PE import's DLL,
    /// a Mach-O two-level namespace library.
    pub library: Option<String>,
    /// A PE import by ordinal: the ordinal.
    pub ordinal: Option<u16>,
    /// The first pointer slot the loader fills with its address, if any.
    pub slot: Option<u64>,
}

/// An exported symbol: rizin's `iE`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Export {
    /// The symbol's name as the binary spells it; `Ordinal_n` for a PE
    /// export by ordinal only.
    pub name: String,
    /// Its address.
    pub addr: u64,
    /// For a PE forwarder, the export it forwards to (`NTDLL.RtlAllocateHeap`);
    /// `addr` is then that string's.
    pub forward: Option<String>,
}

/// A parsed binary: what [`parse`] read from its headers, and what
/// [`functions`](fn@functions) needs to recover its functions.
#[derive(Clone, Debug)]
pub struct Binary<'a> {
    /// The container format.
    pub format: Format,
    /// The instruction set of the code segments; `None` for one binform
    /// does not decode, whose binary has its layout and no functions.
    pub arch: Option<Arch>,
    /// The entry point, when the binary has one.
    pub entry: Option<u64>,
    /// Sections in header order.
    pub sections: Vec<Section>,
    /// Imported symbols, one per symbol.
    pub imports: Vec<Import>,
    /// Exported symbols.
    pub exports: Vec<Export>,
    /// Every mapped segment, code and data.
    pub(crate) segments: Vec<Segment<'a>>,
    /// Addresses known to start functions. Duplicates are harmless.
    pub(crate) seeds: Vec<Seed>,
    /// Import slots, one per slot. Calls through them, and through stubs that only jump
    /// through them, are resolved to the import; calls to imports that never
    /// return end their basic block.
    pub(crate) slots: Vec<Slot>,
    /// Landing pads, explored as part of the functions they belong to.
    pub(crate) handlers: Vec<Handler>,
    /// The code each function spans, by unwind tables that say so (ELF and
    /// Mach-O `.eh_frame`, x86-64 PE `.pdata`), each range starting at its
    /// function's entry. Code inside a range that no path reaches is
    /// explored too, after an indirect jump binform cannot follow: the
    /// cases of a jump table without a bound.
    pub(crate) extents: Vec<Range<u64>>,
    /// The value 32-bit x86 position-independent PLT stubs address the GOT
    /// through (`jmp [ebx + disp]`), when the binary has one; on MIPS, the
    /// address `_gp` stands for, which GOT loads are offsets from; on 64-bit
    /// PowerPC, the TOC pointer `r2` holds (`.TOC.`).
    pub(crate) got: Option<u64>,
    /// Slots the loader fills with an address of this binary, and the
    /// address: ELF `RELATIVE` relocations of a position-independent
    /// executable, whose slots hold zero in the file (a GOT slot that holds
    /// a jump table's address, in 32-bit PowerPC PIC code).
    pub(crate) rebased: Vec<(u64, u64)>,
}

impl Binary<'_> {
    /// The mapped section that holds `addr`.
    #[must_use]
    pub fn section_at(&self, addr: u64) -> Option<&Section> {
        self.sections
            .iter()
            .filter(|s| s.mapped())
            .find(|s| addr.wrapping_sub(s.addr) < s.size)
    }

    /// The file offset of `addr`, when a mapped section's file bytes hold
    /// it.
    #[must_use]
    pub fn offset(&self, addr: u64) -> Option<u64> {
        self.sections.iter().filter(|s| s.mapped()).find_map(|s| {
            let delta = addr.wrapping_sub(s.addr);
            (delta < s.file_size).then(|| s.offset.wrapping_add(delta))
        })
    }

    /// The name of syscall `number` in this binary's OS and architecture:
    /// Linux's, for an ELF file. `None` for a number the OS does not name,
    /// and for PE and Mach-O files, whose syscall numbers are not stable.
    #[must_use]
    pub fn syscall(&self, number: u64) -> Option<&'static str> {
        match (self.format, self.arch) {
            (Format::Elf, Some(arch)) => syscalls::name(arch, number),
            _ => None,
        }
    }

    /// The syscall number a libc wrapper such as `connect` issues in this
    /// binary's OS and architecture: the inverse of [`syscall`](Self::syscall),
    /// for resolving an imported wrapper call to the syscall behind it. `None`
    /// for an unknown name, and for PE and Mach-O files.
    #[must_use]
    pub fn syscall_number(&self, name: &str) -> Option<u64> {
        match (self.format, self.arch) {
            (Format::Elf, Some(arch)) => syscalls::number(arch, name),
            _ => None,
        }
    }

    /// The name of the import whose slot is at `slot`: what a [`Ref`] that
    /// goes through a slot (a [`Ref::to`] that is no function's entry)
    /// calls.
    #[must_use]
    pub fn import(&self, slot: u64) -> Option<&str> {
        self.slots
            .iter()
            .find(|s| s.slot == slot)
            .map(|s| s.name.as_str())
    }
}

/// Bounds on the work [`functions`](fn@functions) does.
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
        Self::DEFAULT
    }
}

impl Limits {
    /// Bounds no real binary reaches: a hostile one stops at them.
    pub const DEFAULT: Self = Self {
        functions: 1 << 20,
        instructions: 1 << 27,
        table_entries: 512,
    };

    /// Bounds for a caller that scans many files and wants each answer
    /// quickly: a 64th of the default instruction budget (two million,
    /// tens of milliseconds on most binaries), at the cost of
    /// [`Functions::truncated`] on the largest.
    pub const QUICK: Self = Self {
        functions: 1 << 18,
        instructions: 1 << 21,
        table_entries: 512,
    };
}

/// A recovered function.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Function {
    /// Address of the first instruction.
    pub entry: u64,
    /// What the binary calls it: a symbol, else an export, else (for a stub
    /// that only jumps to an import) the import.
    pub name: Option<String>,
    /// Bytes from the lowest block start to the highest block end. Blocks
    /// need not be contiguous, so this can exceed the bytes they cover.
    pub size: u64,
    /// Basic blocks.
    pub blocks: u32,
    /// McCabe complexity, `edges - blocks + 2 * exits`, where an exit is a
    /// block that leaves the function (a return, a trap, an indirect jump).
    pub complexity: u32,
    /// Calls and jumps the function makes, in address order.
    pub refs: Vec<Ref>,
}

/// A set of ways a function's entry was found. Several often agree; a
/// function found one way only is where tools tend to differ.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub(crate) struct Found(u16);

impl Found {
    /// The program entry point.
    pub(crate) const ENTRY: Self = Self(1);
    /// An initializer, finalizer or TLS callback the loader runs.
    pub(crate) const LOADER: Self = Self(1 << 1);
    /// A symbol-table entry.
    pub(crate) const SYMBOL: Self = Self(1 << 2);
    /// An export.
    pub(crate) const EXPORT: Self = Self(1 << 3);
    /// An unwind-table range (ELF `.eh_frame`, PE `.pdata`).
    pub(crate) const UNWIND: Self = Self(1 << 4);
    /// Mach-O `LC_FUNCTION_STARTS`.
    pub(crate) const FUNCTION_STARTS: Self = Self(1 << 5);
    /// A direct call from a recovered function.
    pub(crate) const CALL: Self = Self(1 << 6);
    /// A direct call that a linear sweep of the code decoded. Without
    /// [`Found::CALL`], no recovered function makes the call, and the bytes
    /// may not be code at all.
    pub(crate) const SWEEP: Self = Self(1 << 7);
    /// A direct jump to code that sets up a stack frame, as only a
    /// function's first instructions do: a tail call.
    pub(crate) const TAIL_CALL: Self = Self(1 << 8);
    /// A stub that jumps to an import (an ELF PLT entry, a Mach-O stub).
    pub(crate) const STUB: Self = Self(1 << 9);
    /// The program's `main`: the first argument the entry point passes to
    /// the C runtime's start routine.
    pub(crate) const MAIN: Self = Self(1 << 10);
    /// A code address held in a table of addresses (a MIPS GOT entry).
    pub(crate) const POINTER: Self = Self(1 << 11);

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
    pub(crate) const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// The names of the ways in the set, as the constants spell them.
    pub(crate) fn names(self) -> impl Iterator<Item = &'static str> {
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

/// The functions [`functions`](fn@functions) recovered, with the facts that say how far
/// to trust them: code they mostly do not cover (packed or encrypted code),
/// paths that run into bytes that do not decode (data, or the wrong
/// instruction set), jumps whose targets are unknown, and whether a
/// [`Limits`] bound cut the work short.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Functions {
    /// Functions in entry-address order.
    pub functions: Vec<Function>,
    /// Bytes of executable code in the binary.
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

impl Functions {
    /// The function whose entry is `addr`: what a [`Ref`] to a function
    /// calls.
    #[must_use]
    pub fn function(&self, addr: u64) -> Option<&Function> {
        self.functions
            .binary_search_by_key(&addr, |function| function.entry)
            .ok()
            .and_then(|index| self.functions.get(index))
    }

    /// The name of what `to` (a [`Ref::to`]) reaches: a named function, or
    /// the import whose slot it is.
    #[must_use]
    pub fn name<'a>(&'a self, bin: &'a Binary<'_>, to: u64) -> Option<&'a str> {
        self.function(to)
            .and_then(|function| function.name.as_deref())
            .or_else(|| bin.import(to))
    }
}

/// Recover the functions of `bin`, doing no more work than `limits` allow.
#[must_use]
pub fn functions(bin: &Binary<'_>, limits: &Limits) -> Functions {
    if bin.arch.is_none() {
        return Functions::default();
    }
    functions::recover(bin, limits).0
}
