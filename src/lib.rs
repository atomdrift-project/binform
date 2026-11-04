//! binform recovers functions from machine code: where each one starts and
//! ends, its basic blocks, its complexity, and the calls and jumps it makes,
//! in ELF, PE and Mach-O binaries of the instruction sets [`Arch`] lists.
//!
//! [`parse`] reads a binary's headers into a [`Binary`]; [`recover`]
//! recovers its functions; [`calls`] reads the values each call and syscall
//! passes. Each is a pure function of its input: no I/O, no threads, no
//! global state, no panics, and work bounded by [`Limits`], because the
//! input is assumed hostile. A caller pays only for what it calls.
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let bytes = std::fs::read("a.out")?;
//! let bin = binform::parse(&bytes)?;
//! for f in &binform::recover(&bin, &binform::Limits::DEFAULT).functions {
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

// Tests build their inputs with plain arithmetic; the library is linted
// without them.
#![cfg_attr(test, allow(clippy::arithmetic_side_effects))]

mod calls;
#[cfg(feature = "diagnostics")]
pub mod diagnostics;
mod functions;
mod isa;
mod layout;
mod syscalls;
#[cfg(test)]
mod tests;

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};
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
    /// 32-bit PowerPC, little-endian: Windows NT's.
    PowerPcEl,
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
    /// Motorola M*Core (RCE), little-endian: the set C-SKY ABIv1 descends
    /// from, decoded as such.
    MCore,
    /// eBPF, little-endian: the Linux kernel's in-kernel virtual machine.
    /// Programs are relocatable objects, one function per program section
    /// and its static subprograms.
    Bpf,
    /// Intel (Altera) Nios II, R1, little-endian.
    Nios2,
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
            | Self::PowerPcEl
            | Self::RiscV32
            | Self::M68k
            | Self::OpenRisc
            | Self::MicroBlaze
            | Self::MicroBlazeEl
            | Self::Arc
            | Self::ArcV2
            | Self::CSky
            | Self::MCore
            | Self::Nios2
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
            | Self::LoongArch64
            | Self::Bpf => 8,
        }
    }
}

/// The instruction set's short lowercase name, as toolchains spell it:
///
/// ```
/// assert_eq!(binform::Arch::X86_64.to_string(), "x86-64");
/// assert_eq!(binform::Arch::PowerPc64El.to_string(), "ppc64le");
/// ```
impl core::fmt::Display for Arch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::X86 => "x86",
            Self::X86_64 => "x86-64",
            Self::Arm64 => "arm64",
            Self::Arm => "arm",
            Self::Mips => "mips",
            Self::MipsEl => "mipsel",
            Self::Mips64 => "mips64",
            Self::Mips64El => "mips64el",
            Self::MipsR6 => "mipsr6",
            Self::MipsR6El => "mipsr6el",
            Self::Mips64R6 => "mips64r6",
            Self::Mips64R6El => "mips64r6el",
            Self::S390x => "s390x",
            Self::Sparc => "sparc",
            Self::Sparc64 => "sparc64",
            Self::SuperH => "sh",
            Self::PowerPc => "ppc",
            Self::PowerPcEl => "ppcle",
            Self::PowerPc64 => "ppc64",
            Self::PowerPc64El => "ppc64le",
            Self::RiscV32 => "riscv32",
            Self::RiscV64 => "riscv64",
            Self::LoongArch64 => "loongarch64",
            Self::M68k => "m68k",
            Self::OpenRisc => "or1k",
            Self::MicroBlaze => "microblaze",
            Self::MicroBlazeEl => "microblazeel",
            Self::Arc => "arc",
            Self::ArcV2 => "arcv2",
            Self::CSky => "csky",
            Self::Xtensa => "xtensa",
            Self::MCore => "mcore",
            Self::Bpf => "bpf",
            Self::Nios2 => "nios2",
        })
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
    /// A routine the loader runs: an initializer or finalizer (ELF
    /// `DT_INIT`, `DT_FINI` and their arrays), a TLS callback (PE).
    Loader,
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
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Slot {
    /// Address of the slot.
    pub(crate) slot: u64,
    /// The imported symbol's name, as the binary spells it.
    pub(crate) name: String,
    /// Its entry in [`Binary::imports`], once [`Binary::index_slots`] ran.
    pub(crate) import: Option<usize>,
}

/// A container format binform reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Format {
    /// ELF: executables, shared objects and relocatable objects.
    Elf,
    /// PE/COFF images.
    Pe,
    /// Mach-O, thin or one slice of a universal file.
    MachO,
}

/// The format's name: `ELF`, `PE` or `Mach-O`.
impl core::fmt::Display for Format {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Elf => "ELF",
            Self::Pe => "PE",
            Self::MachO => "Mach-O",
        })
    }
}

/// A section as its header describes it, values as the header holds them:
/// a PE section's sizes unrounded, a nameless one nameless.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Section {
    /// The header's name; Mach-O's is `__SEGMENT.__section`, a PE long name
    /// (`/4`) the one the COFF string table holds.
    pub name: String,
    /// Virtual address; in a relocatable ELF object, where binform placed
    /// the section, as its functions' addresses are.
    pub addr: u64,
    /// Bytes in memory: a PE section's `VirtualSize`.
    pub size: u64,
    /// File offset of the bytes the file holds.
    pub offset: u64,
    /// Bytes the file holds: zero for zero-filled sections (`.bss`); a PE
    /// section's `SizeOfRawData`.
    pub file_size: u64,
    /// The header's flag word: ELF `sh_flags`, PE `Characteristics`, Mach-O
    /// the section's `flags` (type in the low byte, attributes above).
    pub flags: u64,
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

/// An imported symbol.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
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
    /// A PE import from the delay-load table, bound on first call rather
    /// than at load.
    pub delayed: bool,
}

/// An exported symbol.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Export {
    /// The symbol's name as the binary spells it; `Ordinal_n` for a PE
    /// export by ordinal only.
    pub name: String,
    /// Its address; `None` for a Mach-O re-export, which has none of its
    /// own. A PE forwarder's is that of its forwarder string.
    pub addr: Option<u64>,
    /// For a forwarder, the export it forwards to: a PE forwarder's string
    /// (`NTDLL.RtlAllocateHeap`); a Mach-O re-export's library stem and
    /// symbol (`libsystem_c._memcpy`).
    pub forward: Option<String>,
}

/// A parsed binary: what [`parse`] read from its headers, and what
/// [`recover`] needs to recover its functions.
#[derive(Clone, Debug)]
pub struct Binary<'a> {
    pub(crate) format: Format,
    pub(crate) arch: Option<Arch>,
    pub(crate) entry: Option<u64>,
    pub(crate) sections: Vec<Section>,
    pub(crate) imports: Vec<Import>,
    pub(crate) exports: Vec<Export>,
    /// Every mapped segment, code and data.
    pub(crate) segments: Vec<Segment<'a>>,
    /// Addresses known to start functions. Duplicates are harmless.
    pub(crate) seeds: Vec<Seed>,
    /// Import slots, one per slot, in address order once
    /// [`Binary::index_slots`] ran. Calls through them, and through stubs
    /// that only jump through them, are resolved to the import; calls to
    /// imports that never return end their basic block.
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
    /// The container format.
    #[must_use]
    pub const fn format(&self) -> Format {
        self.format
    }

    /// The instruction set of the code; `None` for one binform does not
    /// decode, whose binary has its layout and no functions.
    #[must_use]
    pub const fn arch(&self) -> Option<Arch> {
        self.arch
    }

    /// The entry point, when the binary has one.
    #[must_use]
    pub const fn entry(&self) -> Option<u64> {
        self.entry
    }

    /// Sections in header order.
    #[must_use]
    pub fn sections(&self) -> &[Section] {
        &self.sections
    }

    /// Imported symbols, one per symbol (a PE import, one per
    /// import-address-table entry).
    #[must_use]
    pub fn imports(&self) -> &[Import] {
        &self.imports
    }

    /// Exported symbols.
    #[must_use]
    pub fn exports(&self) -> &[Export] {
        &self.exports
    }

    /// The mapped section that holds `addr`.
    #[must_use]
    pub fn section_at(&self, addr: u64) -> Option<&Section> {
        self.sections
            .iter()
            .filter(|s| s.mapped())
            // A PE section with no `VirtualSize` maps its raw size.
            .find(|s| addr.wrapping_sub(s.addr) < s.size.max(s.file_size))
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

    /// The import whose address the loader writes to `slot`, and its index
    /// in [`imports`](Self::imports).
    #[must_use]
    pub fn import(&self, slot: u64) -> Option<(usize, &Import)> {
        let at = self.slots.binary_search_by_key(&slot, |s| s.slot).ok()?;
        let index = self.slots.get(at)?.import?;
        Some((index, self.imports.get(index)?))
    }

    /// Sort the slots by address and point each at its import: the one
    /// whose own slot it is, else the first of its name.
    pub(crate) fn index_slots(&mut self) {
        let mut by_slot = HashMap::new();
        let mut by_name = HashMap::new();
        for (i, import) in self.imports.iter().enumerate() {
            if let Some(slot) = import.slot {
                by_slot.entry(slot).or_insert(i);
            }
            by_name.entry(import.name.as_str()).or_insert(i);
        }
        for slot in &mut self.slots {
            slot.import = by_slot
                .get(&slot.slot)
                .or_else(|| by_name.get(slot.name.as_str()))
                .copied();
        }
        self.slots.sort_by_key(|slot| slot.slot);
        self.slots.dedup_by_key(|slot| slot.slot);
    }

    /// Whether `addr` lies in an executable segment.
    #[cfg(any(test, feature = "diagnostics"))]
    pub(crate) fn is_code(&self, addr: u64) -> bool {
        self.segments.iter().any(|segment| {
            segment.executable
                && addr
                    .checked_sub(segment.addr)
                    .is_some_and(|offset| offset < segment.bytes.len() as u64)
        })
    }
}

/// Bounds on the work [`recover`] does.
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
    /// [`Recovery::truncated`] on the largest.
    pub const QUICK: Self = Self {
        functions: 1 << 18,
        instructions: 1 << 21,
        table_entries: 512,
    };
}

/// A recovered function.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
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
            Origin::Loader => Self::LOADER,
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
#[non_exhaustive]
pub struct Ref {
    /// Address of the instruction.
    pub from: u64,
    /// Where it goes.
    pub to: Dest,
    /// What kind of transfer it is.
    pub kind: RefKind,
}

impl Ref {
    /// The transfer at `from`, of `kind`, to `to`.
    #[must_use]
    pub const fn new(from: u64, to: Dest, kind: RefKind) -> Self {
        Self { from, to, kind }
    }

    /// The address the transfer reaches: its target, or the slot it goes
    /// through.
    #[must_use]
    pub const fn addr(&self) -> u64 {
        match self.to {
            Dest::Code(addr) | Dest::Slot { addr, .. } => addr,
        }
    }
}

/// Where a [`Ref`] goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Dest {
    /// Code at this address: a function's entry ([`Recovery::function`]),
    /// or a block of the function itself.
    Code(u64),
    /// Wherever the pointer in the memory slot at `addr` leads: for an
    /// import's slot, the import, by its index in [`Binary::imports`].
    Slot {
        /// The slot's address.
        addr: u64,
        /// The import whose address the loader writes there.
        import: Option<usize>,
    },
}

/// What a [`Ref`] does.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
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

/// The functions [`recover`] recovered, with the facts that say how far to
/// trust them: code they mostly do not cover (packed or encrypted code),
/// paths that run into bytes that do not decode (data, or the wrong
/// instruction set), jumps whose targets are unknown, and whether a
/// [`Limits`] bound cut the work short.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Recovery {
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
    /// Each stub's entry, and the import slot it only jumps through.
    pub(crate) stubs: BTreeMap<u64, u64>,
}

impl Recovery {
    /// The function whose entry is `addr`: what a [`Dest::Code`] that is a
    /// call reaches.
    #[must_use]
    pub fn function(&self, addr: u64) -> Option<&Function> {
        self.functions
            .binary_search_by_key(&addr, |function| function.entry)
            .ok()
            .and_then(|index| self.functions.get(index))
    }

    /// The name of what `to` reaches: a named function, or an import.
    #[must_use]
    pub fn name<'a>(&'a self, bin: &'a Binary<'_>, to: Dest) -> Option<&'a str> {
        match to {
            Dest::Code(addr) => self.function(addr)?.name.as_deref(),
            Dest::Slot { import, .. } => Some(bin.imports.get(import?)?.name.as_str()),
        }
    }
}

/// Recover the functions of `bin`, doing no more work than `limits` allow.
#[must_use]
pub fn recover(bin: &Binary<'_>, limits: &Limits) -> Recovery {
    functions::recover(bin, limits).0
}
