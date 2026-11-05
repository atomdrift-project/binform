//! An ELF file's [`Binary`]: its code, where its functions start, and its
//! import slots.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};

use super::elf::{self, Elf, Place};
use super::read::{self, Reader};
use super::{
    Tables, bare, eh, file_range, go_seeds, gopclntab, import_table, limits, relocate, seed,
    unwind_seeds,
};
use crate::isa::Memory;
use crate::{Arch, Binary, Export, Format, Origin, Section, Segment, Slot};

/// `e_flags`' C-SKY ABI field: ABIv1 is 1.
const EF_CSKY_ABI_V1: u32 = 1 << 28;

/// The [`Binary`] of an ELF file; its layout alone when binform does not
/// decode its instruction set.
pub(super) fn binary<'a>(bytes: &'a [u8], elf: &Elf) -> Binary<'a> {
    if let Some(arch) = arch(elf) {
        return image(bytes, elf, arch);
    }
    let addrs: Vec<u64> = elf.sections.iter().map(|sh| sh.addr).collect();
    let slots = slots(elf);
    let tables = tables(elf, &addrs, &slots, elf.kind == elf::ET_REL);
    bare(Format::Elf, elf.entry, tables, slots)
}

/// The instruction set of an ELF file's machine, word size and byte order.
fn arch(elf: &Elf) -> Option<Arch> {
    use elf::*;
    let arch = match (elf.machine, elf.is_64) {
        (EM_386, _) => Arch::X86,
        (EM_X86_64, _) => Arch::X86_64,
        (EM_AARCH64, _) => Arch::Arm64,
        (EM_ARM, _) => Arch::Arm,
        // EF_MIPS_ARCH: 9 and 10 are MIPS32 and MIPS64 Release 6.
        (EM_MIPS | EM_MIPS_RS3_LE, wide) => {
            let r6 = matches!(elf.header_flags >> 28, 9 | 10);
            match (wide, elf.big, r6) {
                (false, true, false) => Arch::Mips,
                (false, false, false) => Arch::MipsEl,
                (true, true, false) => Arch::Mips64,
                (true, false, false) => Arch::Mips64El,
                (false, true, true) => Arch::MipsR6,
                (false, false, true) => Arch::MipsR6El,
                (true, true, true) => Arch::Mips64R6,
                (true, false, true) => Arch::Mips64R6El,
            }
        }
        (EM_S390, true) => Arch::S390x,
        (EM_SPARC | EM_SPARC32PLUS, _) => Arch::Sparc,
        (EM_SPARCV9, _) => Arch::Sparc64,
        (EM_SH, _) => Arch::SuperH,
        (EM_PPC, false) if elf.big => Arch::PowerPc,
        (EM_PPC, false) => Arch::PowerPcEl,
        (EM_PPC64, true) if elf.big => Arch::PowerPc64,
        (EM_PPC64, true) => Arch::PowerPc64El,
        (EM_RISCV, false) => Arch::RiscV32,
        (EM_RISCV, true) => Arch::RiscV64,
        (EM_LOONGARCH, true) => Arch::LoongArch64,
        (EM_68K, false) => Arch::M68k,
        (EM_OPENRISC, false) => Arch::OpenRisc,
        (EM_MICROBLAZE | EM_MICROBLAZE_OLD, false) if elf.big => Arch::MicroBlaze,
        (EM_MICROBLAZE | EM_MICROBLAZE_OLD, false) => Arch::MicroBlazeEl,
        (EM_ARC_COMPACT, false) => Arch::Arc,
        (EM_ARC_COMPACT2, false) => Arch::ArcV2,
        (EM_CSKY, false) if elf.header_flags & 0xf000_0000 == EF_CSKY_ABI_V1 => Arch::CSky,
        (EM_XTENSA, false) => Arch::Xtensa,
        (EM_MCORE, false) => Arch::MCore,
        (EM_BPF, true) => Arch::Bpf,
        (EM_ALTERA_NIOS2, false) => Arch::Nios2,
        _ => return None,
    };
    // A byte order the instruction set does not run in.
    (elf.big == arch.big_endian()).then_some(arch)
}

fn image<'a>(bytes: &'a [u8], elf: &Elf, arch: Arch) -> Binary<'a> {
    let object = elf.kind == elf::ET_REL;

    // An object's sections are placed and linked as a loader would see
    // them; an executable's sit at their addresses. Program headers stand in
    // when the section table is stripped, empty, or names no code (packers).
    let (addrs, mut segments, mut slots) = if object {
        let layout = relocate::layout(bytes, elf, arch);
        (layout.addrs, layout.segments, layout.imports)
    } else {
        let addrs = elf.sections.iter().map(|sh| sh.addr).collect();
        (addrs, section_segments(bytes, elf, arch), Vec::new())
    };
    if !segments
        .iter()
        .any(|segment| segment.executable && !segment.bytes.is_empty())
    {
        segments = program_segments(bytes, elf);
    }
    let sections = ElfSections { elf, addrs: &addrs };
    let memory = Memory::for_arch(&segments, arch);
    // RELA relocations against no symbol: RELATIVE (and IRELATIVE, whose
    // addend is a resolver's address).
    let rebased: Vec<(u64, u64)> = elf
        .dynamic_relocations
        .iter()
        .filter(|reloc| reloc.symbol == 0)
        .filter_map(|reloc| Some((reloc.offset, u64::try_from(reloc.addend?).ok()?)))
        .collect();

    let mut seeds = Vec::new();
    if elf.entry != 0 {
        seeds.push(seed(elf.entry, Origin::Entry));
    }
    for symbol in elf.symbols.iter().chain(&elf.dynamic_symbols) {
        if symbol.kind != elf::STT_FUNC || symbol.place == Place::Undefined {
            continue;
        }
        // An object's symbol values are offsets into their sections, and
        // the first function of each sits at offset zero.
        let addr = if object {
            match symbol.place.section().and_then(|index| addrs.get(index)) {
                Some(&base) if base != 0 => base.wrapping_add(symbol.value),
                _ => continue,
            }
        } else if symbol.value != 0 {
            symbol.value
        } else {
            continue;
        };
        seeds.push(seed(addr, Origin::Symbol(symbol.name.clone())));
    }
    let (inits, finis) = initializers(elf, &sections, &memory, &rebased);
    seeds.extend(
        inits
            .into_iter()
            .chain(finis)
            .map(|addr| seed(addr, Origin::Loader)),
    );
    if let Some((_, sh)) = sections.find(".gopclntab") {
        let text = sections.find(".text").map(|(addr, _)| addr);
        let table = file_range(bytes, sh.offset, sh.size);
        seeds.extend(go_seeds(gopclntab::functions(table, text, true, elf.big)));
    }
    let mut pads = eh::Pads::new(if elf.is_64 { 8 } else { 4 });
    let mut extents = Vec::new();
    if let Some((addr, sh)) = sections.find(".eh_frame") {
        extents = eh::eh_frame(&memory, addr, sh.size, &mut pads);
        seeds.extend(unwind_seeds(&extents));
    }
    seeds.extend(
        stubs(bytes, arch, &sections)
            .into_iter()
            .map(|addr| seed(addr, Origin::Stub)),
    );

    slots.extend(self::slots(elf));
    if arch.mips() {
        slots.extend(mips_got_imports(elf));
    }
    let got = global_pointer(elf, arch, &sections, &memory);
    if arch.mips() && !object {
        seeds.extend(
            mips_got_pointers(elf, &sections, &memory, &slots)
                .into_iter()
                .map(|addr| seed(addr, Origin::Pointer)),
        );
    }
    // 64-bit ELFv1: the entry point and function symbols name descriptors
    // in `.opd` (the code's address, the TOC pointer, an environment), and
    // each descriptor stands for a function.
    if arch == Arch::PowerPc64
        && !object
        && let Some((opd, sh)) = sections.find(".opd")
    {
        for seed in &mut seeds {
            if seed.addr.wrapping_sub(opd) < sh.size
                && let Some(code) = memory.read(seed.addr, 8)
            {
                seed.addr = code;
            }
        }
        seeds.extend(
            read::entries(opd, mapped(&memory, opd, sh.size), 24)
                .filter_map(|descriptor| memory.read(descriptor, 8))
                .filter(|&code| code != 0)
                .map(|code| seed(code, Origin::Pointer)),
        );
    }

    let tables = tables(elf, &addrs, &slots, object);
    Binary {
        arch: Some(arch),
        segments,
        seeds,
        handlers: pads.handlers,
        extents,
        got,
        rebased,
        ..bare(Format::Elf, elf.entry, tables, slots)
    }
}

/// How many of the `size` bytes from `addr` are mapped, in its segment.
fn mapped(memory: &Memory<'_>, addr: u64, size: u64) -> u64 {
    memory
        .at(addr)
        .map_or(0, |(bytes, _)| bytes.len() as u64)
        .min(size)
}

/// An executable's loaded sections, as segments, with the data objects
/// that lie in code split out of it.
fn section_segments<'a>(bytes: &'a [u8], elf: &Elf, arch: Arch) -> Vec<Segment<'a>> {
    // Sections may all map the same bytes: count no more zeros than the
    // file holds.
    let mut zeros_left = bytes.len();
    let segments = elf
        .sections
        .iter()
        .filter(|sh| sh.flags & elf::SHF_ALLOC != 0 && sh.kind != elf::SHT_NOBITS)
        .flat_map(|sh| {
            let data = file_range(bytes, sh.offset, sh.size);
            let executable = sh.flags & elf::SHF_EXECINSTR != 0;
            // SPARC's zeros that start code, in 16-byte units, are written
            // at load time: the `.plt` header (and on 64-bit SPARC, the
            // whole `.plt` but the entries' first jumps), which the dynamic
            // linker fills.
            let zeros = if executable && matches!(arch, Arch::Sparc | Arch::Sparc64) {
                let zeros = data
                    .iter()
                    .take(zeros_left)
                    .take_while(|&&b| b == 0)
                    .count();
                zeros_left = zeros_left.saturating_sub(zeros);
                zeros & !15
            } else {
                0
            };
            let (head, code) = data.split_at(zeros);
            [
                (sh.addr, head, false),
                (sh.addr.wrapping_add(zeros as u64), code, executable),
            ]
            .into_iter()
            .filter(|(_, part, _)| !part.is_empty())
            .map(|(addr, part, executable)| Segment {
                addr,
                bytes: Cow::Borrowed(part),
                executable,
            })
        })
        .collect();
    // Sun Studio puts constant pools (`___const_seg_*`, jump tables among
    // them) in `.text`, as data objects: they are not code.
    let pools: Vec<(u64, u64)> = elf
        .symbols
        .iter()
        .filter(|symbol| symbol.kind == elf::STT_OBJECT && symbol.size > 0)
        .filter(|symbol| symbol.place != Place::Undefined)
        .map(|symbol| (symbol.value, symbol.value.saturating_add(symbol.size)))
        .collect();
    fence(segments, pools)
}

/// The loadable program headers, as segments.
fn program_segments<'a>(bytes: &'a [u8], elf: &Elf) -> Vec<Segment<'a>> {
    elf.programs
        .iter()
        .filter(|ph| ph.kind == elf::PT_LOAD)
        .map(|ph| Segment {
            addr: ph.vaddr,
            bytes: Cow::Borrowed(file_range(bytes, ph.offset, ph.filesz)),
            executable: ph.flags & elf::PF_X != 0,
        })
        .collect()
}

/// `segments` with the `ranges` (start, end) that lie wholly inside
/// executable ones split out of them as data. At most [`limits::TABLE`]
/// ranges are looked at in all, however the segments overlap.
fn fence<'a>(segments: Vec<Segment<'a>>, mut ranges: Vec<(u64, u64)>) -> Vec<Segment<'a>> {
    ranges.sort_unstable();
    let mut budget = usize::try_from(limits::TABLE).unwrap_or(usize::MAX);
    let mut out = Vec::with_capacity(segments.len());
    for segment in segments {
        let end = segment.addr.saturating_add(segment.bytes.len() as u64);
        // The ranges that start inside the segment.
        let first = ranges.partition_point(|&(from, _)| from < segment.addr);
        let last = ranges.partition_point(|&(from, _)| from <= end);
        let window = ranges
            .get(first..last)
            .filter(|_| segment.executable)
            .unwrap_or_default();
        let window = window.get(..budget).unwrap_or(window);
        budget = budget.saturating_sub(window.len());
        let mut inside = window
            .iter()
            .copied()
            .filter(|&(_, to)| to <= end)
            .peekable();
        if inside.peek().is_none() {
            out.push(segment);
            continue;
        }
        let piece = |from: u64, to: u64, executable: bool| {
            let range = usize::try_from(from.saturating_sub(segment.addr)).unwrap_or(0)
                ..usize::try_from(to.saturating_sub(segment.addr)).unwrap_or(0);
            Segment {
                addr: from,
                bytes: match &segment.bytes {
                    Cow::Borrowed(bytes) => Cow::Borrowed(bytes.get(range).unwrap_or_default()),
                    Cow::Owned(bytes) => Cow::Owned(bytes.get(range).unwrap_or_default().to_vec()),
                },
                executable,
            }
        };
        let mut at = segment.addr;
        for (from, to) in inside {
            // Overlapping objects: what is left of this one.
            let from = from.max(at);
            if to <= from {
                continue;
            }
            if from > at {
                out.push(piece(at, from, true));
            }
            out.push(piece(from, to, false));
            at = to;
        }
        if at < end {
            out.push(piece(at, end, true));
        }
    }
    out
}

/// The register the ABI keeps pointing at the GOT or small data, where it
/// has one: x86's GOT base, MIPS's `$gp`, 64-bit PowerPC's TOC pointer and
/// RISC-V's `gp`.
fn global_pointer(
    elf: &Elf,
    arch: Arch,
    sections: &ElfSections<'_>,
    memory: &Memory<'_>,
) -> Option<u64> {
    let symbol = |name: &str, dynamic: bool| {
        let dynamic = if dynamic {
            &elf.dynamic_symbols[..]
        } else {
            &[]
        };
        elf.symbols
            .iter()
            .chain(dynamic)
            .find(|symbol| symbol.name == name && symbol.value != 0)
            .map(|symbol| symbol.value)
    };
    match arch {
        Arch::X86 => elf
            .dynamic_value(elf::DT_PLTGOT)
            .or_else(|| sections.find(".got.plt").map(|(addr, _)| addr)),
        // `_gp`, which the linker places 0x7ff0 past the GOT's start unless
        // told otherwise. A static, stripped executable has neither: its
        // `.got` section stands in (uClibc's `__start` computes `$gp` the
        // same way, `bal; lui; addiu; addu $gp, $gp, $ra`).
        _ if arch.mips() => symbol("_gp", true).or_else(|| {
            elf.dynamic_value(elf::DT_PLTGOT)
                .or_else(|| sections.find(".got").map(|(addr, _)| addr))
                .map(|got| got.wrapping_add(0x7ff0))
        }),
        // The TOC pointer in `r2`: `.TOC.`, which the linker places 0x8000
        // past the start of `.got`.
        Arch::PowerPc64 | Arch::PowerPc64El => symbol(".TOC.", false).or_else(|| {
            sections
                .find(".got")
                .map(|(addr, _)| addr.wrapping_add(0x8000))
        }),
        // The global pointer, which the linker relaxes accesses near it
        // to: `__global_pointer$`, or what `_start` sets `gp` to.
        Arch::RiscV32 | Arch::RiscV64 => symbol("__global_pointer$", false).or_else(|| {
            let code = memory.code(elf.entry)?;
            crate::isa::riscv::gp_setup(code, elf.entry, arch == Arch::RiscV64)
        }),
        _ => None,
    }
}

/// An ELF file's import slots: the dynamic relocations against undefined
/// symbols.
fn slots(elf: &Elf) -> Vec<Slot> {
    elf.dynamic_relocations
        .iter()
        .filter(|reloc| reloc.symbol != 0)
        .filter_map(|reloc| {
            let symbol = elf.dynamic_symbols.get(reloc.symbol)?;
            (symbol.place == Place::Undefined && !symbol.name.is_empty()).then(|| Slot {
                slot: reloc.offset,
                name: symbol.name.clone(),
                import: None,
            })
        })
        .collect()
}

/// An ELF file's sections, imports and exports. `addrs` are the sections'
/// addresses (an object's, as binform placed them).
fn tables(elf: &Elf, addrs: &[u64], slots: &[Slot], object: bool) -> Tables {
    let sections = elf
        .sections
        .iter()
        .enumerate()
        .filter(|&(i, sh)| i != 0 || sh.kind != 0)
        .map(|(i, sh)| Section {
            name: sh.name.clone(),
            addr: if object {
                addrs.get(i).copied().unwrap_or(0)
            } else {
                sh.addr
            },
            size: sh.size,
            offset: sh.offset,
            file_size: if sh.kind == elf::SHT_NOBITS {
                0
            } else {
                sh.size
            },
            flags: sh.flags,
            readable: sh.flags & elf::SHF_ALLOC != 0,
            writable: sh.flags & elf::SHF_WRITE != 0,
            executable: sh.flags & elf::SHF_EXECINSTR != 0,
        })
        .collect();
    // The symbols the loader binds (or, in an object, the linker): the
    // dynamic table's, else the static table's. Imports are the undefined
    // ones. Exports are the defined ones, weak ones too (the dynamic linker
    // binds to a weak definition as to any other): of the dynamic table,
    // whose symbols other images can bind to, and of an object's static
    // table, whose the linker can. A static executable's `.symtab` names
    // its own functions, which nothing outside binds to.
    let named = |symbol: &&elf::Symbol| {
        matches!(
            symbol.bind,
            elf::STB_GLOBAL | elf::STB_WEAK | elf::STB_GNU_UNIQUE
        ) && !matches!(symbol.kind, elf::STT_SECTION | elf::STT_FILE)
            && !symbol.name.is_empty()
    };
    let undefined = if elf.dynamic_symbols.is_empty() {
        &elf.symbols
    } else {
        &elf.dynamic_symbols
    };
    let imports = import_table(
        slots,
        undefined
            .iter()
            .filter(named)
            .filter(|symbol| symbol.place == Place::Undefined)
            .map(|symbol| (symbol.name.as_str(), symbol.library.as_deref())),
    );
    let exported: &[elf::Symbol] = if !elf.dynamic_symbols.is_empty() {
        &elf.dynamic_symbols
    } else if object {
        &elf.symbols
    } else {
        &[]
    };
    let mut seen = HashSet::new();
    let exports = exported
        .iter()
        .filter(named)
        .filter(|symbol| symbol.place != Place::Undefined)
        .filter_map(|symbol| {
            let addr = if object {
                addrs
                    .get(symbol.place.section()?)?
                    .wrapping_add(symbol.value)
            } else {
                symbol.value
            };
            seen.insert((symbol.name.as_str(), addr)).then(|| Export {
                forward: None,
                name: symbol.name.clone(),
                addr: Some(addr),
            })
        })
        .collect();

    Tables {
        sections,
        imports,
        exports,
    }
}

/// The MIPS GOT's slots for undefined symbols. The GOT holds its local
/// entries, then one for each dynamic symbol from `DT_MIPS_GOTSYM` on, in
/// order; the dynamic linker fills them without relocations.
fn mips_got_imports(elf: &Elf) -> Vec<Slot> {
    let (Some(got), Some(local), Some(first)) = (
        elf.dynamic_value(elf::DT_PLTGOT),
        elf.dynamic_value(elf::DT_MIPS_LOCAL_GOTNO),
        elf.dynamic_value(elf::DT_MIPS_GOTSYM),
    ) else {
        return Vec::new();
    };
    let width = if elf.is_64 { 8 } else { 4 };
    let first = usize::try_from(first).unwrap_or(usize::MAX);
    (0_u64..)
        .zip(elf.dynamic_symbols.iter().skip(first))
        .filter(|(_, symbol)| symbol.place == Place::Undefined && !symbol.name.is_empty())
        .map(|(i, symbol)| Slot {
            slot: got.wrapping_add(local.wrapping_add(i).wrapping_mul(width)),
            name: symbol.name.clone(),
            import: None,
        })
        .collect()
}

/// The code addresses a MIPS GOT holds: the functions whose address the
/// program takes. Local entries hold 64 KiB pages (`%got_page`), which are
/// left out, as are import slots.
fn mips_got_pointers(
    elf: &Elf,
    sections: &ElfSections<'_>,
    memory: &Memory<'_>,
    imports: &[Slot],
) -> Vec<u64> {
    let width: u8 = if elf.is_64 { 8 } else { 4 };
    let range = sections
        .find(".got")
        .map(|(addr, sh)| (addr, sh.size))
        .or_else(|| {
            let got = elf.dynamic_value(elf::DT_PLTGOT)?;
            let local = elf.dynamic_value(elf::DT_MIPS_LOCAL_GOTNO)?;
            let first = elf.dynamic_value(elf::DT_MIPS_GOTSYM)?;
            let globals = (elf.dynamic_symbols.len() as u64).saturating_sub(first);
            Some((
                got,
                local
                    .saturating_add(globals)
                    .saturating_mul(u64::from(width)),
            ))
        });
    let Some((start, size)) = range else {
        return Vec::new();
    };
    let slots: HashSet<u64> = imports.iter().map(|import| import.slot).collect();
    read::entries(start, mapped(memory, start, size), u64::from(width))
        .filter(|slot| !slots.contains(slot))
        .filter_map(|slot| memory.read(slot, width))
        .filter(|&addr| addr & 3 == 0 && addr & 0xffff != 0 && memory.is_code(addr))
        .collect()
}

/// An ELF file's section headers with the address each is mapped at.
struct ElfSections<'e> {
    elf: &'e Elf,
    addrs: &'e [u64],
}

impl ElfSections<'_> {
    /// The address and header of the section called `name`.
    fn find(&self, name: &str) -> Option<(u64, &elf::Section)> {
        self.elf
            .sections
            .iter()
            .zip(self.addrs)
            .find(|(sh, _)| sh.name == name)
            .map(|(sh, &addr)| (addr, sh))
    }
}

/// The entries of the procedure linkage table: its header, which jumps to
/// the dynamic linker, and one stub per import. With indirect-branch
/// tracking the stubs callers use live in `.plt.sec`; `.plt.got` holds the
/// stubs of imports bound at load time.
fn stubs(bytes: &[u8], arch: Arch, sections: &ElfSections<'_>) -> Vec<u64> {
    if arch == Arch::Arm {
        return arm_stubs(bytes, sections);
    }
    // Each set's header size, and its stub size when the section's entry
    // size does not give it. No stub is under 8 bytes: an entry size of 4
    // is a word's (Arm's `.plt`), or UnixWare's convention that GNU ld
    // follows for the i386 `.plt`, whose stubs are 16.
    let (header, stub) = match arch {
        Arch::X86 | Arch::X86_64 => (16, None),
        Arch::Arm64 => (32, None),
        Arch::S390x => (32, Some(32)),
        // Four reserved entries, which the dynamic linker fills, then one
        // per import (`sethi; ba,a`): 12 bytes on 32-bit SPARC, 32 on V9.
        Arch::Sparc => (48, Some(12)),
        Arch::Sparc64 => (128, Some(32)),
        // An eight-instruction header, then four per import (`auipc t3;
        // ld t3; jalr t1, t3; nop`, `pcaddu12i t3; ld.d t3; jirl t1, t3;
        // nop`).
        Arch::RiscV32 | Arch::RiscV64 | Arch::LoongArch64 => (32, Some(16)),
        // ARCv2: a 32-byte header, then `ld r12, [pcl, slot]; j.d [r12];
        // mov r12, pcl` per import.
        Arch::ArcV2 => (32, Some(16)),
        // The others' stubs vary by ABI: the header alone.
        _ => (0, Some(0)),
    };
    let entries = |name: &str, skip: u64| -> Vec<u64> {
        let Some((addr, sh)) = sections.find(name) else {
            return Vec::new();
        };
        let size = match stub {
            Some(0) => return Vec::new(),
            Some(size) => size,
            None if sh.entsize >= 8 => sh.entsize,
            None => 16,
        };
        let Some(first) = addr.checked_add(skip) else {
            return Vec::new();
        };
        read::entries(first, sh.size.saturating_sub(skip), size)
            .take(limits::STUBS)
            .collect()
    };
    let mut stubs: Vec<u64> = sections
        .find(".plt")
        .map(|(addr, _)| addr)
        .into_iter()
        .collect();
    // With indirect-branch tracking, `.plt` keeps each import's lazy-binding
    // entry (`endbr64; push n; jmp .plt`) and `.plt.sec` the stub calls go
    // to: both are code.
    stubs.extend(entries(".plt", header));
    stubs.extend(entries(".plt.sec", 0));
    stubs.extend(entries(".plt.got", 0));
    stubs
}

/// The entries of a 32-bit Arm PLT: after its 20-byte header, 12-byte A32
/// stubs, each preceded by a 4-byte Thumb `bx pc; b.n` when Thumb code
/// calls it. The Thumb entry is a stub of its own, at an odd address.
fn arm_stubs(bytes: &[u8], sections: &ElfSections<'_>) -> Vec<u64> {
    const BX_PC: u16 = 0x4778;
    let Some((addr, sh)) = sections.find(".plt") else {
        return Vec::new();
    };
    let plt = Reader::new(file_range(bytes, sh.offset, sh.size), false);
    let mut stubs = vec![addr];
    let mut at = 20_u64;
    while at < plt.bytes.len() as u64 && stubs.len() <= limits::STUBS {
        let stub = addr.wrapping_add(at);
        if plt.u16(at) == Some(BX_PC) {
            stubs.extend([stub | 1, stub.wrapping_add(4)]);
            at = at.saturating_add(16);
        } else {
            stubs.push(stub);
            at = at.saturating_add(12);
        }
    }
    stubs
}

/// Initializer and finalizer addresses in the order the loader runs them:
/// `DT_PREINIT_ARRAY`, `DT_INIT`, `DT_INIT_ARRAY`, then `DT_FINI_ARRAY` and
/// `DT_FINI`; or the array sections of a static executable. `rebased` are
/// the (slot, address) pairs RELATIVE relocations fill.
fn initializers(
    elf: &Elf,
    sections: &ElfSections<'_>,
    memory: &Memory<'_>,
    rebased: &[(u64, u64)],
) -> (Vec<u64>, Vec<u64>) {
    let width: u8 = if elf.is_64 { 8 } else { 4 };
    // A position-independent array holds zeros until a RELATIVE relocation
    // fills it; the relocation's addend is the address. The first
    // relocation of a slot wins.
    let relative: HashMap<u64, u64> = rebased.iter().rev().copied().collect();
    let array = |start: u64, size: u64| -> Vec<u64> {
        read::entries(start, size, u64::from(width))
            .take(limits::INITIALIZERS)
            .filter_map(|slot| match memory.read(slot, width) {
                Some(0) | None => relative.get(&slot).copied(),
                // All ones terminates the old `.ctors` lists.
                Some(value) if value == u64::MAX || value == u64::from(u32::MAX) => None,
                value => value,
            })
            .collect()
    };
    let section = |name: &str| {
        sections
            .find(name)
            .map(|(addr, sh)| array(addr, sh.size))
            .unwrap_or_default()
    };
    if elf.dynamic.is_empty() {
        let mut inits = section(".preinit_array");
        inits.extend(section(".init_array"));
        return (inits, section(".fini_array"));
    }
    let value = |tag: u64| elf.dynamic_value(tag).unwrap_or(0);
    let mut inits = array(value(elf::DT_PREINIT_ARRAY), value(elf::DT_PREINIT_ARRAYSZ));
    inits.extend(Some(value(elf::DT_INIT)).filter(|&init| init != 0));
    inits.extend(array(
        value(elf::DT_INIT_ARRAY),
        value(elf::DT_INIT_ARRAYSZ),
    ));
    let mut finis = array(value(elf::DT_FINI_ARRAY), value(elf::DT_FINI_ARRAYSZ));
    finis.extend(Some(value(elf::DT_FINI)).filter(|&fini| fini != 0));
    (inits, finis)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A file of `sections`, each `(name, addr, size, entsize)`, mapped
    /// where its header says.
    fn elf(sections: &[(&str, u64, u64, u64)]) -> Elf {
        Elf {
            is_64: false,
            big: false,
            machine: 0,
            header_flags: 0,
            kind: 3,
            entry: 0,
            programs: Vec::new(),
            sections: sections
                .iter()
                .map(|&(name, addr, size, entsize)| elf::Section {
                    name: name.into(),
                    kind: 1,
                    flags: 6,
                    addr,
                    offset: addr,
                    size,
                    link: 0,
                    info: 0,
                    addralign: 16,
                    entsize,
                })
                .collect(),
            symbols: Vec::new(),
            dynamic_symbols: Vec::new(),
            dynamic: Vec::new(),
            relocations: Vec::new(),
            dynamic_relocations: Vec::new(),
        }
    }

    /// GNU ld gives the i386 `.plt` an entry size of 4, UnixWare's
    /// convention, though its header and each stub are 16 bytes: a stub
    /// every 16 bytes, not every 4. `.plt.got`'s 8-byte stubs say 8.
    #[test]
    fn i386_plt_entry_size_of_4_is_no_stub_size() {
        let elf = elf(&[(".plt", 0x1000, 64, 4), (".plt.got", 0x1040, 16, 8)]);
        let addrs: Vec<u64> = elf.sections.iter().map(|sh| sh.addr).collect();
        let sections = ElfSections {
            elf: &elf,
            addrs: &addrs,
        };
        assert_eq!(
            stubs(&[], Arch::X86, &sections),
            [0x1000, 0x1010, 0x1020, 0x1030, 0x1040, 0x1048]
        );
    }

    #[test]
    fn fences_data_out_of_code() {
        let bytes = [0_u8; 32];
        let code = Segment {
            addr: 0x1000,
            bytes: Cow::Borrowed(&bytes),
            executable: true,
        };
        let parts: Vec<(u64, usize, bool)> = fence(
            vec![code],
            vec![
                (0x1008, 0x1010),
                (0x100c, 0x1014),
                (0x1018, 0x1020),
                (0x101c, 0x1030),
            ],
        )
        .iter()
        .map(|segment| (segment.addr, segment.bytes.len(), segment.executable))
        .collect();
        assert_eq!(
            parts,
            [
                (0x1000, 8, true),
                (0x1008, 8, false),
                (0x1010, 4, false),
                (0x1014, 4, true),
                (0x1018, 8, false)
            ]
        );
    }

    /// Thousands of overlapping code segments and a million data objects
    /// in them look at no more than the budget of objects.
    #[test]
    fn fencing_overlapping_segments_is_bounded() {
        let bytes = vec![0_u8; 1 << 20];
        let segments: Vec<Segment<'_>> = (0..1 << 14)
            .map(|_| Segment {
                addr: 0x1000,
                bytes: Cow::Borrowed(&bytes),
                executable: true,
            })
            .collect();
        let ranges = (0..1 << 20).map(|i| (0x1000 + i, 0x1001 + i)).collect();
        let start = std::time::Instant::now();
        let fenced = fence(segments, ranges);
        assert!(fenced.len() < 1 << 22);
        assert!(start.elapsed().as_secs() < 5);
    }

    /// A `.opd` and a GOT whose headers claim 2^60 bytes read only what is
    /// mapped.
    #[test]
    fn descriptor_and_got_counts_are_what_is_mapped() {
        let bytes = [0_u8; 48];
        let segments = [Segment {
            addr: 0x1000,
            bytes: Cow::Borrowed(&bytes),
            executable: false,
        }];
        let memory = Memory::new(&segments);
        assert_eq!(mapped(&memory, 0x1000, 1 << 60), 48);
        assert_eq!(mapped(&memory, 0x1010, 8), 8);
        assert_eq!(mapped(&memory, 0x9000, 1 << 60), 0);
        let start = std::time::Instant::now();
        assert_eq!(
            read::entries(0x1000, mapped(&memory, 0x1000, u64::MAX), 24).count(),
            2
        );
        assert!(start.elapsed().as_millis() < 100);
    }
}
