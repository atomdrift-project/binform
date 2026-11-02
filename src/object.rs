//! Build an [`Image`] from the bytes of an ELF, PE or Mach-O file.
//!
//! Everything a loader or linker leaves behind that names function starts
//! becomes a [`Seed`]: entry points, initializers, TLS callbacks, symbols,
//! exports, unwind tables and Mach-O function starts. Import slots come from
//! the PE import table, ELF relocations against undefined symbols, and the
//! Mach-O indirect symbol table.

use std::borrow::Cow;
use std::fmt;

use crate::decode::Memory;
use crate::{Arch, Handler, Image, Import, Origin, Seed, Segment};

use elf::Elf;
use macho::MachO;
use pe::Pe;

mod eh;
mod elf;
mod gopclntab;
mod macho;
mod pe;
mod read;
mod relocate;

/// Why bytes could not become an [`Image`].
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Not ELF, PE or Mach-O, or too malformed to parse.
    Format(String),
    /// A format funktion reads, for an instruction set it does not decode.
    Arch(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Format(why) => write!(f, "not a readable executable: {why}"),
            Self::Arch(arch) => write!(f, "unsupported architecture: {arch}"),
        }
    }
}

impl std::error::Error for Error {}

/// The [`Image`] of an ELF, PE or Mach-O file. A universal Mach-O yields its
/// first slice of a supported architecture.
pub fn image(bytes: &[u8]) -> Result<Image<'_>, Error> {
    match bytes.get(..4) {
        Some(b"\x7fELF") => elf_image(bytes, &elf::parse(bytes).map_err(Error::Format)?),
        Some([b'M', b'Z', ..]) => pe_image(bytes, &pe::parse(bytes).map_err(Error::Format)?),
        Some(&[0xca, 0xfe, 0xba, 0xbe | 0xbf]) => fat_image(bytes),
        Some(_) => macho_image(bytes, &macho::parse(bytes).map_err(Error::Format)?),
        None => Err(Error::Format("too short".into())),
    }
}

/// The functions of a Go binary's function table, which in a PE file has no
/// section of its own: the first header in data whose first function is
/// code. Entries count from the first code section when the header leaves
/// the text start to the loader.
fn pe_gopclntab(segments: &[Segment<'_>]) -> Vec<(u64, String)> {
    let memory = Memory::new(segments);
    let text = segments
        .iter()
        .find(|segment| segment.executable)
        .map(|segment| segment.addr);
    for segment in segments.iter().filter(|segment| !segment.executable) {
        let data: &[u8] = &segment.bytes;
        // Each header starts at a pointer-aligned magic number, two zero
        // bytes, the instruction size quantum, and the pointer size.
        let headers = data.chunks_exact(4).enumerate().filter_map(|(i, word)| {
            let magic = u32::from_le_bytes(word.try_into().ok()?);
            let rest = data.get(i * 4 + 4..i * 4 + 8)?;
            (gopclntab::MAGICS.contains(&magic) && rest.get(..2) == Some(&[0, 0][..]))
                .then(|| data.get(i * 4..))
                .flatten()
        });
        for table in headers {
            let functions = gopclntab::functions(table, text, false, false);
            if functions
                .first()
                .is_some_and(|&(entry, _)| memory.is_code(entry))
            {
                return functions;
            }
        }
    }
    Vec::new()
}

/// `len` bytes at file offset `offset`, cut short at the end of the file.
fn file_range(bytes: &[u8], offset: u64, len: u64) -> &[u8] {
    let start = usize::try_from(offset)
        .unwrap_or(usize::MAX)
        .min(bytes.len());
    let end = usize::try_from(offset.saturating_add(len))
        .unwrap_or(usize::MAX)
        .min(bytes.len());
    bytes.get(start..end).unwrap_or_default()
}

fn seed(addr: u64, origin: Origin) -> Seed {
    Seed { addr, origin }
}

// ---------------------------------------------------------------------------
// ELF
// ---------------------------------------------------------------------------

const EM_SPARC: u16 = 2;
const EM_386: u16 = 3;
const EM_MIPS: u16 = 8;
const EM_MIPS_RS3_LE: u16 = 10;
const EM_SPARC32PLUS: u16 = 18;
const EM_S390: u16 = 22;
const EM_ARM: u16 = 40;
const EM_SH: u16 = 42;
const EM_SPARCV9: u16 = 43;
const EM_X86_64: u16 = 62;
const EM_AARCH64: u16 = 183;

/// The instruction set of an ELF file's machine, word size and byte order.
fn elf_arch(elf: &Elf) -> Result<Arch, Error> {
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
        (EM_S390, false) => return Err(Error::Arch("31-bit s390".into())),
        (EM_SPARC | EM_SPARC32PLUS, _) => Arch::Sparc,
        (EM_SPARCV9, _) => Arch::Sparc64,
        (EM_SH, _) => Arch::SuperH,
        (machine, _) => return Err(Error::Arch(format!("ELF machine {machine}"))),
    };
    if elf.big != arch.big_endian() {
        let order = if elf.big { "big" } else { "little" };
        return Err(Error::Arch(format!("{order}-endian {arch:?} ELF")));
    }
    Ok(arch)
}

/// `segments` with the `ranges` (start, end) that lie wholly inside
/// executable ones split out of them as data.
fn fence<'a>(segments: Vec<Segment<'a>>, mut ranges: Vec<(u64, u64)>) -> Vec<Segment<'a>> {
    ranges.sort_unstable();
    let mut out = Vec::with_capacity(segments.len());
    for segment in segments {
        let len = segment.bytes.len() as u64;
        let end = segment.addr.saturating_add(len);
        let inside: Vec<(u64, u64)> = ranges
            .iter()
            .copied()
            .filter(|&(from, to)| segment.executable && from >= segment.addr && to <= end)
            .collect();
        if inside.is_empty() {
            out.push(segment);
            continue;
        }
        let piece = |from: u64, to: u64, executable: bool| {
            let range = usize::try_from(from - segment.addr).unwrap_or(0)
                ..usize::try_from(to - segment.addr).unwrap_or(0);
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

const DT_INIT: u64 = 12;
const DT_FINI: u64 = 13;
const DT_INIT_ARRAY: u64 = 25;
const DT_FINI_ARRAY: u64 = 26;
const DT_INIT_ARRAYSZ: u64 = 27;
const DT_FINI_ARRAYSZ: u64 = 28;
const DT_PREINIT_ARRAY: u64 = 32;
const DT_PREINIT_ARRAYSZ: u64 = 33;

fn elf_image<'a>(bytes: &'a [u8], elf: &Elf) -> Result<Image<'a>, Error> {
    let arch = elf_arch(elf)?;
    let object = elf.kind == elf::ET_REL;

    // An object's sections are placed and linked as a loader would see
    // them; an executable's sit at their addresses. Program headers stand in
    // when the section table is stripped, empty, or names no code (packers).
    let (addrs, mut segments, mut imports) = if object {
        let layout = relocate::layout(bytes, elf, arch);
        (layout.addrs, layout.segments, layout.imports)
    } else {
        let segments = elf
            .sections
            .iter()
            .filter(|sh| sh.flags & elf::SHF_ALLOC != 0 && sh.kind != elf::SHT_NOBITS)
            .flat_map(|sh| {
                let data = file_range(bytes, sh.offset, sh.size);
                let executable = sh.flags & elf::SHF_EXECINSTR != 0;
                // Zeros that start code are written at load time: SPARC's
                // `.plt` header (and on 64-bit SPARC, the whole `.plt` but
                // the entries' first jumps), which the dynamic linker fills.
                let zeros = if executable {
                    data.iter().take_while(|&&b| b == 0).count() & !15
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
        let addrs = elf.sections.iter().map(|sh| sh.addr).collect();
        // Sun Studio puts constant pools (`___const_seg_*`, jump tables
        // among them) in `.text`, as data objects: they are not code.
        let pools: Vec<(u64, u64)> = elf
            .symbols
            .iter()
            .filter(|symbol| symbol.kind == elf::STT_OBJECT && symbol.size > 0)
            .filter(|symbol| symbol.shndx != elf::SHN_UNDEF)
            .map(|symbol| (symbol.value, symbol.value.saturating_add(symbol.size)))
            .collect();
        (addrs, fence(segments, pools), Vec::new())
    };
    if !segments
        .iter()
        .any(|segment: &Segment<'_>| segment.executable && !segment.bytes.is_empty())
    {
        segments = elf
            .programs
            .iter()
            .filter(|ph| ph.kind == elf::PT_LOAD)
            .map(|ph| Segment {
                addr: ph.vaddr,
                bytes: Cow::Borrowed(file_range(bytes, ph.offset, ph.filesz)),
                executable: ph.flags & elf::PF_X != 0,
            })
            .collect();
    }
    let sections = ElfSections { elf, addrs: &addrs };

    let mut seeds = Vec::new();
    if elf.entry != 0 {
        seeds.push(seed(elf.entry, Origin::Entry));
    }
    for symbol in elf.symbols.iter().chain(&elf.dynamic_symbols) {
        if symbol.kind != elf::STT_FUNC || symbol.shndx == elf::SHN_UNDEF {
            continue;
        }
        // An object's symbol values are offsets into their sections, and
        // the first function of each sits at offset zero.
        let addr = if object {
            match addrs.get(usize::from(symbol.shndx)) {
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
    let memory = Memory::for_arch(&segments, arch);
    let (inits, finis) = elf_initializers(elf, &sections, &memory);
    seeds.extend(
        (0..)
            .zip(inits)
            .map(|(i, addr)| seed(addr, Origin::Init(i))),
    );
    seeds.extend(
        (0..)
            .zip(finis)
            .map(|(i, addr)| seed(addr, Origin::Fini(i))),
    );
    if let Some((_, sh)) = sections.find(".gopclntab") {
        let text = sections.find(".text").map(|(addr, _)| addr);
        let table = file_range(bytes, sh.offset, sh.size);
        seeds.extend(
            gopclntab::functions(table, text, true, elf.big)
                .into_iter()
                .map(|(addr, name)| seed(addr, Origin::Symbol(name))),
        );
    }
    let (mut handlers, mut extents) = (Vec::new(), Vec::new());
    if let Some((addr, sh)) = sections.find(".eh_frame") {
        (extents, handlers) = eh::eh_frame(&memory, addr, sh.size, elf.is_64);
        seeds.extend(
            extents
                .iter()
                .map(|extent| seed(extent.start, Origin::Unwind)),
        );
    }
    seeds.extend(
        elf_stubs(bytes, arch, &sections)
            .into_iter()
            .map(|addr| seed(addr, Origin::Stub)),
    );

    // Relocations against undefined symbols fill import slots.
    for reloc in &elf.dynamic_relocations {
        if reloc.symbol == 0 {
            continue;
        }
        let Some(symbol) = elf.dynamic_symbols.get(reloc.symbol) else {
            continue;
        };
        if symbol.shndx == elf::SHN_UNDEF && !symbol.name.is_empty() {
            imports.push(Import {
                slot: reloc.offset,
                name: symbol.name.clone(),
            });
        }
    }
    let mips = arch.mips();
    if mips {
        imports.extend(mips_got_imports(elf));
    }
    let got = if arch == Arch::X86 {
        elf.dynamic_value(elf::DT_PLTGOT)
            .or_else(|| sections.find(".got.plt").map(|(addr, _)| addr))
    } else if mips {
        // `_gp`, which the linker places 0x7ff0 past the GOT's start unless
        // told otherwise.
        elf.symbols
            .iter()
            .chain(&elf.dynamic_symbols)
            .find(|symbol| symbol.name == "_gp" && symbol.value != 0)
            .map(|symbol| symbol.value)
            .or_else(|| {
                // A static, stripped executable has neither: its `.got`
                // section stands in (uClibc's `__start` computes `$gp` the
                // same way, `bal; lui; addiu; addu $gp, $gp, $ra`).
                elf.dynamic_value(elf::DT_PLTGOT)
                    .or_else(|| sections.find(".got").map(|(addr, _)| addr))
                    .map(|got| got.wrapping_add(0x7ff0))
            })
    } else {
        None
    };
    if mips && !object {
        seeds.extend(
            mips_got_pointers(elf, &sections, &memory, &imports)
                .into_iter()
                .map(|addr| seed(addr, Origin::Pointer)),
        );
    }
    drop(memory);

    Ok(Image {
        arch,
        segments,
        seeds,
        imports,
        handlers,
        extents,
        got,
    })
}

/// The MIPS GOT's slots for undefined symbols. The GOT holds its local
/// entries, then one for each dynamic symbol from `DT_MIPS_GOTSYM` on, in
/// order; the dynamic linker fills them without relocations.
fn mips_got_imports(elf: &Elf) -> Vec<Import> {
    let (Some(got), Some(local), Some(first)) = (
        elf.dynamic_value(elf::DT_PLTGOT),
        elf.dynamic_value(elf::DT_MIPS_LOCAL_GOTNO),
        elf.dynamic_value(elf::DT_MIPS_GOTSYM),
    ) else {
        return Vec::new();
    };
    let width = if elf.is_64 { 8 } else { 4 };
    let first = usize::try_from(first).unwrap_or(usize::MAX);
    (local..)
        .zip(elf.dynamic_symbols.iter().skip(first))
        .filter(|(_, symbol)| symbol.shndx == elf::SHN_UNDEF && !symbol.name.is_empty())
        .map(|(entry, symbol)| Import {
            slot: got.wrapping_add(entry.wrapping_mul(width)),
            name: symbol.name.clone(),
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
    imports: &[Import],
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
    let slots: std::collections::HashSet<u64> = imports.iter().map(|import| import.slot).collect();
    (0..size / u64::from(width))
        .map(|i| start.wrapping_add(i * u64::from(width)))
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
fn elf_stubs(bytes: &[u8], arch: Arch, sections: &ElfSections<'_>) -> Vec<u64> {
    if arch == Arch::Arm {
        return arm_stubs(bytes, sections);
    }
    // Each set's header size, and its stub size when the section's entry
    // size does not give it (Arm's `.plt` says 4, a word).
    let (header, stub) = match arch {
        Arch::X86 | Arch::X86_64 => (16, None),
        Arch::Arm64 => (32, None),
        Arch::S390x => (32, Some(32)),
        // Four reserved entries, which the dynamic linker fills, then one
        // per import (`sethi; ba,a`): 12 bytes on 32-bit SPARC, 32 on V9.
        Arch::Sparc => (48, Some(12)),
        Arch::Sparc64 => (128, Some(32)),
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
            None if sh.entsize >= 4 => sh.entsize,
            None => 16,
        };
        let count = (sh.size.saturating_sub(skip) / size).min(1 << 16);
        (0..count).map(|i| addr + skip + i * size).collect()
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
    let Some((addr, sh)) = sections.find(".plt") else {
        return Vec::new();
    };
    let plt = file_range(bytes, sh.offset, sh.size);
    let mut stubs = vec![addr];
    let mut at = 20_usize;
    while at < plt.len() && stubs.len() <= 1 << 16 {
        let stub = addr.wrapping_add(at as u64);
        // `bx pc` (0x4778), little-endian.
        if plt.get(at..at + 2) == Some(&[0x78, 0x47][..]) {
            stubs.extend([stub | 1, stub + 4]);
            at += 16;
        } else {
            stubs.push(stub);
            at += 12;
        }
    }
    stubs
}

/// Initializer and finalizer addresses in the order the loader runs them:
/// `DT_PREINIT_ARRAY`, `DT_INIT`, `DT_INIT_ARRAY`, then `DT_FINI_ARRAY` and
/// `DT_FINI`; or the array sections of a static executable.
fn elf_initializers(
    elf: &Elf,
    sections: &ElfSections<'_>,
    memory: &Memory<'_>,
) -> (Vec<u64>, Vec<u64>) {
    let width: u8 = if elf.is_64 { 8 } else { 4 };
    // A position-independent array holds zeros until a RELATIVE relocation
    // fills it; the relocation's addend is the address.
    let relative = |slot: u64| {
        elf.dynamic_relocations
            .iter()
            .find(|reloc| reloc.offset == slot && reloc.symbol == 0 && reloc.addend.is_some())
            .and_then(|reloc| reloc.addend)
            .and_then(|addend| u64::try_from(addend).ok())
    };
    let array = |start: u64, size: u64| -> Vec<u64> {
        let count = (size / u64::from(width)).min(1 << 16);
        (0..count)
            .filter_map(|i| {
                let slot = start.wrapping_add(i * u64::from(width));
                match memory.read(slot, width) {
                    Some(0) | None => relative(slot),
                    // All ones terminates the old `.ctors` lists.
                    Some(value) if value == u64::MAX || value == u64::from(u32::MAX) => None,
                    value => value,
                }
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
    let mut inits = array(value(DT_PREINIT_ARRAY), value(DT_PREINIT_ARRAYSZ));
    inits.extend(Some(value(DT_INIT)).filter(|&init| init != 0));
    inits.extend(array(value(DT_INIT_ARRAY), value(DT_INIT_ARRAYSZ)));
    let mut finis = array(value(DT_FINI_ARRAY), value(DT_FINI_ARRAYSZ));
    finis.extend(Some(value(DT_FINI)).filter(|&fini| fini != 0));
    (inits, finis)
}

// ---------------------------------------------------------------------------
// PE
// ---------------------------------------------------------------------------

const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

fn pe_image<'a>(bytes: &'a [u8], pe: &Pe<'_>) -> Result<Image<'a>, Error> {
    let machine = pe.machine;
    let arch = match machine {
        0x014c => Arch::X86,
        0x8664 => Arch::X86_64,
        0xaa64 => Arch::Arm64,
        // Windows CE on Arm, with Thumb (`THUMB`) or without; ARMNT,
        // Windows on 32-bit Arm, which runs Thumb-2 only.
        0x01c0 | 0x01c2 | 0x01c4 => Arch::Arm,
        _ => return Err(Error::Arch(format!("PE machine {machine:#06x}"))),
    };
    // ARMNT code addresses carry Thumb's bit 0, as `.pdata` writes them;
    // Windows CE's set it for Thumb code only.
    let code = |addr: u64| if machine == 0x01c4 { addr | 1 } else { addr };
    let base = pe.image_base;
    let at = |rva: u32| base.wrapping_add(u64::from(rva));
    let resources = pe.resources();
    let segments: Vec<Segment<'a>> = pe
        .sections
        .iter()
        .map(|section| {
            let raw = u64::from(section.size_of_raw_data);
            let size = match u64::from(section.virtual_size) {
                0 => raw,
                virtual_size => raw.min(virtual_size),
            };
            Segment {
                addr: at(section.virtual_address),
                bytes: Cow::Borrowed(file_range(
                    bytes,
                    u64::from(section.pointer_to_raw_data),
                    size,
                )),
                executable: section.characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE)
                    != 0
                    && !resources.is_some_and(|rva| {
                        rva.wrapping_sub(section.virtual_address) < section.virtual_size.max(1)
                    }),
            }
        })
        .collect();

    let mut seeds = Vec::new();
    if pe.entry != 0 {
        seeds.push(seed(code(at(pe.entry)), Origin::Entry));
    }
    for (rva, name) in pe.exports() {
        if rva != 0 {
            seeds.push(seed(code(at(rva)), Origin::Export(name)));
        }
    }
    seeds.extend(
        (0..)
            .zip(pe.tls_callbacks())
            .map(|(i, addr)| seed(code(addr), Origin::Tls(i))),
    );
    seeds.extend(
        pe_gopclntab(&segments)
            .into_iter()
            .map(|(addr, name)| seed(addr, Origin::Symbol(name))),
    );
    let mut extents = Vec::new();
    match arch {
        Arch::Arm64 => seeds.extend(
            pe.arm64_functions()
                .into_iter()
                .map(|begin| seed(at(begin), Origin::Unwind)),
        ),
        Arch::Arm if machine == 0x01c4 => seeds.extend(
            pe.arm_functions()
                .into_iter()
                .map(|begin| seed(at(begin), Origin::Unwind)),
        ),
        Arch::Arm => {
            for (begin, end) in pe.wince_functions() {
                seeds.push(seed(begin, Origin::Unwind));
                extents.push(begin..end);
            }
        }
        Arch::X86_64 => {
            for (begin, end) in pe.x64_functions() {
                seeds.push(seed(at(begin), Origin::Unwind));
                extents.push(at(begin)..at(end));
            }
        }
        // 32-bit x86 unwinds by frame chain, not by table.
        _ => {}
    }
    let imports = pe
        .imports()
        .into_iter()
        .map(|(slot, name)| Import {
            slot: at(slot),
            name,
        })
        .collect();

    Ok(Image {
        arch,
        segments,
        seeds,
        imports,
        handlers: Vec::new(),
        extents,
        got: None,
    })
}

// ---------------------------------------------------------------------------
// Mach-O
// ---------------------------------------------------------------------------

const S_ZEROFILL: u32 = 0x1;
const S_NON_LAZY_SYMBOL_POINTERS: u32 = 0x6;
const S_LAZY_SYMBOL_POINTERS: u32 = 0x7;
const S_SYMBOL_STUBS: u32 = 0x8;
const S_GB_ZEROFILL: u32 = 0xc;
const S_THREAD_LOCAL_ZEROFILL: u32 = 0x12;

fn macho_arch(cputype: u32) -> Option<Arch> {
    match cputype {
        macho::CPU_TYPE_X86 => Some(Arch::X86),
        macho::CPU_TYPE_X86_64 => Some(Arch::X86_64),
        macho::CPU_TYPE_ARM64 => Some(Arch::Arm64),
        _ => None,
    }
}

fn fat_image(bytes: &[u8]) -> Result<Image<'_>, Error> {
    let slices = macho::fat(bytes).map_err(Error::Format)?;
    let slice = slices
        .iter()
        .find(|slice| macho_arch(slice.cputype).is_some())
        .ok_or_else(|| Error::Arch("no supported slice in universal binary".into()))?;
    let slice = file_range(bytes, slice.offset, slice.size);
    macho_image(slice, &macho::parse(slice).map_err(Error::Format)?)
}

fn macho_image<'a>(bytes: &'a [u8], macho: &MachO) -> Result<Image<'a>, Error> {
    let cputype = macho.cputype;
    let arch =
        macho_arch(cputype).ok_or_else(|| Error::Arch(format!("Mach-O CPU type {cputype:#x}")))?;
    if macho.big {
        return Err(Error::Arch("big-endian Mach-O".into()));
    }
    let sections = &macho.sections;
    let symbols = &macho.symbols;
    // An object's calls are linked to their symbols first.
    let (mut linked, mut imports) = if macho.filetype == macho::MH_OBJECT {
        relocate::macho(bytes, sections, symbols, arch)
    } else {
        (Vec::new(), Vec::new())
    };
    let segments: Vec<Segment<'a>> = sections
        .iter()
        .enumerate()
        .filter(|(_, section)| {
            !matches!(
                section.flags & macho::SECTION_TYPE,
                S_ZEROFILL | S_GB_ZEROFILL | S_THREAD_LOCAL_ZEROFILL
            )
        })
        .map(|(i, section)| Segment {
            addr: section.addr,
            bytes: match linked.get_mut(i).and_then(Option::take) {
                Some(owned) => Cow::Owned(owned),
                None => Cow::Borrowed(file_range(bytes, section.offset, section.size)),
            },
            executable: section.code,
        })
        .collect();

    let mut seeds = Vec::new();
    if macho.entry != 0 {
        seeds.push(seed(macho.entry, Origin::Entry));
    }
    for symbol in symbols {
        if !symbol.is_stab()
            && symbol.n_type & macho::N_TYPE == macho::N_SECT
            && symbol.n_value != 0
        {
            seeds.push(seed(symbol.n_value, Origin::Symbol(symbol.name.clone())));
        }
    }
    let text = macho
        .segments
        .iter()
        .find(|segment| segment.named("__TEXT"))
        .map(|segment| segment.vmaddr);
    let pointer: u64 = if macho.is_64 { 8 } else { 4 };
    if let (Some(mut addr), Some((offset, size))) = (text, macho.function_starts) {
        for delta in uleb128s(file_range(bytes, offset, size)).take_while(|&delta| delta != 0) {
            addr = addr.wrapping_add(delta);
            seeds.push(seed(addr, Origin::FunctionStarts));
        }
    }
    for section in sections {
        let kind = section.flags & macho::SECTION_TYPE;
        if kind != S_NON_LAZY_SYMBOL_POINTERS && kind != S_LAZY_SYMBOL_POINTERS {
            continue;
        }
        let first = section.reserved1 as usize;
        let count = usize::try_from(section.size / pointer).unwrap_or(0);
        let entries = macho.indirect.iter().skip(first).take(count);
        for (i, &index) in (0_u64..).zip(entries) {
            // INDIRECT_SYMBOL_LOCAL and INDIRECT_SYMBOL_ABS name no import.
            if index & 0xc000_0000 != 0 {
                continue;
            }
            if let Some(symbol) = symbols.get(index as usize)
                && !symbol.name.is_empty()
            {
                imports.push(Import {
                    slot: section.addr.wrapping_add(i * pointer),
                    name: symbol.name.clone(),
                });
            }
        }
    }

    if let Some(section) = sections.iter().find(|section| section.named("__gopclntab")) {
        let text = sections
            .iter()
            .find(|section| section.named("__text"))
            .map(|section| section.addr);
        let table = file_range(bytes, section.offset, section.size);
        seeds.extend(
            gopclntab::functions(table, text, true, false)
                .into_iter()
                .map(|(addr, name)| seed(addr, Origin::Symbol(name))),
        );
    }

    // Stubs: each jumps through the symbol pointer its index names.
    for section in sections {
        if section.flags & macho::SECTION_TYPE != S_SYMBOL_STUBS || section.reserved2 == 0 {
            continue;
        }
        let size = u64::from(section.reserved2);
        let count = (section.size / size).min(1 << 16);
        seeds.extend((0..count).map(|i| seed(section.addr + i * size, Origin::Stub)));
    }

    let memory = Memory::new(&segments);
    let width: u8 = if macho.is_64 { 8 } else { 4 };
    let (mut handlers, mut extents) = (Vec::new(), Vec::new());
    if let Some(section) = sections.iter().find(|section| section.named("__eh_frame")) {
        (extents, handlers) = eh::eh_frame(&memory, section.addr, section.size, macho.is_64);
        seeds.extend(
            extents
                .iter()
                .map(|extent| seed(extent.start, Origin::Unwind)),
        );
    }
    if let (Some(base), Some(section)) = (
        text,
        sections
            .iter()
            .find(|section| section.named("__unwind_info")),
    ) {
        let info = file_range(bytes, section.offset, section.size);
        for (function, lsda) in unwind_info_lsdas(info) {
            let function = base.wrapping_add(u64::from(function));
            let lsda = base.wrapping_add(u64::from(lsda));
            handlers.extend(
                eh::landing_pads(&memory, lsda, function, width)
                    .into_iter()
                    .map(|addr| Handler { function, addr }),
            );
        }
    }
    drop(memory);

    Ok(Image {
        arch,
        segments,
        seeds,
        imports,
        handlers,
        extents,
        got: None,
    })
}

/// The (function, LSDA) pairs of a compact unwind table, as offsets from
/// the image base. The first-level index's entries each point at a run of
/// LSDA entries; the runs are contiguous, so the table is the span from the
/// first entry's run to the last's (the sentinel).
fn unwind_info_lsdas(info: &[u8]) -> impl Iterator<Item = (u32, u32)> + '_ {
    let u32_at = |at: usize| -> Option<u32> {
        Some(u32::from_le_bytes(
            info.get(at..at.checked_add(4)?)?.try_into().ok()?,
        ))
    };
    let span = (|| {
        if u32_at(0)? != 1 {
            return None;
        }
        let index = usize::try_from(u32_at(20)?).ok()?;
        let count = usize::try_from(u32_at(24)?).ok()?;
        let last = index.checked_add(count.checked_sub(1)?.checked_mul(12)?)?;
        let start = usize::try_from(u32_at(index.checked_add(8)?)?).ok()?;
        let end = usize::try_from(u32_at(last.checked_add(8)?)?).ok()?;
        info.get(start..end.max(start))
    })()
    .unwrap_or_default();
    span.chunks_exact(8).filter_map(|pair| {
        let function = u32::from_le_bytes(pair.get(..4)?.try_into().ok()?);
        let lsda = u32::from_le_bytes(pair.get(4..)?.try_into().ok()?);
        Some((function, lsda))
    })
}

/// The ULEB128 values packed in `data`, ending at the first truncated one.
fn uleb128s(data: &[u8]) -> impl Iterator<Item = u64> + '_ {
    let mut rest = data;
    std::iter::from_fn(move || {
        let mut value = 0_u64;
        let mut shift = 0_u32;
        loop {
            let (&byte, tail) = rest.split_first()?;
            rest = tail;
            if shift < 64 {
                value |= u64::from(byte & 0x7f) << shift;
            }
            shift = shift.saturating_add(7);
            if byte & 0x80 == 0 {
                return Some(value);
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn uleb128() {
        let values: Vec<u64> = uleb128s(&[0x02, 0xe5, 0x8e, 0x26, 0x80]).collect();
        assert_eq!(values, [2, 624_485]);
    }

    /// A compact unwind table: two first-level entries (the second the
    /// sentinel) and the run of LSDA entries between them.
    #[test]
    fn unwind_info_names_lsdas() {
        let words: [u32; 17] = [
            1, 28, 0, 28, 0, 28, 2, // header: version, encodings, personalities, index
            0x1000, 0, 52, // index entry: its LSDA run starts at 52
            0x2000, 0, 68, // sentinel: the run ends at 68
            0x1000, 0x4000, 0x1100, 0x4010, // (function, LSDA) pairs
        ];
        let info: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        let pairs: Vec<(u32, u32)> = unwind_info_lsdas(&info).collect();
        assert_eq!(pairs, [(0x1000, 0x4000), (0x1100, 0x4010)]);
        assert_eq!(
            unwind_info_lsdas(info.get(..30).unwrap_or_default()).count(),
            0
        );
        assert_eq!(unwind_info_lsdas(&[]).count(), 0);
    }

    #[test]
    fn file_ranges_clamp() {
        let bytes = [1, 2, 3, 4];
        assert_eq!(file_range(&bytes, 2, 10), [3, 4]);
        assert!(file_range(&bytes, 9, 1).is_empty());
        assert!(file_range(&bytes, u64::MAX, u64::MAX).is_empty());
    }

    #[test]
    fn rejects_garbage() {
        assert!(image(b"").is_err());
        assert!(image(b"not an executable at all").is_err());
        assert!(image(b"\x7fELF\x02\x01\x01").is_err());
        assert!(image(b"MZ\x90\x00").is_err());
    }
}
