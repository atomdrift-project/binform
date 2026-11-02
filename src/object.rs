//! Build an [`Image`] from the bytes of an ELF, PE or Mach-O file.
//!
//! Everything a loader or linker leaves behind that names function starts
//! becomes a [`Seed`]: entry points, initializers, TLS callbacks, symbols,
//! exports, unwind tables and Mach-O function starts. Import slots come from
//! the PE import table, ELF relocations against undefined symbols, and the
//! Mach-O indirect symbol table.

use std::borrow::Cow;
use std::fmt;

use goblin::elf::{Elf, program_header, section_header, sym};
use goblin::mach::{self, MachO};
use goblin::pe::PE;

use crate::decode::Memory;
use crate::{Arch, Handler, Image, Import, Origin, Seed, Segment};

mod eh;
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
    let format = |e: goblin::error::Error| Error::Format(e.to_string());
    match bytes.get(..4) {
        Some(b"\x7fELF") => elf_image(bytes, &Elf::parse(bytes).map_err(format)?),
        Some([b'M', b'Z', ..]) => {
            let mut options = goblin::pe::options::ParseOptions::default();
            options.parse_attribute_certificates = false;
            options.parse_resources = false;
            pe_image(
                bytes,
                &PE::parse_with_opts(bytes, &options).map_err(format)?,
            )
        }
        Some(&[0xca, 0xfe, 0xba, 0xbe]) => fat_image(bytes),
        Some(_) => macho_image(bytes, &MachO::parse(bytes, 0).map_err(format)?),
        None => Err(Error::Format("too short".into())),
    }
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

fn elf_image<'a>(bytes: &'a [u8], elf: &Elf<'_>) -> Result<Image<'a>, Error> {
    use goblin::elf::header::{EM_386, EM_AARCH64, EM_X86_64, ET_REL};
    let arch = match elf.header.e_machine {
        EM_386 => Arch::X86,
        EM_X86_64 => Arch::X86_64,
        EM_AARCH64 => Arch::Arm64,
        machine => return Err(Error::Arch(format!("ELF machine {machine}"))),
    };
    if !elf.little_endian {
        return Err(Error::Arch("big-endian ELF".into()));
    }
    let object = elf.header.e_type == ET_REL;

    // An object's sections are placed and linked as a loader would see
    // them; an executable's sit at their addresses. Program headers stand in
    // when the section table is stripped, empty, or names no code (packers).
    let (addrs, mut segments, mut imports) = if object {
        let layout = relocate::layout(bytes, elf, arch);
        (layout.addrs, layout.segments, layout.imports)
    } else {
        let segments = elf
            .section_headers
            .iter()
            .filter(|sh| {
                sh.sh_flags & u64::from(section_header::SHF_ALLOC) != 0
                    && sh.sh_type != section_header::SHT_NOBITS
            })
            .map(|sh| Segment {
                addr: sh.sh_addr,
                bytes: Cow::Borrowed(file_range(bytes, sh.sh_offset, sh.sh_size)),
                executable: sh.sh_flags & u64::from(section_header::SHF_EXECINSTR) != 0,
            })
            .collect();
        let addrs = elf.section_headers.iter().map(|sh| sh.sh_addr).collect();
        (addrs, segments, Vec::new())
    };
    if !segments
        .iter()
        .any(|segment: &Segment<'_>| segment.executable && !segment.bytes.is_empty())
    {
        segments = elf
            .program_headers
            .iter()
            .filter(|ph| ph.p_type == program_header::PT_LOAD)
            .map(|ph| Segment {
                addr: ph.p_vaddr,
                bytes: Cow::Borrowed(file_range(bytes, ph.p_offset, ph.p_filesz)),
                executable: ph.p_flags & program_header::PF_X != 0,
            })
            .collect();
    }
    let sections = ElfSections { elf, addrs: &addrs };

    let mut seeds = Vec::new();
    if elf.entry != 0 {
        seeds.push(seed(elf.entry, Origin::Entry));
    }
    for (symbols, names) in [(&elf.syms, &elf.strtab), (&elf.dynsyms, &elf.dynstrtab)] {
        for symbol in symbols.iter() {
            if symbol.st_type() != sym::STT_FUNC
                || symbol.st_shndx == section_header::SHN_UNDEF as usize
            {
                continue;
            }
            // An object's symbol values are offsets into their sections, and
            // the first function of each sits at offset zero.
            let addr = if object {
                match addrs.get(symbol.st_shndx) {
                    Some(&base) if base != 0 => base.wrapping_add(symbol.st_value),
                    _ => continue,
                }
            } else if symbol.st_value != 0 {
                symbol.st_value
            } else {
                continue;
            };
            let name = names.get_at(symbol.st_name).unwrap_or_default();
            seeds.push(seed(addr, Origin::Symbol(name.to_owned())));
        }
    }
    let memory = Memory::new(&segments);
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
    let mut handlers = Vec::new();
    if let Some((addr, sh)) = sections.find(".eh_frame") {
        let (starts, pads) = eh::eh_frame(&memory, addr, sh.sh_size, elf.is_64);
        seeds.extend(starts.into_iter().map(|addr| seed(addr, Origin::Unwind)));
        handlers = pads;
    }
    seeds.extend(
        elf_stubs(arch, &sections)
            .into_iter()
            .map(|addr| seed(addr, Origin::Stub)),
    );

    // Relocations against undefined symbols fill import slots.
    for reloc in elf
        .pltrelocs
        .iter()
        .chain(elf.dynrelas.iter())
        .chain(elf.dynrels.iter())
    {
        if reloc.r_sym == 0 {
            continue;
        }
        let Some(symbol) = elf.dynsyms.get(reloc.r_sym) else {
            continue;
        };
        let name = elf.dynstrtab.get_at(symbol.st_name).unwrap_or_default();
        if symbol.st_shndx == section_header::SHN_UNDEF as usize && !name.is_empty() {
            imports.push(Import {
                slot: reloc.r_offset,
                name: name.to_owned(),
            });
        }
    }
    let got = if arch == Arch::X86 {
        elf.dynamic
            .as_ref()
            .and_then(|dynamic| dynamic.info.pltgot)
            .or_else(|| sections.find(".got.plt").map(|(addr, _)| addr))
    } else {
        None
    };
    drop(memory);

    Ok(Image {
        arch,
        segments,
        seeds,
        imports,
        handlers,
        got,
    })
}

/// An ELF file's section headers with the address each is mapped at.
struct ElfSections<'e> {
    elf: &'e Elf<'e>,
    addrs: &'e [u64],
}

impl ElfSections<'_> {
    /// The address and header of the section called `name`.
    fn find(&self, name: &str) -> Option<(u64, &section_header::SectionHeader)> {
        self.elf
            .section_headers
            .iter()
            .zip(self.addrs)
            .find(|(sh, _)| self.elf.shdr_strtab.get_at(sh.sh_name) == Some(name))
            .map(|(sh, &addr)| (addr, sh))
    }
}

/// The entries of the procedure linkage table: its header, which jumps to
/// the dynamic linker, and one stub per import. With indirect-branch
/// tracking the stubs callers use live in `.plt.sec`; `.plt.got` holds the
/// stubs of imports bound at load time.
fn elf_stubs(arch: Arch, sections: &ElfSections<'_>) -> Vec<u64> {
    let entries = |name: &str, skip: u64| -> Vec<u64> {
        let Some((addr, sh)) = sections.find(name) else {
            return Vec::new();
        };
        let size = if sh.sh_entsize >= 4 {
            sh.sh_entsize
        } else {
            16
        };
        let count = (sh.sh_size.saturating_sub(skip) / size).min(1 << 16);
        (0..count).map(|i| addr + skip + i * size).collect()
    };
    let header = if arch == Arch::Arm64 { 32 } else { 16 };
    let mut stubs: Vec<u64> = sections
        .find(".plt")
        .map(|(addr, _)| addr)
        .into_iter()
        .collect();
    if sections.find(".plt.sec").is_some() {
        stubs.extend(entries(".plt.sec", 0));
    } else {
        stubs.extend(entries(".plt", header));
    }
    stubs.extend(entries(".plt.got", 0));
    stubs
}

/// Initializer and finalizer addresses in the order the loader runs them:
/// `DT_PREINIT_ARRAY`, `DT_INIT`, `DT_INIT_ARRAY`, then `DT_FINI_ARRAY` and
/// `DT_FINI`; or the array sections of a static executable.
fn elf_initializers(
    elf: &Elf<'_>,
    sections: &ElfSections<'_>,
    memory: &Memory<'_>,
) -> (Vec<u64>, Vec<u64>) {
    let width: u8 = if elf.is_64 { 8 } else { 4 };
    // A position-independent array holds zeros until a RELATIVE relocation
    // fills it; the relocation's addend is the address.
    let relative = |slot: u64| {
        elf.dynrelas
            .iter()
            .find(|reloc| reloc.r_offset == slot && reloc.r_sym == 0)
            .and_then(|reloc| reloc.r_addend)
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
            .map(|(addr, sh)| array(addr, sh.sh_size))
            .unwrap_or_default()
    };
    match &elf.dynamic {
        Some(dynamic) => {
            use goblin::elf::dynamic::{
                DT_FINI, DT_FINI_ARRAY, DT_FINI_ARRAYSZ, DT_INIT, DT_INIT_ARRAY, DT_INIT_ARRAYSZ,
                DT_PREINIT_ARRAY, DT_PREINIT_ARRAYSZ,
            };
            // The raw entries: goblin's summary turns these addresses into
            // file offsets.
            let value = |tag: u64| {
                dynamic
                    .dyns
                    .iter()
                    .find(|entry| entry.d_tag == tag)
                    .map_or(0, |entry| entry.d_val)
            };
            let mut inits = array(value(DT_PREINIT_ARRAY), value(DT_PREINIT_ARRAYSZ));
            inits.extend(Some(value(DT_INIT)).filter(|&init| init != 0));
            inits.extend(array(value(DT_INIT_ARRAY), value(DT_INIT_ARRAYSZ)));
            let mut finis = array(value(DT_FINI_ARRAY), value(DT_FINI_ARRAYSZ));
            finis.extend(Some(value(DT_FINI)).filter(|&fini| fini != 0));
            (inits, finis)
        }
        None => {
            let mut inits = section(".preinit_array");
            inits.extend(section(".init_array"));
            (inits, section(".fini_array"))
        }
    }
}

// ---------------------------------------------------------------------------
// PE
// ---------------------------------------------------------------------------

const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

fn pe_image<'a>(bytes: &'a [u8], pe: &PE<'_>) -> Result<Image<'a>, Error> {
    let machine = pe.header.coff_header.machine;
    let arch = match machine {
        0x014c => Arch::X86,
        0x8664 => Arch::X86_64,
        0xaa64 => Arch::Arm64,
        _ => return Err(Error::Arch(format!("PE machine {machine:#06x}"))),
    };
    let base = pe.image_base;
    let segments = pe
        .sections
        .iter()
        .map(|section| {
            let raw = u64::from(section.size_of_raw_data);
            let size = match u64::from(section.virtual_size) {
                0 => raw,
                virtual_size => raw.min(virtual_size),
            };
            Segment {
                addr: base.wrapping_add(u64::from(section.virtual_address)),
                bytes: Cow::Borrowed(file_range(
                    bytes,
                    u64::from(section.pointer_to_raw_data),
                    size,
                )),
                executable: section.characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE)
                    != 0,
            }
        })
        .collect();

    let mut seeds = Vec::new();
    if pe.entry != 0 {
        seeds.push(seed(base.wrapping_add(u64::from(pe.entry)), Origin::Entry));
    }
    for export in &pe.exports {
        if export.reexport.is_none() && export.rva != 0 {
            let name = export.name.unwrap_or_default().to_owned();
            seeds.push(seed(
                base.wrapping_add(export.rva as u64),
                Origin::Export(name),
            ));
        }
    }
    if let Some(tls) = &pe.tls_data {
        seeds.extend(
            (0..)
                .zip(&tls.callbacks)
                .map(|(i, &addr)| seed(addr, Origin::Tls(i))),
        );
    }
    if let Some(exceptions) = &pe.exception_data {
        if arch == Arch::Arm64 {
            for function in exceptions.functions_arm64().flatten() {
                if !arm64_fragment(exceptions, function, &pe.sections) {
                    let addr = base.wrapping_add(u64::from(function.begin_address));
                    seeds.push(seed(addr, Origin::Unwind));
                }
            }
        } else {
            for function in exceptions.functions().flatten() {
                // A chained entry continues a function that starts elsewhere.
                let chained = exceptions
                    .get_unwind_info(function, &pe.sections)
                    .is_ok_and(|info| info.chained_info.is_some());
                if !chained {
                    let addr = base.wrapping_add(u64::from(function.begin_address));
                    seeds.push(seed(addr, Origin::Unwind));
                }
            }
        }
    }
    let imports = pe
        .imports
        .iter()
        .map(|import| Import {
            slot: base.wrapping_add(import.offset as u64),
            name: import.name.to_string(),
        })
        .collect();

    Ok(Image {
        arch,
        segments,
        seeds,
        imports,
        handlers: Vec::new(),
        got: None,
    })
}

/// Whether an A64 unwind entry describes a fragment of a function rather
/// than its start: packed data that says so, or unwind codes that begin with
/// `end_c`, which stands for the prologue a fragment does not have. MSVC
/// splits functions it shrink-wraps into such fragments.
fn arm64_fragment(
    exceptions: &goblin::pe::exception::ExceptionData<'_>,
    function: goblin::pe::exception::Arm64RuntimeFunction,
    sections: &[goblin::pe::section_table::SectionTable],
) -> bool {
    use goblin::pe::exception::{ARM64_PDATA_PACKED_UNWIND_FRAGMENT, Arm64UnwindCode};
    if function.flag() == ARM64_PDATA_PACKED_UNWIND_FRAGMENT {
        return true;
    }
    let Some(Ok(info)) = exceptions.get_unwind_info_arm64(function, sections) else {
        return false;
    };
    let first = info.unwind_codes(0).ok().and_then(|mut codes| codes.next());
    matches!(first, Some(Ok(code)) if code.code == Arm64UnwindCode::EndC)
}

// ---------------------------------------------------------------------------
// Mach-O
// ---------------------------------------------------------------------------

const CPU_TYPE_X86: u32 = 7;
const CPU_TYPE_X86_64: u32 = 0x0100_0007;
const CPU_TYPE_ARM64: u32 = 0x0100_000c;

fn macho_arch(cputype: u32) -> Option<Arch> {
    match cputype {
        CPU_TYPE_X86 => Some(Arch::X86),
        CPU_TYPE_X86_64 => Some(Arch::X86_64),
        CPU_TYPE_ARM64 => Some(Arch::Arm64),
        _ => None,
    }
}

fn fat_image(bytes: &[u8]) -> Result<Image<'_>, Error> {
    let format = |e: goblin::error::Error| Error::Format(e.to_string());
    let fat = mach::MultiArch::new(bytes).map_err(format)?;
    let arches = fat.arches().map_err(format)?;
    let slice = arches
        .iter()
        .find(|arch| macho_arch(arch.cputype).is_some())
        .ok_or_else(|| Error::Arch("no supported slice in universal binary".into()))?;
    let slice = file_range(bytes, u64::from(slice.offset), u64::from(slice.size));
    macho_image(slice, &MachO::parse(slice, 0).map_err(format)?)
}

/// One section header, read from the load commands: goblin's `Section`
/// drops `reserved1`, a pointer or stub section's index into the indirect
/// symbol table, and `reserved2`, a stub section's stub size.
struct MachSection {
    name: [u8; 16],
    addr: u64,
    size: u64,
    offset: u64,
    /// File offset and count of the section's relocations (objects only).
    reloff: u32,
    nreloc: u32,
    flags: u32,
    reserved1: u32,
    reserved2: u32,
    code: bool,
}

impl MachSection {
    fn named(&self, name: &str) -> bool {
        let len = self.name.iter().position(|&b| b == 0).unwrap_or(16);
        self.name.get(..len) == Some(name.as_bytes())
    }
}

const S_ZEROFILL: u32 = 0x1;
const S_NON_LAZY_SYMBOL_POINTERS: u32 = 0x6;
const S_LAZY_SYMBOL_POINTERS: u32 = 0x7;
const S_SYMBOL_STUBS: u32 = 0x8;
const S_GB_ZEROFILL: u32 = 0xc;
const S_THREAD_LOCAL_ZEROFILL: u32 = 0x12;
const S_ATTR_CODE: u32 =
    mach::constants::S_ATTR_PURE_INSTRUCTIONS | mach::constants::S_ATTR_SOME_INSTRUCTIONS;
const VM_PROT_EXECUTE: u32 = 0x4;

fn mach_sections(bytes: &[u8], macho: &MachO<'_>) -> Vec<MachSection> {
    use mach::load_command::CommandVariant;
    let u32_at = |at: usize| {
        bytes
            .get(at..at.checked_add(4)?)
            .and_then(|b| b.try_into().ok())
            .map(u32::from_le_bytes)
    };
    let u64_at = |at: usize| {
        bytes
            .get(at..at.checked_add(8)?)
            .and_then(|b| b.try_into().ok())
            .map(u64::from_le_bytes)
    };
    let mut sections = Vec::new();
    for command in &macho.load_commands {
        let (header, size, wide, executable, count) = match &command.command {
            CommandVariant::Segment32(segment) => (
                56,
                68,
                false,
                segment.initprot & VM_PROT_EXECUTE != 0,
                segment.nsects,
            ),
            CommandVariant::Segment64(segment) => (
                72,
                80,
                true,
                segment.initprot & VM_PROT_EXECUTE != 0,
                segment.nsects,
            ),
            _ => continue,
        };
        for i in 0..count.min(1 << 12) as usize {
            let at = command
                .offset
                .saturating_add(header)
                .saturating_add(i.saturating_mul(size));
            let field = |offset: usize| at.saturating_add(offset);
            let parsed = if wide {
                (|| {
                    Some(MachSection {
                        name: bytes.get(at..at.checked_add(16)?)?.try_into().ok()?,
                        addr: u64_at(field(32))?,
                        size: u64_at(field(40))?,
                        offset: u64::from(u32_at(field(48))?),
                        reloff: u32_at(field(56))?,
                        nreloc: u32_at(field(60))?,
                        flags: u32_at(field(64))?,
                        reserved1: u32_at(field(68))?,
                        reserved2: u32_at(field(72))?,
                        code: false,
                    })
                })()
            } else {
                (|| {
                    Some(MachSection {
                        name: bytes.get(at..at.checked_add(16)?)?.try_into().ok()?,
                        addr: u64::from(u32_at(field(32))?),
                        size: u64::from(u32_at(field(36))?),
                        offset: u64::from(u32_at(field(40))?),
                        reloff: u32_at(field(48))?,
                        nreloc: u32_at(field(52))?,
                        flags: u32_at(field(56))?,
                        reserved1: u32_at(field(60))?,
                        reserved2: u32_at(field(64))?,
                        code: false,
                    })
                })()
            };
            let Some(mut section) = parsed else { break };
            section.code = executable && section.flags & S_ATTR_CODE != 0;
            sections.push(section);
        }
    }
    sections
}

fn macho_image<'a>(bytes: &'a [u8], macho: &MachO<'_>) -> Result<Image<'a>, Error> {
    use mach::load_command::CommandVariant;
    let cputype = macho.header.cputype;
    let arch =
        macho_arch(cputype).ok_or_else(|| Error::Arch(format!("Mach-O CPU type {cputype:#x}")))?;
    if !macho.little_endian {
        return Err(Error::Arch("big-endian Mach-O".into()));
    }
    let sections = mach_sections(bytes, macho);
    let symbols: Vec<(&str, mach::symbols::Nlist)> = macho.symbols().flatten().collect();
    // An object's calls are linked to their symbols first.
    let (mut linked, mut imports) = if macho.header.filetype == mach::header::MH_OBJECT {
        relocate::macho(bytes, &sections, &symbols, arch)
    } else {
        (Vec::new(), Vec::new())
    };
    let segments: Vec<Segment<'a>> = sections
        .iter()
        .enumerate()
        .filter(|(_, section)| {
            !matches!(
                section.flags & mach::constants::SECTION_TYPE,
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
    for (name, nlist) in &symbols {
        if !nlist.is_stab()
            && nlist.n_type & mach::symbols::N_TYPE == mach::symbols::N_SECT
            && nlist.n_value != 0
        {
            seeds.push(seed(nlist.n_value, Origin::Symbol((*name).to_owned())));
        }
    }
    let text = macho
        .segments
        .iter()
        .find(|segment| segment.name().is_ok_and(|name| name == "__TEXT"))
        .map(|segment| segment.vmaddr);
    let pointer: u64 = if macho.is_64 { 8 } else { 4 };
    for command in &macho.load_commands {
        match &command.command {
            CommandVariant::FunctionStarts(starts) => {
                let Some(mut addr) = text else { continue };
                let data = file_range(bytes, u64::from(starts.dataoff), u64::from(starts.datasize));
                for delta in uleb128s(data).take_while(|&delta| delta != 0) {
                    addr = addr.wrapping_add(delta);
                    seeds.push(seed(addr, Origin::FunctionStarts));
                }
            }
            CommandVariant::Dysymtab(dysymtab) => {
                let table = file_range(
                    bytes,
                    u64::from(dysymtab.indirectsymoff),
                    u64::from(dysymtab.nindirectsyms).saturating_mul(4),
                );
                let indirect: Vec<u32> = table
                    .chunks_exact(4)
                    .filter_map(|b| b.try_into().ok().map(u32::from_le_bytes))
                    .collect();
                for section in &sections {
                    let kind = section.flags & mach::constants::SECTION_TYPE;
                    if kind != S_NON_LAZY_SYMBOL_POINTERS && kind != S_LAZY_SYMBOL_POINTERS {
                        continue;
                    }
                    let first = section.reserved1 as usize;
                    let count = usize::try_from(section.size / pointer).unwrap_or(0);
                    let entries = indirect.iter().skip(first).take(count);
                    for (i, &index) in (0_u64..).zip(entries) {
                        // INDIRECT_SYMBOL_LOCAL and INDIRECT_SYMBOL_ABS name no import.
                        if index & 0xc000_0000 != 0 {
                            continue;
                        }
                        if let Some((name, _)) = symbols.get(index as usize)
                            && !name.is_empty()
                        {
                            imports.push(Import {
                                slot: section.addr.wrapping_add(i * pointer),
                                name: (*name).to_owned(),
                            });
                        }
                    }
                }
            }
            _ => {}
        }
    }

    // Stubs: each jumps through the symbol pointer its index names.
    for section in &sections {
        if section.flags & mach::constants::SECTION_TYPE != S_SYMBOL_STUBS || section.reserved2 == 0
        {
            continue;
        }
        let size = u64::from(section.reserved2);
        let count = (section.size / size).min(1 << 16);
        seeds.extend((0..count).map(|i| seed(section.addr + i * size, Origin::Stub)));
    }

    let memory = Memory::new(&segments);
    let width: u8 = if macho.is_64 { 8 } else { 4 };
    let mut handlers = Vec::new();
    if let Some(section) = sections.iter().find(|section| section.named("__eh_frame")) {
        let (starts, pads) = eh::eh_frame(&memory, section.addr, section.size, macho.is_64);
        seeds.extend(starts.into_iter().map(|addr| seed(addr, Origin::Unwind)));
        handlers = pads;
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
