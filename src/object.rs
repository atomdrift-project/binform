//! Build an [`Image`] from the bytes of an ELF, PE or Mach-O file.
//!
//! Everything a loader or linker leaves behind that names function starts
//! becomes a [`Seed`]: entry points, initializers, TLS callbacks, symbols,
//! exports, unwind tables and Mach-O function starts. Import slots come from
//! the PE import table, ELF relocations against undefined symbols, and the
//! Mach-O indirect symbol table.

use std::fmt;

use goblin::elf::{Elf, program_header, section_header, sym};
use goblin::mach::{self, MachO};
use goblin::pe::PE;

use crate::decode::Memory;
use crate::{Arch, Image, Import, Origin, Seed, Segment};

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
    use goblin::elf::header::{EM_386, EM_AARCH64, EM_X86_64};
    let arch = match elf.header.e_machine {
        EM_386 => Arch::X86,
        EM_X86_64 => Arch::X86_64,
        EM_AARCH64 => Arch::Arm64,
        machine => return Err(Error::Arch(format!("ELF machine {machine}"))),
    };
    if !elf.little_endian {
        return Err(Error::Arch("big-endian ELF".into()));
    }

    // Sections when they describe code; program headers when the section
    // table is stripped, empty, or names no code (packers).
    let mut segments: Vec<Segment<'a>> = elf
        .section_headers
        .iter()
        .filter(|sh| {
            sh.sh_flags & u64::from(section_header::SHF_ALLOC) != 0
                && sh.sh_type != section_header::SHT_NOBITS
        })
        .map(|sh| Segment {
            addr: sh.sh_addr,
            bytes: file_range(bytes, sh.sh_offset, sh.sh_size),
            executable: sh.sh_flags & u64::from(section_header::SHF_EXECINSTR) != 0,
        })
        .collect();
    if !segments
        .iter()
        .any(|segment| segment.executable && !segment.bytes.is_empty())
    {
        segments = elf
            .program_headers
            .iter()
            .filter(|ph| ph.p_type == program_header::PT_LOAD)
            .map(|ph| Segment {
                addr: ph.p_vaddr,
                bytes: file_range(bytes, ph.p_offset, ph.p_filesz),
                executable: ph.p_flags & program_header::PF_X != 0,
            })
            .collect();
    }

    let mut seeds = Vec::new();
    if elf.entry != 0 {
        seeds.push(seed(elf.entry, Origin::Entry));
    }
    for (symbols, names) in [(&elf.syms, &elf.strtab), (&elf.dynsyms, &elf.dynstrtab)] {
        for symbol in symbols.iter() {
            if symbol.st_type() == sym::STT_FUNC
                && symbol.st_shndx != section_header::SHN_UNDEF as usize
                && symbol.st_value != 0
            {
                let name = names.get_at(symbol.st_name).unwrap_or_default();
                seeds.push(seed(symbol.st_value, Origin::Symbol(name.to_owned())));
            }
        }
    }
    let memory = Memory::new(&segments);
    let (inits, finis) = elf_initializers(elf, &memory);
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
    if let Some(eh_frame) = elf_section(elf, ".eh_frame") {
        let data = file_range(bytes, eh_frame.sh_offset, eh_frame.sh_size);
        unwind_starts(data, eh_frame.sh_addr, elf.is_64, &mut seeds);
    }

    // Relocations against undefined symbols fill import slots.
    let mut imports = Vec::new();
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
            .or_else(|| elf_section(elf, ".got.plt").map(|sh| sh.sh_addr))
    } else {
        None
    };

    Ok(Image {
        arch,
        segments,
        seeds,
        imports,
        got,
    })
}

fn elf_section<'e>(elf: &'e Elf<'_>, name: &str) -> Option<&'e section_header::SectionHeader> {
    elf.section_headers
        .iter()
        .find(|sh| elf.shdr_strtab.get_at(sh.sh_name) == Some(name))
}

/// Initializer and finalizer addresses in the order the loader runs them:
/// `DT_INIT` then `DT_INIT_ARRAY` (and the fini pair), or the array sections
/// of a static executable.
fn elf_initializers(elf: &Elf<'_>, memory: &Memory<'_>) -> (Vec<u64>, Vec<u64>) {
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
        elf_section(elf, name)
            .map(|sh| array(sh.sh_addr, sh.sh_size))
            .unwrap_or_default()
    };
    match &elf.dynamic {
        Some(dynamic) => {
            let info = &dynamic.info;
            let mut inits: Vec<u64> = Some(info.init)
                .filter(|&init| init != 0)
                .into_iter()
                .collect();
            inits.extend(array(info.init_array, info.init_arraysz as u64));
            let mut finis: Vec<u64> = Some(info.fini)
                .filter(|&fini| fini != 0)
                .into_iter()
                .collect();
            finis.extend(array(info.fini_array, info.fini_arraysz as u64));
            (inits, finis)
        }
        None => {
            let mut inits = section(".preinit_array");
            inits.extend(section(".init_array"));
            (inits, section(".fini_array"))
        }
    }
}

/// The start of every range `.eh_frame` describes.
fn unwind_starts(data: &[u8], addr: u64, is_64: bool, seeds: &mut Vec<Seed>) {
    use gimli::{BaseAddresses, CieOrFde, EhFrame, LittleEndian, UnwindSection};
    let mut eh_frame = EhFrame::new(data, LittleEndian);
    eh_frame.set_address_size(if is_64 { 8 } else { 4 });
    let bases = BaseAddresses::default().set_eh_frame(addr);
    let mut entries = eh_frame.entries(&bases);
    while let Ok(Some(entry)) = entries.next() {
        if let CieOrFde::Fde(partial) = entry
            && let Ok(fde) = partial.parse(EhFrame::cie_from_offset)
        {
            seeds.push(seed(fde.initial_address(), Origin::Unwind));
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
                bytes: file_range(bytes, u64::from(section.pointer_to_raw_data), size),
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
                let addr = base.wrapping_add(u64::from(function.begin_address));
                seeds.push(seed(addr, Origin::Unwind));
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
        got: None,
    })
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
/// drops `reserved1`, a pointer section's index into the indirect symbol
/// table.
struct MachSection {
    addr: u64,
    size: u64,
    offset: u64,
    flags: u32,
    reserved1: u32,
    code: bool,
}

const S_ZEROFILL: u32 = 0x1;
const S_NON_LAZY_SYMBOL_POINTERS: u32 = 0x6;
const S_LAZY_SYMBOL_POINTERS: u32 = 0x7;
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
                        addr: u64_at(field(32))?,
                        size: u64_at(field(40))?,
                        offset: u64::from(u32_at(field(48))?),
                        flags: u32_at(field(64))?,
                        reserved1: u32_at(field(68))?,
                        code: false,
                    })
                })()
            } else {
                (|| {
                    Some(MachSection {
                        addr: u64::from(u32_at(field(32))?),
                        size: u64::from(u32_at(field(36))?),
                        offset: u64::from(u32_at(field(40))?),
                        flags: u32_at(field(56))?,
                        reserved1: u32_at(field(60))?,
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
    let segments: Vec<Segment<'a>> = sections
        .iter()
        .filter(|section| {
            !matches!(
                section.flags & mach::constants::SECTION_TYPE,
                S_ZEROFILL | S_GB_ZEROFILL | S_THREAD_LOCAL_ZEROFILL
            )
        })
        .map(|section| Segment {
            addr: section.addr,
            bytes: file_range(bytes, section.offset, section.size),
            executable: section.code,
        })
        .collect();

    let mut seeds = Vec::new();
    if macho.entry != 0 {
        seeds.push(seed(macho.entry, Origin::Entry));
    }
    let symbols: Vec<(&str, mach::symbols::Nlist)> = macho.symbols().flatten().collect();
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
    let mut imports = Vec::new();
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

    Ok(Image {
        arch,
        segments,
        seeds,
        imports,
        got: None,
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
