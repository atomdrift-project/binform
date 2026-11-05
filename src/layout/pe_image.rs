//! A PE file's [`Binary`]: its code, where its functions start, and its
//! import slots.

use std::borrow::Cow;

use super::pe::Pe;
use super::read::Reader;
use super::{Tables, bare, file_range, go_seeds, gopclntab, limits, seed};
use crate::isa::Memory;
use crate::{Arch, Binary, Export, Format, Import, Origin, Section, Segment, Slot};

const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;
const IMAGE_FILE_MACHINE_R3000: u16 = 0x0162;
const IMAGE_FILE_MACHINE_R4000: u16 = 0x0166;
const IMAGE_FILE_MACHINE_R10000: u16 = 0x0168;
const IMAGE_FILE_MACHINE_WCEMIPSV2: u16 = 0x0169;
const IMAGE_FILE_MACHINE_ARM: u16 = 0x01c0;
const IMAGE_FILE_MACHINE_THUMB: u16 = 0x01c2;
/// Windows on 32-bit Arm, which runs Thumb-2 only.
const IMAGE_FILE_MACHINE_ARMNT: u16 = 0x01c4;
const IMAGE_FILE_MACHINE_POWERPC: u16 = 0x01f0;
const IMAGE_FILE_MACHINE_POWERPCFP: u16 = 0x01f1;
const IMAGE_FILE_MACHINE_MIPSFPU: u16 = 0x0366;
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
const IMAGE_FILE_MACHINE_ARM64: u16 = 0xaa64;

const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

/// The [`Binary`] of a PE file; its layout alone when binform does not
/// decode its instruction set.
pub(super) fn binary<'a>(bytes: &'a [u8], pe: &Pe<'_>) -> Binary<'a> {
    let (tables, slots) = tables(pe);
    let entry = if pe.entry == 0 {
        0
    } else {
        pe.image_base.wrapping_add(u64::from(pe.entry))
    };
    let layout = bare(Format::Pe, entry, tables, slots);
    match arch(pe.machine) {
        Some(arch) => image(bytes, pe, arch, layout),
        None => layout,
    }
}

fn arch(machine: u16) -> Option<Arch> {
    Some(match machine {
        IMAGE_FILE_MACHINE_I386 => Arch::X86,
        IMAGE_FILE_MACHINE_AMD64 => Arch::X86_64,
        IMAGE_FILE_MACHINE_ARM64 => Arch::Arm64,
        // Windows CE on Arm, with Thumb or without; ARMNT.
        IMAGE_FILE_MACHINE_ARM | IMAGE_FILE_MACHINE_THUMB | IMAGE_FILE_MACHINE_ARMNT => Arch::Arm,
        // MIPS R3000, R4000, R10000, WCE MIPS v2 and MIPS with FPU, all
        // little-endian. (MIPS16 is a different encoding.)
        IMAGE_FILE_MACHINE_R3000
        | IMAGE_FILE_MACHINE_R4000
        | IMAGE_FILE_MACHINE_R10000
        | IMAGE_FILE_MACHINE_WCEMIPSV2
        | IMAGE_FILE_MACHINE_MIPSFPU => Arch::MipsEl,
        // Windows NT on PowerPC, little-endian, with FPU or without.
        IMAGE_FILE_MACHINE_POWERPC | IMAGE_FILE_MACHINE_POWERPCFP => Arch::PowerPcEl,
        _ => return None,
    })
}

/// A PE file's sections, imports and exports, and its import slots.
fn tables(pe: &Pe<'_>) -> (Tables, Vec<Slot>) {
    let at = |rva: u32| pe.image_base.wrapping_add(u64::from(rva));
    let pe_imports = pe.imports();
    let slots = pe_imports
        .iter()
        .map(|import| Slot {
            slot: at(import.slot),
            name: import.name.clone(),
            import: None,
        })
        .collect();
    // Every address-table entry, duplicates included: the table as the
    // linker wrote it, which the imphash is computed over.
    let imports = pe_imports
        .into_iter()
        .map(|import| Import {
            slot: Some(at(import.slot)),
            name: import.name,
            library: (!import.library.is_empty()).then_some(import.library),
            ordinal: import.ordinal,
            delayed: import.delayed,
        })
        .collect();
    let sections = pe
        .sections
        .iter()
        .map(|section| Section {
            name: section.name.clone(),
            addr: at(section.virtual_address),
            size: u64::from(section.virtual_size),
            offset: u64::from(section.pointer_to_raw_data),
            file_size: u64::from(section.size_of_raw_data),
            flags: u64::from(section.characteristics),
            readable: section.characteristics & IMAGE_SCN_MEM_READ != 0,
            writable: section.characteristics & IMAGE_SCN_MEM_WRITE != 0,
            executable: section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0,
        })
        .collect();
    let exports = pe
        .exports()
        .into_iter()
        .map(|export| Export {
            name: export.name,
            addr: Some(at(export.rva)),
            forward: export.forward,
        })
        .collect();
    (
        Tables {
            sections,
            imports,
            exports,
        },
        slots,
    )
}

/// `layout` with the code of a PE file of `arch`, and where its functions
/// start.
fn image<'a>(bytes: &'a [u8], pe: &Pe<'_>, arch: Arch, layout: Binary<'a>) -> Binary<'a> {
    let base = pe.image_base;
    let at = |rva: u32| base.wrapping_add(u64::from(rva));
    let resources = pe.resources();
    let segments: Vec<Segment<'a>> = pe
        .sections
        .iter()
        .map(|section| {
            // The loader reads from below the raw pointer, when it is
            // unaligned: the raw data runs on from there.
            let start = section.raw_start(pe.file_alignment);
            let raw = u64::from(section.pointer_to_raw_data)
                .saturating_sub(start)
                .saturating_add(u64::from(section.size_of_raw_data));
            let size = match u64::from(section.virtual_size) {
                0 => raw,
                virtual_size => raw.min(virtual_size),
            };
            Segment {
                addr: at(section.virtual_address),
                bytes: Cow::Borrowed(file_range(bytes, start, size)),
                executable: section.characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE)
                    != 0
                    && !resources.is_some_and(|rva| {
                        rva.wrapping_sub(section.virtual_address) < section.virtual_size.max(1)
                    }),
            }
        })
        .collect();

    let go = go_functions(&segments, bytes.len());
    // ARMNT code addresses carry Thumb's bit 0, as `.pdata` writes them;
    // Windows CE's set it for Thumb code only. Go's `windows/arm` port is
    // the exception: it emits A32 code under the ARMNT machine.
    let armnt = pe.machine == IMAGE_FILE_MACHINE_ARMNT;
    let thumb = armnt && go.is_empty();
    let code = |addr: u64| if thumb { addr | 1 } else { addr };
    let mut seeds = Vec::new();
    if pe.entry != 0 {
        seeds.push(seed(code(at(pe.entry)), Origin::Entry));
    }
    for export in &layout.exports {
        if let Some(addr) = export.addr.filter(|&addr| addr != base)
            && export.forward.is_none()
        {
            seeds.push(seed(code(addr), Origin::Export(export.name.clone())));
        }
    }
    seeds.extend(
        pe.tls_callbacks()
            .into_iter()
            .map(|addr| seed(code(addr), Origin::Loader)),
    );
    seeds.extend(go_seeds(go));
    let mut extents = Vec::new();
    match arch {
        Arch::Arm64 => seeds.extend(
            pe.arm64_functions()
                .into_iter()
                .map(|begin| seed(at(begin), Origin::Unwind)),
        ),
        Arch::Arm if armnt => seeds.extend(
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
    Binary {
        arch: Some(arch),
        segments,
        seeds,
        extents,
        ..layout
    }
}

/// The functions of a Go binary's function table, which in a PE file has no
/// section of its own: the first header in data whose first function is
/// code, of at most [`limits::GO_HEADERS`] tried. Entries count from the
/// first code section when the header leaves the text start to the loader.
/// Sections may all map the same bytes: no more than `file_len` bytes are
/// searched.
fn go_functions(segments: &[Segment<'_>], file_len: usize) -> Vec<(u64, String)> {
    let memory = Memory::new(segments);
    let text = segments
        .iter()
        .find(|segment| segment.executable)
        .map(|segment| segment.addr);
    let mut tried = 0_usize;
    let mut scan = file_len;
    for segment in segments.iter().filter(|segment| !segment.executable) {
        let data: &[u8] = segment.bytes.get(..scan).unwrap_or(&segment.bytes);
        scan = scan.saturating_sub(data.len());
        let r = Reader::new(data, false);
        // Each header starts at a pointer-aligned magic number, two zero
        // bytes, the instruction size quantum, and the pointer size.
        let headers = (0..data.len()).step_by(4).filter(|&at| {
            let at = at as u64;
            r.u32(at)
                .is_some_and(|magic| gopclntab::MAGICS.contains(&magic))
                && r.at(at).u32(4).is_some_and(|word| word & 0xffff == 0)
        });
        for at in headers {
            if tried >= limits::GO_HEADERS {
                return Vec::new();
            }
            tried = tried.saturating_add(1);
            let table = data.get(at..).unwrap_or_default();
            let Some(table) = gopclntab::Table::new(table, text, false, false) else {
                continue;
            };
            if table
                .function(0)
                .is_some_and(|(entry, _)| memory.is_code(entry))
            {
                return table.functions();
            }
        }
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Data packed with Go 1.20 headers, none of whose first functions is
    /// code, each claiming two million functions: a bounded number is
    /// tried, and none is read past its first function.
    #[test]
    fn go_headers_in_data_are_tried_within_bounds() {
        let mut header = vec![0xf1, 0xff, 0xff, 0xff, 0, 0, 1, 8];
        for word in [1_u64 << 21, 0, 0x1000, 0, 0, 0, 0, 0x48] {
            header.extend(word.to_le_bytes());
        }
        let data: Vec<u8> = header
            .iter()
            .copied()
            .cycle()
            .take(header.len() << 14)
            .collect();
        let segments = [Segment {
            addr: 0x40_0000,
            bytes: Cow::Borrowed(&data),
            executable: false,
        }];
        let start = std::time::Instant::now();
        assert!(go_functions(&segments, data.len()).is_empty());
        assert!(start.elapsed().as_secs() < 5);
    }
}
