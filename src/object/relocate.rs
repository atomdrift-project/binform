//! Lay out and link a relocatable object (ELF `.o`, `.syso`, `.ko`; Mach-O
//! `MH_OBJECT`) the way a loader would see it.
//!
//! An object's branches and pointers hold placeholders until the linker
//! applies relocations, and an ELF object's sections all claim address
//! zero. Each ELF section is placed at a fixed base plus its file offset
//! (rizin's layout, so addresses agree); a Mach-O object's sections already
//! have addresses. Relocations are applied to copies of the sections, and
//! each undefined symbol gets an import slot past the last section, so a
//! call to it reads as a call through an import.

use std::borrow::Cow;
use std::collections::HashMap;

use super::elf::{self, Elf};
use super::macho;

use crate::{Arch, Import, Segment};

/// Where the sections are placed.
const BASE: u64 = 0x800_0000;

/// An object's sections at their placed addresses, linked.
pub(super) struct Layout<'a> {
    /// Each section's address, by section index; zero for sections not
    /// loaded.
    pub(super) addrs: Vec<u64>,
    pub(super) segments: Vec<Segment<'a>>,
    pub(super) imports: Vec<Import>,
}

pub(super) fn layout<'a>(bytes: &'a [u8], elf: &Elf, arch: Arch) -> Layout<'a> {
    let headers = &elf.sections;
    let alloc = |sh: &elf::Section| sh.flags & elf::SHF_ALLOC != 0;
    let mut addrs = vec![0_u64; headers.len()];
    let mut end = BASE.saturating_add(bytes.len() as u64);
    for (addr, sh) in addrs.iter_mut().zip(headers) {
        if !alloc(sh) {
            continue;
        }
        if sh.kind == elf::SHT_NOBITS {
            // No file bytes to sit over: after everything else.
            let align = sh.addralign.clamp(1, 1 << 12);
            *addr = end.div_ceil(align).saturating_mul(align);
            end = addr.saturating_add(sh.size);
        } else {
            *addr = BASE.saturating_add(sh.offset);
        }
    }
    let mut data: Vec<Option<Vec<u8>>> = headers
        .iter()
        .map(|sh| {
            (alloc(sh) && sh.kind != elf::SHT_NOBITS)
                .then(|| super::file_range(bytes, sh.offset, sh.size).to_vec())
        })
        .collect();

    // Undefined symbols resolve to import slots after the last section.
    let mut slots: HashMap<usize, u64> = HashMap::new();
    let mut imports = Vec::new();
    let first_slot = end.div_ceil(16).saturating_mul(16);
    let mut symbol = |index: usize| -> Option<(u64, bool)> {
        let symbol = elf.symbols.get(index)?;
        match symbol.shndx {
            elf::SHN_UNDEF => {
                let name = &symbol.name;
                if name.is_empty() {
                    return None;
                }
                let next = first_slot.saturating_add(8 * slots.len() as u64);
                let slot = *slots.entry(index).or_insert_with(|| {
                    imports.push(Import {
                        slot: next,
                        name: name.clone(),
                    });
                    next
                });
                Some((slot, true))
            }
            elf::SHN_ABS => Some((symbol.value, false)),
            section => {
                let base = *addrs.get(usize::from(section)).filter(|&&addr| addr != 0)?;
                Some((base.wrapping_add(symbol.value), false))
            }
        }
    };

    for &(target, ref relocs) in &elf.relocations {
        let Some(place_base) = addrs.get(target).copied() else {
            continue;
        };
        let Some(Some(section)) = data.get_mut(target) else {
            continue;
        };
        for reloc in relocs.iter() {
            let Some((value, undefined)) = (match reloc.symbol {
                0 => Some((0, false)),
                index => symbol(index),
            }) else {
                continue;
            };
            let Ok(offset) = usize::try_from(reloc.offset) else {
                continue;
            };
            let place = place_base.wrapping_add(reloc.offset);
            let addend = reloc.addend;
            let fix = Fix {
                value,
                addend,
                place,
                undefined,
            };
            match arch {
                Arch::X86_64 => x86_64(section, offset, reloc.kind, fix),
                Arch::X86 => i386(section, offset, reloc.kind, fix),
                Arch::Arm64 => aarch64(section, offset, reloc.kind, fix),
                // Objects for the other sets are laid out but not linked:
                // their calls read as calls to themselves.
                _ => None,
            };
        }
    }

    let segments = headers
        .iter()
        .zip(&addrs)
        .zip(data.iter_mut())
        .filter_map(|((sh, &addr), data)| {
            Some(Segment {
                addr,
                bytes: Cow::Owned(data.take()?),
                executable: sh.flags & elf::SHF_EXECINSTR != 0,
            })
        })
        .collect();
    Layout {
        addrs,
        segments,
        imports,
    }
}

/// A Mach-O object's sections with their branch relocations applied, by
/// section index (`None` for a section without relocations), and the import
/// slots given to undefined symbols. Only branches are linked: they decide
/// where functions are, and an unlinked one reads as a call to itself.
pub(super) fn macho(
    bytes: &[u8],
    sections: &[macho::Section],
    symbols: &[macho::Symbol],
    arch: Arch,
) -> (Vec<Option<Vec<u8>>>, Vec<Import>) {
    use macho::{N_SECT, N_TYPE, N_UNDF};
    /// `ARM64_RELOC_ADDEND`: the addend of the relocation after it.
    const ADDEND: u32 = 10;
    /// `ARM64_RELOC_BRANCH26`, `X86_64_RELOC_BRANCH`.
    const BRANCH: u32 = 2;
    let end = sections
        .iter()
        .map(|section| section.addr.saturating_add(section.size))
        .max()
        .unwrap_or(0);
    let first_slot = end.div_ceil(16).saturating_mul(16);
    let mut slots: HashMap<usize, u64> = HashMap::new();
    let mut imports = Vec::new();
    let mut linked = Vec::with_capacity(sections.len());
    for section in sections {
        let count = u64::from(section.nreloc).min(1 << 20);
        let table = super::file_range(bytes, u64::from(section.reloff), count * 8);
        if table.is_empty() || !section.code {
            linked.push(None);
            continue;
        }
        let mut data = super::file_range(bytes, section.offset, section.size).to_vec();
        let mut addend = 0_i64;
        for entry in table.chunks_exact(8) {
            let word = |i: usize| {
                entry
                    .get(i..i + 4)
                    .and_then(|b| b.try_into().ok())
                    .map_or(0, u32::from_le_bytes)
            };
            let (address, info) = (word(0), word(4));
            let symbol = info & 0x00ff_ffff;
            let external = info & 0x0800_0000 != 0;
            let kind = info >> 28;
            // Scattered relocations (the high bit) are 32-bit only.
            if address & 0x8000_0000 != 0 {
                continue;
            }
            if arch == Arch::Arm64 && kind == ADDEND {
                addend = i64::from(((symbol << 8).cast_signed()) >> 8);
                continue;
            }
            let addend = std::mem::take(&mut addend);
            if !external || kind != BRANCH {
                continue;
            }
            let index = symbol as usize;
            let Some(nlist) = symbols.get(index) else {
                continue;
            };
            let (value, undefined) = match nlist.n_type & N_TYPE {
                N_SECT => (nlist.n_value, false),
                N_UNDF if !nlist.name.is_empty() => {
                    let next = first_slot.saturating_add(8 * slots.len() as u64);
                    let slot = *slots.entry(index).or_insert_with(|| {
                        imports.push(Import {
                            slot: next,
                            name: nlist.name.clone(),
                        });
                        next
                    });
                    (slot, true)
                }
                _ => continue,
            };
            let offset = address as usize;
            let place = section.addr.wrapping_add(u64::from(address));
            match arch {
                Arch::Arm64 => aarch64(
                    &mut data,
                    offset,
                    283,
                    Fix {
                        value,
                        addend: Some(addend),
                        place,
                        undefined,
                    },
                ),
                // The in-place addend counts from the end of the field.
                Arch::X86_64 => x86_64(
                    &mut data,
                    offset,
                    2,
                    Fix {
                        value,
                        addend: None,
                        place: place.wrapping_add(4),
                        undefined,
                    },
                ),
                _ => None,
            };
        }
        linked.push(Some(data));
    }
    (linked, imports)
}

/// One relocation's inputs: the symbol's value `S`, the addend `A` (`None`
/// for a REL relocation, whose addend is in place), and the place `P`.
#[derive(Clone, Copy)]
struct Fix {
    value: u64,
    addend: Option<i64>,
    place: u64,
    /// The symbol is an import: `value` is its slot.
    undefined: bool,
}

impl Fix {
    /// `S + A`, with a REL addend read from `bytes` at `offset`.
    fn target(self, bytes: &[u8], offset: usize) -> Option<u64> {
        let addend = match self.addend {
            Some(addend) => addend,
            None => i64::from(i32::from_le_bytes(
                bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?,
            )),
        };
        Some(self.value.wrapping_add_signed(addend))
    }

    /// `S + A - P`.
    fn relative(self, bytes: &[u8], offset: usize) -> Option<u64> {
        Some(self.target(bytes, offset)?.wrapping_sub(self.place))
    }
}

fn put(bytes: &mut [u8], offset: usize, value: &[u8]) -> Option<()> {
    bytes
        .get_mut(offset..offset.checked_add(value.len())?)?
        .copy_from_slice(value);
    Some(())
}

/// Truncate to 32 bits, as the linker's field is.
fn low32(value: u64) -> [u8; 4] {
    let [a, b, c, d, ..] = value.to_le_bytes();
    [a, b, c, d]
}

fn x86_64(bytes: &mut [u8], offset: usize, kind: u32, fix: Fix) -> Option<()> {
    let value = match kind {
        1 => return put(bytes, offset, &fix.target(bytes, offset)?.to_le_bytes()),
        24 => return put(bytes, offset, &fix.relative(bytes, offset)?.to_le_bytes()),
        // PC32, PLT32; the GOT forms only for imports, whose slot stands in
        // for the GOT entry.
        2 | 4 => fix.relative(bytes, offset)?,
        9 | 41 | 42 if fix.undefined => fix.relative(bytes, offset)?,
        10 | 11 => fix.target(bytes, offset)?,
        _ => return None,
    };
    put(bytes, offset, &low32(value))
}

fn i386(bytes: &mut [u8], offset: usize, kind: u32, fix: Fix) -> Option<()> {
    let value = match kind {
        1 => fix.target(bytes, offset)?,
        2 | 4 => fix.relative(bytes, offset)?,
        _ => return None,
    };
    put(bytes, offset, &low32(value))
}

fn aarch64(bytes: &mut [u8], offset: usize, kind: u32, fix: Fix) -> Option<()> {
    let word = |bytes: &[u8]| {
        Some(u32::from_le_bytes(
            bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?,
        ))
    };
    let patch = |bytes: &mut [u8], mask: u32, field: u32| -> Option<()> {
        let insn = word(bytes)? & !mask | field & mask;
        put(bytes, offset, &insn.to_le_bytes())
    };
    let s_a = fix.target(bytes, offset)?;
    let low12 = (s_a & 0xfff) as u32;
    match kind {
        257 => put(bytes, offset, &s_a.to_le_bytes()),
        258 => put(bytes, offset, &low32(s_a)),
        260 => put(bytes, offset, &s_a.wrapping_sub(fix.place).to_le_bytes()),
        261 => put(bytes, offset, &low32(s_a.wrapping_sub(fix.place))),
        // JUMP26, CALL26: a word offset in 26 bits.
        282 | 283 => {
            let delta = s_a.wrapping_sub(fix.place).cast_signed() >> 2;
            if !(-(1 << 25)..1 << 25).contains(&delta) {
                return None;
            }
            patch(bytes, 0x03ff_ffff, u32::try_from(delta & 0x03ff_ffff).ok()?)
        }
        // ADR_PREL_PG_HI21; ADR_GOT_PAGE for imports.
        275 | 311 if kind == 275 || fix.undefined => {
            let pages = ((s_a & !0xfff).wrapping_sub(fix.place & !0xfff)).cast_signed() >> 12;
            // The low 21 bits, as the field holds them.
            let pages = u32::try_from(pages & 0x1f_ffff).ok()?;
            patch(
                bytes,
                0x60ff_ffe0,
                (pages & 3) << 29 | (pages >> 2 & 0x7_ffff) << 5,
            )
        }
        // ADD_ABS_LO12_NC, LDST8_ABS_LO12_NC
        277 | 278 => patch(bytes, 0xfff << 10, low12 << 10),
        284 => patch(bytes, 0xfff << 10, (low12 >> 1) << 10),
        285 => patch(bytes, 0xfff << 10, (low12 >> 2) << 10),
        286 => patch(bytes, 0xfff << 10, (low12 >> 3) << 10),
        312 if fix.undefined => patch(bytes, 0xfff << 10, (low12 >> 3) << 10),
        299 => patch(bytes, 0xfff << 10, (low12 >> 4) << 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Where the `call rel32` at 0x8000100 in `code` goes.
    fn target(code: &[u8]) -> Option<i64> {
        let rel = i32::from_le_bytes(code.get(1..5)?.try_into().ok()?);
        Some(0x800_0105 + i64::from(rel))
    }

    #[test]
    fn x86_64_call_to_an_import() {
        // call rel32 at 0x8000100 to a slot at 0x8002000, addend -4.
        let mut code = vec![0xe8, 0, 0, 0, 0];
        let fix = Fix {
            value: 0x800_2000,
            addend: Some(-4),
            place: 0x800_0101,
            undefined: true,
        };
        x86_64(&mut code, 1, 4, fix);
        assert_eq!(target(&code), Some(0x800_2000));
    }

    #[test]
    fn i386_reads_its_addend_in_place() {
        // call rel32 with the addend -4 already in the field.
        let mut code = vec![0xe8, 0xfc, 0xff, 0xff, 0xff];
        let fix = Fix {
            value: 0x800_0400,
            addend: None,
            place: 0x800_0101,
            undefined: false,
        };
        i386(&mut code, 1, 2, fix);
        assert_eq!(target(&code), Some(0x800_0400));
    }

    #[test]
    fn aarch64_call_and_page_address() {
        // bl 0; adrp x0, 0; add x0, x0, 0
        let mut code: Vec<u8> = [0x9400_0000_u32, 0x9000_0000, 0x9100_0000]
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect();
        let at = |place: u64, value: u64| Fix {
            value,
            addend: Some(0),
            place,
            undefined: false,
        };
        aarch64(&mut code, 0, 283, at(0x800_1000, 0x800_1040));
        aarch64(&mut code, 4, 275, at(0x800_1004, 0x800_5678));
        aarch64(&mut code, 8, 277, at(0x800_1008, 0x800_5678));
        let words: Vec<u32> = code
            .chunks_exact(4)
            .filter_map(|w| w.try_into().ok().map(u32::from_le_bytes))
            .collect();
        // bl +0x40; adrp x0, +4 pages; add x0, x0, #0x678
        assert_eq!(words, [0x9400_0010, 0x9000_0020, 0x9100_0000 | 0x678 << 10]);
    }
}
