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

use crate::{Arch, Segment, Slot};

/// Where the sections are placed.
const BASE: u64 = 0x800_0000;

/// An object's sections at their placed addresses, linked.
pub(super) struct Layout<'a> {
    /// Each section's address, by section index; zero for sections not
    /// loaded.
    pub(super) addrs: Vec<u64>,
    pub(super) segments: Vec<Segment<'a>>,
    pub(super) imports: Vec<Slot>,
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
                    imports.push(Slot {
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

    // RISC-V's PC-relative low parts name the `auipc` their high part
    // fixed: its place, and the `S + A - P` it used.
    let mut high = HashMap::new();
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
                Arch::Arm => arm(section, offset, reloc.kind, fix),
                arch if arch.mips() => mips(section, offset, reloc.kind, fix, arch.big_endian()),
                Arch::S390x => s390x(section, offset, reloc.kind, fix),
                Arch::Sparc | Arch::Sparc64 => sparc(section, offset, reloc.kind, fix),
                Arch::RiscV32 | Arch::RiscV64 => riscv(section, offset, reloc.kind, fix, &mut high),
                Arch::LoongArch64 => loongarch(section, offset, reloc.kind, fix),
                // SuperH objects are laid out but not linked: their calls
                // read as calls to themselves.
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
) -> (Vec<Option<Vec<u8>>>, Vec<Slot>) {
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
                        imports.push(Slot {
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

/// The `N`-byte field at `offset`.
fn field<const N: usize>(bytes: &[u8], offset: usize) -> Option<[u8; N]> {
    bytes.get(offset..offset.checked_add(N)?)?.try_into().ok()
}

/// The 32-bit word at `offset`, big-endian when `big`.
fn word_at(bytes: &[u8], offset: usize, big: bool) -> Option<u32> {
    let raw = field::<4>(bytes, offset)?;
    Some(if big {
        u32::from_be_bytes(raw)
    } else {
        u32::from_le_bytes(raw)
    })
}

fn put_word(bytes: &mut [u8], offset: usize, word: u32, big: bool) -> Option<()> {
    let raw = if big {
        word.to_be_bytes()
    } else {
        word.to_le_bytes()
    };
    put(bytes, offset, &raw)
}

/// `value`'s low `bits` bits, if it fits in them as a signed number.
fn fits(value: i64, bits: u32) -> Option<u32> {
    let half = 1_i64 << (bits - 1);
    if !(-half..half).contains(&value) {
        return None;
    }
    u32::try_from(value & ((half << 1) - 1)).ok()
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

/// 32-bit Arm, whose relocations are REL: each addend is in the field it
/// fixes. A call between A32 and Thumb becomes a `blx`; an import's slot
/// counts as A32 code.
fn arm(bytes: &mut [u8], offset: usize, kind: u32, fix: Fix) -> Option<()> {
    let insn = word_at(bytes, offset, false)?;
    let thumb = |value: u64| value & 1 != 0;
    match kind {
        // ABS32, REL32
        2 => put(bytes, offset, &low32(fix.target(bytes, offset)?)),
        3 => put(bytes, offset, &low32(fix.relative(bytes, offset)?)),
        // PC24, CALL, JUMP24: a word offset in 24 bits; a call to Thumb is
        // a `blx`, whose H bit holds the offset's halfword.
        1 | 28 | 29 => {
            let addend = fix
                .addend
                .unwrap_or(i64::from(((insn & 0x00ff_ffff) << 8).cast_signed() >> 6));
            let s_a = fix.value.wrapping_add_signed(addend);
            let delta = (s_a & !1).wrapping_sub(fix.place).cast_signed();
            let imm = fits(delta >> 2, 24)?;
            let insn = if kind == 28 && thumb(s_a) {
                0xfa00_0000 | u32::from(delta & 2 != 0) << 24 | imm
            } else if thumb(s_a) {
                return None;
            } else {
                insn & 0xff00_0000 | imm
            };
            put_word(bytes, offset, insn, false)
        }
        // THM_CALL, THM_JUMP24: a halfword offset split over two
        // halfwords; a call to A32 is a `blx`, from the word-aligned PC.
        10 | 30 => {
            let (first, second) = (insn & 0xffff, insn >> 16);
            let addend = fix.addend.unwrap_or_else(|| thumb_offset(first, second));
            let s_a = fix.value.wrapping_add_signed(addend);
            let to_a32 = !thumb(s_a);
            if to_a32 && kind == 30 {
                return None;
            }
            let from = if to_a32 { fix.place & !3 } else { fix.place };
            let delta = (s_a & !1).wrapping_sub(from).cast_signed();
            let imm = fits(delta, 25)?;
            let s = imm >> 24 & 1;
            let (i1, i2) = (imm >> 23 & 1, imm >> 22 & 1);
            let (j1, j2) = (!(i1 ^ s) & 1, !(i2 ^ s) & 1);
            let first = 0xf000 | s << 10 | (imm >> 12 & 0x3ff);
            // Bit 12 set: `bl`, or `b.w` for the jump; clear: `blx`.
            let link = u32::from(!to_a32) << 12;
            let second = second & 0xc000 | link | j1 << 13 | j2 << 11 | (imm >> 1 & 0x7ff);
            put_word(bytes, offset, second << 16 | first, false)
        }
        _ => None,
    }
}

/// The offset a Thumb `bl`'s halfwords hold: S:I1:I2:imm10:imm11:0, with
/// I = not (J xor S).
fn thumb_offset(first: u32, second: u32) -> i64 {
    let s = (first >> 10) & 1;
    let i1 = !((second >> 13) & 1 ^ s) & 1;
    let i2 = !((second >> 11) & 1 ^ s) & 1;
    let raw = s << 24 | i1 << 23 | i2 << 22 | (first & 0x3ff) << 12 | (second & 0x7ff) << 1;
    i64::from((raw << 7).cast_signed() >> 7)
}

/// MIPS: `R_MIPS_26` fills a `jal` or `j`; position-independent code calls
/// through `$t9` (`jalr $t9`, or `jr $t9` for a tail call), which
/// `R_MIPS_JALR` names the callee of, so the jump becomes a direct one as a
/// linker relaxes it. Both reach only the 256 MB region the delay slot is
/// in.
fn mips(bytes: &mut [u8], offset: usize, kind: u32, fix: Fix, big: bool) -> Option<()> {
    const JALR_T9: u32 = 0x0320_f809;
    const JR_T9: u32 = 0x0320_0008;
    let insn = word_at(bytes, offset, big)?;
    let region = |target: u64| {
        if (target ^ fix.place.wrapping_add(4)) & !0x0fff_ffff != 0 {
            return None;
        }
        u32::try_from(target >> 2 & 0x03ff_ffff).ok()
    };
    match kind {
        // R_MIPS_32, R_MIPS_64
        2 => {
            let addend = fix.addend.unwrap_or(i64::from(insn.cast_signed()));
            let target = fix.value.wrapping_add_signed(addend);
            put_word(
                bytes,
                offset,
                u32::try_from(target & 0xffff_ffff).ok()?,
                big,
            )
        }
        18 => {
            let raw = field::<8>(bytes, offset)?;
            let in_place = if big {
                i64::from_be_bytes(raw)
            } else {
                i64::from_le_bytes(raw)
            };
            let target = fix
                .value
                .wrapping_add_signed(fix.addend.unwrap_or(in_place));
            let raw = if big {
                target.to_be_bytes()
            } else {
                target.to_le_bytes()
            };
            put(bytes, offset, &raw)
        }
        // R_MIPS_26: the in-place addend is the 26-bit field, in words.
        4 => {
            let addend = fix.addend.unwrap_or(i64::from(insn & 0x03ff_ffff) << 2);
            let target = fix.value.wrapping_add_signed(addend);
            put_word(bytes, offset, insn & 0xfc00_0000 | region(target)?, big)
        }
        // R_MIPS_JALR
        37 if insn == JALR_T9 || insn == JR_T9 => {
            let target = fix.value.wrapping_add_signed(fix.addend.unwrap_or(0));
            let opcode = if insn == JALR_T9 {
                0x0c00_0000
            } else {
                0x0800_0000
            };
            put_word(bytes, offset, opcode | region(target)?, big)
        }
        _ => None,
    }
}

/// s390x: RELA, big-endian; relative fields count halfwords.
fn s390x(bytes: &mut [u8], offset: usize, kind: u32, fix: Fix) -> Option<()> {
    let target = fix.value.wrapping_add_signed(fix.addend?);
    let relative = target.wrapping_sub(fix.place).cast_signed();
    match kind {
        // R_390_32, R_390_PC32, R_390_64
        4 => put(
            bytes,
            offset,
            &u32::try_from(target & 0xffff_ffff).ok()?.to_be_bytes(),
        ),
        5 => put(bytes, offset, &fits(relative, 32)?.to_be_bytes()),
        22 => put(bytes, offset, &target.to_be_bytes()),
        // PC16DBL, PLT16DBL, PC32DBL, PLT32DBL
        16 | 17 => {
            let half = u16::try_from(fits(relative >> 1, 16)?).ok()?;
            put(bytes, offset, &half.to_be_bytes())
        }
        19 | 20 => put(bytes, offset, &fits(relative >> 1, 32)?.to_be_bytes()),
        _ => None,
    }
}

/// SPARC: RELA, big-endian; `call` holds a 30-bit word displacement.
fn sparc(bytes: &mut [u8], offset: usize, kind: u32, fix: Fix) -> Option<()> {
    let target = fix.value.wrapping_add_signed(fix.addend?);
    let relative = target.wrapping_sub(fix.place).cast_signed();
    let insn = word_at(bytes, offset, true)?;
    match kind {
        // R_SPARC_32, UA32, R_SPARC_64, UA64, DISP32
        3 | 23 => put(
            bytes,
            offset,
            &u32::try_from(target & 0xffff_ffff).ok()?.to_be_bytes(),
        ),
        32 | 54 => put(bytes, offset, &target.to_be_bytes()),
        6 => put(bytes, offset, &fits(relative, 32)?.to_be_bytes()),
        // WDISP30, WPLT30: `call`, whose displacement wraps; WDISP22:
        // `b<cc>`.
        7 | 18 => {
            let disp = u32::try_from((relative >> 2) & 0x3fff_ffff).ok()?;
            put_word(bytes, offset, insn & 0xc000_0000 | disp, true)
        }
        8 => put_word(
            bytes,
            offset,
            insn & !0x3f_ffff | fits(relative >> 2, 22)?,
            true,
        ),
        _ => None,
    }
}

/// The `(value + 0x800) >> 12` an `auipc`/`lui` holds, and the low 12
/// bits its partner adds.
fn split(value: i64) -> Option<(u32, u32)> {
    let high = fits(value.wrapping_add(0x800) >> 12, 20)?;
    let low = u32::try_from(value & 0xfff).ok()?;
    Some((high, low))
}

/// RISC-V: RELA, little-endian. Calls are `auipc; jalr` pairs (`CALL`),
/// and branches within a section are relocated too, as the linker may
/// relax what lies between.
fn riscv(
    bytes: &mut [u8],
    offset: usize,
    kind: u32,
    fix: Fix,
    high: &mut HashMap<u64, i64>,
) -> Option<()> {
    let target = fix.value.wrapping_add_signed(fix.addend?);
    let relative = target.wrapping_sub(fix.place).cast_signed();
    let insn = word_at(bytes, offset, false).unwrap_or(0);
    let half = u16::from_le_bytes(field::<2>(bytes, offset)?);
    let u_type = |insn: u32, value: u32| insn & 0xfff | value << 12;
    let i_type = |insn: u32, value: u32| insn & 0x000f_ffff | value << 20;
    let s_type =
        |insn: u32, value: u32| insn & 0x01ff_f07f | (value >> 5) << 25 | (value & 0x1f) << 7;
    match kind {
        // R_RISCV_32, R_RISCV_64, R_RISCV_32_PCREL
        1 => put(bytes, offset, &low32(target)),
        2 => put(bytes, offset, &target.to_le_bytes()),
        57 => put(bytes, offset, &fits(relative, 32)?.to_le_bytes()),
        // ADD32, SUB32, ADD64, SUB64: `.eh_frame`'s and the debug
        // sections' differences.
        35 | 39 => add_sub(bytes, offset, target, false, kind == 39),
        36 | 40 => add_sub(bytes, offset, target, true, kind == 40),
        // BRANCH: B-type, 13 bits.
        16 => {
            let imm = fits(relative, 13)?;
            let field = (imm >> 12 & 1) << 31
                | (imm >> 5 & 0x3f) << 25
                | (imm >> 1 & 0xf) << 8
                | (imm >> 11 & 1) << 7;
            put_word(bytes, offset, insn & 0x01ff_f07f | field, false)
        }
        // JAL: J-type, 21 bits.
        17 => {
            let imm = fits(relative, 21)?;
            let field = (imm >> 20 & 1) << 31
                | (imm >> 1 & 0x3ff) << 21
                | (imm >> 11 & 1) << 20
                | (imm >> 12 & 0xff) << 12;
            put_word(bytes, offset, insn & 0xfff | field, false)
        }
        // CALL, CALL_PLT: `auipc` and the `jalr` after it.
        18 | 19 => {
            let (hi, lo) = split(relative)?;
            let next = offset.checked_add(4)?;
            let jalr = word_at(bytes, next, false)?;
            put_word(bytes, offset, u_type(insn, hi), false)?;
            put_word(bytes, next, i_type(jalr, lo), false)
        }
        // PCREL_HI20; GOT_HI20 for imports, whose slot stands in for the
        // GOT entry.
        20 | 23 if kind == 23 || fix.undefined => {
            high.insert(fix.place, relative);
            put_word(bytes, offset, u_type(insn, split(relative)?.0), false)
        }
        // PCREL_LO12_I, PCREL_LO12_S: the symbol is the `auipc`.
        24 | 25 => {
            let (_, lo) = split(*high.get(&target)?)?;
            let insn = if kind == 24 {
                i_type(insn, lo)
            } else {
                s_type(insn, lo)
            };
            put_word(bytes, offset, insn, false)
        }
        // HI20, LO12_I, LO12_S: absolute `lui; addi`.
        26 => put_word(
            bytes,
            offset,
            u_type(insn, split(target.cast_signed())?.0),
            false,
        ),
        27 => put_word(
            bytes,
            offset,
            i_type(insn, split(target.cast_signed())?.1),
            false,
        ),
        28 => put_word(
            bytes,
            offset,
            s_type(insn, split(target.cast_signed())?.1),
            false,
        ),
        // RVC_BRANCH: CB, 9 bits.
        44 => {
            let imm = fits(relative, 9)?;
            let field = (imm >> 8 & 1) << 12
                | (imm >> 3 & 3) << 10
                | (imm >> 6 & 3) << 5
                | (imm >> 1 & 3) << 3
                | (imm >> 5 & 1) << 2;
            let field = u16::try_from(field).ok()?;
            put(bytes, offset, &(half & 0xe383 | field).to_le_bytes())
        }
        // RVC_JUMP: CJ, 12 bits.
        45 => {
            let imm = fits(relative, 12)?;
            let field = (imm >> 11 & 1) << 12
                | (imm >> 4 & 1) << 11
                | (imm >> 8 & 3) << 9
                | (imm >> 10 & 1) << 8
                | (imm >> 6 & 1) << 7
                | (imm >> 7 & 1) << 6
                | (imm >> 1 & 7) << 3
                | (imm >> 5 & 1) << 2;
            let field = u16::try_from(field).ok()?;
            put(bytes, offset, &(half & 0xe003 | field).to_le_bytes())
        }
        _ => None,
    }
}

/// `bytes`' 32-bit (`wide`: 64-bit) field at `offset`, plus or minus
/// `value`: the `ADD`/`SUB` pairs that write a difference of two labels.
fn add_sub(bytes: &mut [u8], offset: usize, value: u64, wide: bool, sub: bool) -> Option<()> {
    if wide {
        let old = u64::from_le_bytes(field::<8>(bytes, offset)?);
        let new = if sub {
            old.wrapping_sub(value)
        } else {
            old.wrapping_add(value)
        };
        put(bytes, offset, &new.to_le_bytes())
    } else {
        let old = u32::from_le_bytes(field::<4>(bytes, offset)?);
        let value = u32::from_le_bytes(low32(value));
        let new = if sub {
            old.wrapping_sub(value)
        } else {
            old.wrapping_add(value)
        };
        put(bytes, offset, &new.to_le_bytes())
    }
}

/// LoongArch: RELA, little-endian. Calls are `bl` (`B26`) or, in the
/// medium code model, `pcaddu18i; jirl` pairs (`CALL36`); addresses are
/// `pcalau12i; addi.d` (`PCALA_HI20`, `PCALA_LO12`), whose low part is the
/// target's own low 12 bits. Branches within a section are relocated too,
/// as the linker may relax what lies between.
fn loongarch(bytes: &mut [u8], offset: usize, kind: u32, fix: Fix) -> Option<()> {
    let target = fix.value.wrapping_add_signed(fix.addend?);
    let relative = target.wrapping_sub(fix.place).cast_signed();
    let insn = word_at(bytes, offset, false).unwrap_or(0);
    // The 20-bit field at bits 5-24, and the 12- and 16-bit ones from bit
    // 10.
    let si20 = |insn: u32, value: u32| insn & !(0xf_ffff << 5) | (value & 0xf_ffff) << 5;
    let i12 = |insn: u32, value: u32| insn & !(0xfff << 10) | (value & 0xfff) << 10;
    let i16 = |insn: u32, value: u32| insn & !(0xffff << 10) | (value & 0xffff) << 10;
    let page = |value: u64| value.wrapping_add(0x800) & !0xfff;
    let low12 = u32::try_from(target & 0xfff).ok()?;
    match kind {
        // R_LARCH_32, R_LARCH_64, R_LARCH_32_PCREL, R_LARCH_64_PCREL
        1 => put(bytes, offset, &low32(target)),
        2 => put(bytes, offset, &target.to_le_bytes()),
        99 => put(bytes, offset, &fits(relative, 32)?.to_le_bytes()),
        109 => put(bytes, offset, &relative.to_le_bytes()),
        // ADD32, ADD64, SUB32, SUB64
        50 | 55 => add_sub(bytes, offset, target, false, kind == 55),
        51 | 56 => add_sub(bytes, offset, target, true, kind == 56),
        // B16: `beq` and kin; B21: `beqz`, `bnez`; B26: `b`, `bl`.
        64 => put_word(bytes, offset, i16(insn, fits(relative >> 2, 16)?), false),
        65 => {
            let offs = fits(relative >> 2, 21)?;
            put_word(bytes, offset, i16(insn, offs) & !0x1f | offs >> 16, false)
        }
        66 => {
            let offs = fits(relative >> 2, 26)?;
            put_word(bytes, offset, i16(insn, offs) & !0x3ff | offs >> 16, false)
        }
        // ABS_HI20, ABS_LO12, ABS64_LO20, ABS64_HI12: `lu12i.w; ori;
        // lu32i.d; lu52i.d`.
        67 => put_word(
            bytes,
            offset,
            si20(insn, u32::try_from(target >> 12 & 0xf_ffff).ok()?),
            false,
        ),
        68 => put_word(bytes, offset, i12(insn, low12), false),
        69 => put_word(
            bytes,
            offset,
            si20(insn, u32::try_from(target >> 32 & 0xf_ffff).ok()?),
            false,
        ),
        70 => put_word(
            bytes,
            offset,
            i12(insn, u32::try_from(target >> 52).ok()?),
            false,
        ),
        // PCALA_HI20, PCALA_LO12; GOT_PC_HI20 and GOT_PC_LO12 for imports,
        // whose slot stands in for the GOT entry.
        71 | 75 if kind == 71 || fix.undefined => {
            let pages = page(target).wrapping_sub(fix.place & !0xfff).cast_signed() >> 12;
            put_word(
                bytes,
                offset,
                si20(insn, u32::try_from(pages & 0xf_ffff).ok()?),
                false,
            )
        }
        72 | 76 if kind == 72 || fix.undefined => put_word(bytes, offset, i12(insn, low12), false),
        // PCREL20_S2: `pcaddi`.
        103 => put_word(bytes, offset, si20(insn, fits(relative >> 2, 20)?), false),
        // CALL36: `pcaddu18i` and the `jirl` after it.
        110 => {
            let high = relative.wrapping_add(0x2_0000) >> 18;
            let low = relative.wrapping_sub(high << 18) >> 2;
            let next = offset.checked_add(4)?;
            let jirl = word_at(bytes, next, false)?;
            put_word(bytes, offset, si20(insn, fits(high, 20)?), false)?;
            put_word(bytes, next, i16(jirl, fits(low, 16)?), false)
        }
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

    /// Where the Arm code at `place` in `code` (Thumb when `place` is odd)
    /// calls.
    fn arm_call(code: &[u8], place: u64) -> crate::isa::Flow {
        crate::isa::arm::decode(&mut crate::isa::arm::State::default(), code, place).flow
    }

    #[test]
    fn arm_calls_switch_modes() {
        use crate::isa::Flow;
        let at = |place: u64, value: u64| Fix {
            value,
            addend: None,
            place,
            undefined: false,
        };
        // An A32 `bl` (addend -8 in place) to Thumb code at a halfword:
        // `blx`, with the H bit.
        let mut code = 0xebff_fffe_u32.to_le_bytes();
        arm(&mut code, 0, 28, at(0x800_0100, 0x800_0203));
        assert_eq!(arm_call(&code, 0x800_0100), Flow::Call(0x800_0203));
        // A Thumb `bl` (addend -4 in place) at a halfword-aligned place,
        // to A32 code: `blx`, from the word-aligned PC.
        let mut code = [0xff, 0xf7, 0xfe, 0xff];
        arm(&mut code, 0, 10, at(0x800_0102, 0x800_0400));
        assert_eq!(arm_call(&code, 0x800_0103), Flow::Call(0x800_0400));
        // And to Thumb code, backwards: `bl`.
        let mut code = [0xff, 0xf7, 0xfe, 0xff];
        arm(&mut code, 0, 10, at(0x800_0102, 0x800_0041));
        assert_eq!(arm_call(&code, 0x800_0103), Flow::Call(0x800_0041));
    }

    /// The flow of each RISC-V instruction in `code`, decoded from `addr`.
    fn riscv_flows(code: &[u8], addr: u64) -> Vec<crate::isa::Flow> {
        let config = crate::isa::riscv::Config {
            wide: true,
            gp: None,
        };
        let mut state = crate::isa::riscv::State::default();
        let mut flows = Vec::new();
        let mut at = 0;
        while let Some(rest) = code.get(at..).filter(|rest| !rest.is_empty()) {
            let insn = crate::isa::riscv::decode(&mut state, config, rest, addr + at as u64);
            flows.push(insn.flow);
            at += insn.len as usize;
        }
        flows
    }

    #[test]
    fn riscv_calls_and_branches() {
        use crate::isa::Flow;
        let at = |place: u64, value: u64| Fix {
            value,
            addend: Some(0),
            place,
            undefined: false,
        };
        let mut high = HashMap::new();
        // auipc ra, 0; jalr ra, 0(ra)
        let mut code: Vec<u8> = [0x0000_0097_u32, 0x0000_80e7]
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect();
        riscv(&mut code, 0, 19, at(0x800_1000, 0x801_3a00), &mut high);
        assert_eq!(riscv_flows(&code, 0x800_1000)[1], Flow::Call(0x801_3a00));
        // beq a0, a1, 0, backwards; jal ra, 0, forwards.
        let mut code = 0x00b5_0063_u32.to_le_bytes();
        riscv(&mut code, 0, 16, at(0x800_1000, 0x800_0f00), &mut high);
        assert_eq!(riscv_flows(&code, 0x800_1000), [Flow::Branch(0x800_0f00)]);
        let mut code = 0x0000_00ef_u32.to_le_bytes();
        riscv(&mut code, 0, 17, at(0x800_1000, 0x808_0000), &mut high);
        assert_eq!(riscv_flows(&code, 0x800_1000), [Flow::Call(0x808_0000)]);
        // c.beqz a0, 0; c.j 0.
        let mut code = 0xc101_u16.to_le_bytes();
        riscv(&mut code, 0, 44, at(0x800_1000, 0x800_0f42), &mut high);
        assert_eq!(riscv_flows(&code, 0x800_1000), [Flow::Branch(0x800_0f42)]);
        let mut code = 0xa001_u16.to_le_bytes();
        riscv(&mut code, 0, 45, at(0x800_1000, 0x800_17fe), &mut high);
        assert_eq!(riscv_flows(&code, 0x800_1000), [Flow::Jump(0x800_17fe)]);
    }

    #[test]
    fn loongarch_calls_and_addresses() {
        use crate::isa::{Flow, Note};
        let at = |place: u64, value: u64| Fix {
            value,
            addend: Some(0),
            place,
            undefined: false,
        };
        let decode = |words: &[u32], addr: u64| {
            let mut state = crate::isa::loongarch::State::default();
            words
                .iter()
                .enumerate()
                .map(|(i, w)| {
                    crate::isa::loongarch::decode(&mut state, &w.to_le_bytes(), addr + 4 * i as u64)
                })
                .collect::<Vec<_>>()
        };
        let words = |code: &[u8]| -> Vec<u32> {
            code.chunks_exact(4)
                .filter_map(|w| w.try_into().ok().map(u32::from_le_bytes))
                .collect()
        };
        // pcaddu18i ra, 0; jirl ra, ra, 0: a call 0x12345678 on, and back.
        for to in [0x1a34_6678_u64, 0x800_0000] {
            let mut code: Vec<u8> = [0x1e00_0001_u32, 0x4c00_0021]
                .iter()
                .flat_map(|w| w.to_le_bytes())
                .collect();
            loongarch(&mut code, 0, 110, at(0x833_3000, to));
            assert_eq!(decode(&words(&code), 0x833_3000)[1].flow, Flow::Call(to));
        }
        // bl 0, forwards; b 0, backwards; bnez a0, 0; bltu a2, a0, 0.
        for (word, kind, to, flow) in [
            (0x5400_0000_u32, 66, 0x900_0000, Flow::Call(0x900_0000)),
            (0x5000_0000, 66, 0x7f0_0000, Flow::Jump(0x7f0_0000)),
            (0x4400_0080, 65, 0x7f8_0004, Flow::Branch(0x7f8_0004)),
            (0x6800_00c4, 64, 0x800_1ffc, Flow::Branch(0x800_1ffc)),
        ] {
            let mut code = word.to_le_bytes().to_vec();
            loongarch(&mut code, 0, kind, at(0x800_0000, to));
            assert_eq!(decode(&words(&code), 0x800_0000)[0].flow, flow);
        }
        // pcalau12i a2, 0; addi.d a2, a2, 0: an address on another page.
        let mut code: Vec<u8> = [0x1a00_0006_u32, 0x02c0_00c6]
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect();
        loongarch(&mut code, 0, 71, at(0x800_1000, 0x804_5ab8));
        loongarch(&mut code, 4, 72, at(0x800_1004, 0x804_5ab8));
        assert_eq!(
            decode(&words(&code), 0x800_1000)[1].note,
            Note::Address {
                reg: 6,
                addr: 0x804_5ab8
            }
        );
    }

    #[test]
    fn mips_calls_through_t9_become_direct() {
        let at = |value: u64| Fix {
            value,
            addend: None,
            place: 0x800_0010,
            undefined: false,
        };
        // jalr $t9, jr $t9 (little-endian): jal, j.
        let mut code: Vec<u8> = [0x0320_f809_u32, 0x0320_0008]
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect();
        mips(&mut code, 0, 37, at(0x800_0100), false);
        mips(&mut code, 4, 37, at(0x800_0200), false);
        assert_eq!(word_at(&code, 0, false), Some(0x0e00_0040));
        assert_eq!(word_at(&code, 4, false), Some(0x0a00_0080));
        // Out of the delay slot's 256 MB region: left alone.
        let mut code = 0x0320_f809_u32.to_be_bytes();
        assert_eq!(mips(&mut code, 0, 37, at(0x1000_0000), true), None);
        assert_eq!(code, 0x0320_f809_u32.to_be_bytes());
    }
}
