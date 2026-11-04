//! Lay out and link a relocatable object (ELF `.o`, `.syso`, `.ko`; Mach-O
//! `MH_OBJECT`) the way a loader would see it.
//!
//! An object's branches and pointers hold placeholders until the linker
//! applies relocations, and an ELF object's sections all claim address
//! zero. An ELF object's sections are placed at [`BASE`] plus their file
//! offsets, those with no file bytes after the rest; a Mach-O object's
//! sections already have addresses. Relocations are applied to copies of
//! the sections they patch, and each undefined symbol gets an import slot
//! past the last section, so a call to it reads as a call through an
//! import.

use std::borrow::Cow;
use std::collections::HashMap;

use super::elf::{self, Elf};
use super::read::{self, Reader};
use super::{file_range, limits, macho};

use crate::{Arch, Segment, Slot};

/// Where an ELF object's sections are placed.
const BASE: u64 = 0x800_0000;

// x86-64.
const R_X86_64_64: u32 = 1;
const R_X86_64_PC32: u32 = 2;
const R_X86_64_PLT32: u32 = 4;
const R_X86_64_GOTPCREL: u32 = 9;
const R_X86_64_32: u32 = 10;
const R_X86_64_32S: u32 = 11;
const R_X86_64_PC64: u32 = 24;
const R_X86_64_GOTPCRELX: u32 = 41;
const R_X86_64_REX_GOTPCRELX: u32 = 42;

// 32-bit x86.
const R_386_32: u32 = 1;
const R_386_PC32: u32 = 2;
const R_386_PLT32: u32 = 4;

// A64.
const R_AARCH64_ABS64: u32 = 257;
const R_AARCH64_ABS32: u32 = 258;
const R_AARCH64_PREL64: u32 = 260;
const R_AARCH64_PREL32: u32 = 261;
const R_AARCH64_ADR_PREL_PG_HI21: u32 = 275;
const R_AARCH64_ADD_ABS_LO12_NC: u32 = 277;
const R_AARCH64_LDST8_ABS_LO12_NC: u32 = 278;
const R_AARCH64_JUMP26: u32 = 282;
const R_AARCH64_CALL26: u32 = 283;
const R_AARCH64_LDST16_ABS_LO12_NC: u32 = 284;
const R_AARCH64_LDST32_ABS_LO12_NC: u32 = 285;
const R_AARCH64_LDST64_ABS_LO12_NC: u32 = 286;
const R_AARCH64_LDST128_ABS_LO12_NC: u32 = 299;
const R_AARCH64_ADR_GOT_PAGE: u32 = 311;
const R_AARCH64_LD64_GOT_LO12_NC: u32 = 312;

// 32-bit Arm.
const R_ARM_PC24: u32 = 1;
const R_ARM_ABS32: u32 = 2;
const R_ARM_REL32: u32 = 3;
const R_ARM_THM_CALL: u32 = 10;
const R_ARM_CALL: u32 = 28;
const R_ARM_JUMP24: u32 = 29;
const R_ARM_THM_JUMP24: u32 = 30;

// MIPS.
const R_MIPS_32: u32 = 2;
const R_MIPS_26: u32 = 4;
const R_MIPS_64: u32 = 18;
const R_MIPS_JALR: u32 = 37;

// s390x.
const R_390_32: u32 = 4;
const R_390_PC32: u32 = 5;
const R_390_PC16DBL: u32 = 16;
const R_390_PLT16DBL: u32 = 17;
const R_390_PC32DBL: u32 = 19;
const R_390_PLT32DBL: u32 = 20;
const R_390_64: u32 = 22;

// SPARC.
const R_SPARC_32: u32 = 3;
const R_SPARC_DISP32: u32 = 6;
const R_SPARC_WDISP30: u32 = 7;
const R_SPARC_WDISP22: u32 = 8;
const R_SPARC_WPLT30: u32 = 18;
const R_SPARC_UA32: u32 = 23;
const R_SPARC_64: u32 = 32;
const R_SPARC_UA64: u32 = 54;

// RISC-V.
const R_RISCV_32: u32 = 1;
const R_RISCV_64: u32 = 2;
const R_RISCV_BRANCH: u32 = 16;
const R_RISCV_JAL: u32 = 17;
const R_RISCV_CALL: u32 = 18;
const R_RISCV_CALL_PLT: u32 = 19;
const R_RISCV_GOT_HI20: u32 = 20;
const R_RISCV_PCREL_HI20: u32 = 23;
const R_RISCV_PCREL_LO12_I: u32 = 24;
const R_RISCV_PCREL_LO12_S: u32 = 25;
const R_RISCV_HI20: u32 = 26;
const R_RISCV_LO12_I: u32 = 27;
const R_RISCV_LO12_S: u32 = 28;
const R_RISCV_ADD32: u32 = 35;
const R_RISCV_ADD64: u32 = 36;
const R_RISCV_SUB32: u32 = 39;
const R_RISCV_SUB64: u32 = 40;
const R_RISCV_RVC_BRANCH: u32 = 44;
const R_RISCV_RVC_JUMP: u32 = 45;
const R_RISCV_32_PCREL: u32 = 57;

// LoongArch.
const R_LARCH_32: u32 = 1;
const R_LARCH_64: u32 = 2;
const R_LARCH_ADD32: u32 = 50;
const R_LARCH_ADD64: u32 = 51;
const R_LARCH_SUB32: u32 = 55;
const R_LARCH_SUB64: u32 = 56;
const R_LARCH_B16: u32 = 64;
const R_LARCH_B21: u32 = 65;
const R_LARCH_B26: u32 = 66;
const R_LARCH_ABS_HI20: u32 = 67;
const R_LARCH_ABS_LO12: u32 = 68;
const R_LARCH_ABS64_LO20: u32 = 69;
const R_LARCH_ABS64_HI12: u32 = 70;
const R_LARCH_PCALA_HI20: u32 = 71;
const R_LARCH_PCALA_LO12: u32 = 72;
const R_LARCH_GOT_PC_HI20: u32 = 75;
const R_LARCH_GOT_PC_LO12: u32 = 76;
const R_LARCH_32_PCREL: u32 = 99;
const R_LARCH_PCREL20_S2: u32 = 103;
const R_LARCH_64_PCREL: u32 = 109;
const R_LARCH_CALL36: u32 = 110;

// Mach-O.
/// `ARM64_RELOC_ADDEND`: the addend of the relocation after it.
const ARM64_RELOC_ADDEND: u32 = 10;
/// `ARM64_RELOC_BRANCH26` and `X86_64_RELOC_BRANCH`.
const RELOC_BRANCH: u32 = 2;
/// A Mach-O relocation entry's `r_address` high bit: scattered, which is
/// 32-bit only.
const R_SCATTERED: u32 = 0x8000_0000;
const R_EXTERN: u32 = 0x0800_0000;

/// An object's sections at their placed addresses, linked.
pub(super) struct Layout<'a> {
    /// Each section's address, by section index; zero for sections not
    /// loaded.
    pub(super) addrs: Vec<u64>,
    pub(super) segments: Vec<Segment<'a>>,
    pub(super) imports: Vec<Slot>,
}

/// Import slots for an object's undefined symbols: one per symbol, 8 bytes
/// apart, from the first 16-byte boundary past the sections.
struct ImportSlots {
    first: u64,
    by_symbol: HashMap<usize, u64>,
    imports: Vec<Slot>,
}

impl ImportSlots {
    fn new(end: u64) -> Self {
        Self {
            first: end.div_ceil(16).saturating_mul(16),
            by_symbol: HashMap::new(),
            imports: Vec::new(),
        }
    }

    /// The slot of symbol `index`, called `name`.
    fn slot(&mut self, index: usize, name: &str) -> u64 {
        let next = (self.by_symbol.len() as u64)
            .saturating_mul(8)
            .saturating_add(self.first);
        *self.by_symbol.entry(index).or_insert_with(|| {
            self.imports.push(Slot {
                slot: next,
                name: name.to_owned(),
                import: None,
            });
            next
        })
    }
}

/// A section's bytes, copied the first time a relocation patches them,
/// while the copies stay within [`limits::LINKED_BYTES`].
fn writable<'s>(bytes: &'s mut Cow<'_, [u8]>, budget: &mut usize) -> Option<&'s mut [u8]> {
    if let Cow::Borrowed(borrowed) = bytes {
        *budget = budget.checked_sub(borrowed.len())?;
    }
    Some(bytes.to_mut())
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
    let mut data: Vec<Option<Cow<'a, [u8]>>> = headers
        .iter()
        .map(|sh| {
            (alloc(sh) && sh.kind != elf::SHT_NOBITS)
                .then(|| Cow::Borrowed(file_range(bytes, sh.offset, sh.size)))
        })
        .collect();

    let mut slots = ImportSlots::new(end);
    let mut symbol = |index: usize| -> Option<(u64, bool)> {
        let symbol = elf.symbols.get(index)?;
        match symbol.shndx {
            elf::SHN_UNDEF if symbol.name.is_empty() => None,
            elf::SHN_UNDEF => Some((slots.slot(index, &symbol.name), true)),
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
    let mut budget = limits::LINKED_BYTES;
    for &(target, ref relocs) in &elf.relocations {
        let Some(place_base) = addrs.get(target).copied() else {
            continue;
        };
        let Some(Some(section)) = data.get_mut(target) else {
            continue;
        };
        if relocs.is_empty() {
            continue;
        }
        let Some(section) = writable(section, &mut budget) else {
            continue;
        };
        for reloc in relocs {
            let Some((value, undefined)) = (match reloc.symbol {
                0 => Some((0, false)),
                index => symbol(index),
            }) else {
                continue;
            };
            let offset = reloc.offset;
            let fix = Fix {
                value,
                addend: reloc.addend,
                place: place_base.wrapping_add(offset),
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
        .zip(data)
        .filter_map(|((sh, &addr), data)| {
            Some(Segment {
                addr,
                bytes: data?,
                executable: sh.flags & elf::SHF_EXECINSTR != 0,
            })
        })
        .collect();
    Layout {
        addrs,
        segments,
        imports: slots.imports,
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
    let end = sections
        .iter()
        .map(|section| section.addr.saturating_add(section.size))
        .max()
        .unwrap_or(0);
    let mut slots = ImportSlots::new(end);
    let mut budget = limits::LINKED_BYTES;
    let mut linked = Vec::with_capacity(sections.len());
    for section in sections {
        let count = u64::from(section.nreloc).min(limits::TABLE);
        let table = file_range(bytes, u64::from(section.reloff), count.saturating_mul(8));
        let mut data = Cow::Borrowed(file_range(bytes, section.offset, section.size));
        let writable = (section.code && !table.is_empty())
            .then(|| writable(&mut data, &mut budget))
            .flatten();
        let patched = match writable {
            Some(data) => data,
            None => {
                linked.push(None);
                continue;
            }
        };
        let r = Reader::new(table, false);
        let mut addend = 0_i64;
        for at in read::table(0, 8, count) {
            let (Some(address), Some(info)) = (r.u32(at), r.at(at).u32(4)) else {
                break;
            };
            let symbol = info & 0x00ff_ffff;
            let kind = info >> 28;
            if address & R_SCATTERED != 0 {
                continue;
            }
            if arch == Arch::Arm64 && kind == ARM64_RELOC_ADDEND {
                addend = i64::from((symbol << 8).cast_signed() >> 8);
                continue;
            }
            let addend = std::mem::take(&mut addend);
            if info & R_EXTERN == 0 || kind != RELOC_BRANCH {
                continue;
            }
            let Ok(index) = usize::try_from(symbol) else {
                continue;
            };
            let Some(nlist) = symbols.get(index) else {
                continue;
            };
            let (value, undefined) = match nlist.n_type & N_TYPE {
                N_SECT => (nlist.n_value, false),
                N_UNDF if !nlist.name.is_empty() => (slots.slot(index, &nlist.name), true),
                _ => continue,
            };
            let offset = u64::from(address);
            let place = section.addr.wrapping_add(offset);
            match arch {
                Arch::Arm64 => branch26(patched, offset, value.wrapping_add_signed(addend), place),
                // The in-place addend counts from the end of the field.
                Arch::X86_64 => rel32(
                    patched,
                    offset,
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
        linked.push(Some(data.into_owned()));
    }
    (linked, slots.imports)
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
    fn target(self, bytes: &[u8], offset: u64) -> Option<u64> {
        let addend = match self.addend {
            Some(addend) => addend,
            None => i64::from(Reader::new(bytes, false).u32(offset)?.cast_signed()),
        };
        Some(self.value.wrapping_add_signed(addend))
    }

    /// `S + A - P`.
    fn relative(self, bytes: &[u8], offset: u64) -> Option<u64> {
        Some(self.target(bytes, offset)?.wrapping_sub(self.place))
    }
}

/// The 32-bit word at `offset`, big-endian when `big`.
fn word(bytes: &[u8], offset: u64, big: bool) -> Option<u32> {
    Reader::new(bytes, big).u32(offset)
}

fn put_word(bytes: &mut [u8], offset: u64, word: u32, big: bool) -> Option<()> {
    let raw = if big {
        word.to_be_bytes()
    } else {
        word.to_le_bytes()
    };
    put(bytes, offset, &raw)
}

/// `value`'s low `bits` bits, if it fits in them as a signed number.
fn fits(value: i64, bits: u32) -> Option<u32> {
    let unused = 64_u32.checked_sub(bits)?;
    let extended = value.checked_shl(unused)?.checked_shr(unused)?;
    let low = value.cast_unsigned() & u64::MAX.checked_shr(unused)?;
    (extended == value).then(|| u32::try_from(low).ok())?
}

fn put(bytes: &mut [u8], offset: u64, value: &[u8]) -> Option<()> {
    let offset = usize::try_from(offset).ok()?;
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

/// A little-endian 32-bit PC-relative field: `S + A - P`, truncated.
fn rel32(bytes: &mut [u8], offset: u64, fix: Fix) -> Option<()> {
    put(bytes, offset, &low32(fix.relative(bytes, offset)?))
}

/// An A64 `b` or `bl` at `offset`, at `place`: a word offset to `target`
/// in 26 bits.
fn branch26(bytes: &mut [u8], offset: u64, target: u64, place: u64) -> Option<()> {
    let delta = target.wrapping_sub(place).cast_signed() >> 2;
    let imm = fits(delta, 26)?;
    let insn = word(bytes, offset, false)? & !0x03ff_ffff | imm;
    put(bytes, offset, &insn.to_le_bytes())
}

fn x86_64(bytes: &mut [u8], offset: u64, kind: u32, fix: Fix) -> Option<()> {
    match kind {
        R_X86_64_64 => put(bytes, offset, &fix.target(bytes, offset)?.to_le_bytes()),
        R_X86_64_PC64 => put(bytes, offset, &fix.relative(bytes, offset)?.to_le_bytes()),
        R_X86_64_PC32 | R_X86_64_PLT32 => rel32(bytes, offset, fix),
        // The GOT forms only for imports, whose slot stands in for the GOT
        // entry.
        R_X86_64_GOTPCREL | R_X86_64_GOTPCRELX | R_X86_64_REX_GOTPCRELX if fix.undefined => {
            rel32(bytes, offset, fix)
        }
        R_X86_64_32 | R_X86_64_32S => put(bytes, offset, &low32(fix.target(bytes, offset)?)),
        _ => None,
    }
}

fn i386(bytes: &mut [u8], offset: u64, kind: u32, fix: Fix) -> Option<()> {
    match kind {
        R_386_32 => put(bytes, offset, &low32(fix.target(bytes, offset)?)),
        R_386_PC32 | R_386_PLT32 => rel32(bytes, offset, fix),
        _ => None,
    }
}

fn aarch64(bytes: &mut [u8], offset: u64, kind: u32, fix: Fix) -> Option<()> {
    let patch = |bytes: &mut [u8], mask: u32, field: u32| -> Option<()> {
        let insn = word(bytes, offset, false)? & !mask | field & mask;
        put(bytes, offset, &insn.to_le_bytes())
    };
    let s_a = fix.target(bytes, offset)?;
    let low12 = (s_a & 0xfff) as u32;
    // A load or store's scaled 12-bit offset.
    let scaled = |bytes: &mut [u8], scale: u32| patch(bytes, 0xfff << 10, (low12 >> scale) << 10);
    match kind {
        R_AARCH64_ABS64 => put(bytes, offset, &s_a.to_le_bytes()),
        R_AARCH64_ABS32 => put(bytes, offset, &low32(s_a)),
        R_AARCH64_PREL64 => put(bytes, offset, &s_a.wrapping_sub(fix.place).to_le_bytes()),
        R_AARCH64_PREL32 => put(bytes, offset, &low32(s_a.wrapping_sub(fix.place))),
        R_AARCH64_JUMP26 | R_AARCH64_CALL26 => branch26(bytes, offset, s_a, fix.place),
        // The GOT form only for imports.
        R_AARCH64_ADR_PREL_PG_HI21 | R_AARCH64_ADR_GOT_PAGE
            if kind == R_AARCH64_ADR_PREL_PG_HI21 || fix.undefined =>
        {
            let pages = ((s_a & !0xfff).wrapping_sub(fix.place & !0xfff)).cast_signed() >> 12;
            // The low 21 bits, as the field holds them.
            let pages = u32::try_from(pages & 0x1f_ffff).ok()?;
            patch(
                bytes,
                0x60ff_ffe0,
                (pages & 3) << 29 | (pages >> 2 & 0x7_ffff) << 5,
            )
        }
        R_AARCH64_ADD_ABS_LO12_NC | R_AARCH64_LDST8_ABS_LO12_NC => scaled(bytes, 0),
        R_AARCH64_LDST16_ABS_LO12_NC => scaled(bytes, 1),
        R_AARCH64_LDST32_ABS_LO12_NC => scaled(bytes, 2),
        R_AARCH64_LDST64_ABS_LO12_NC => scaled(bytes, 3),
        R_AARCH64_LD64_GOT_LO12_NC if fix.undefined => scaled(bytes, 3),
        R_AARCH64_LDST128_ABS_LO12_NC => scaled(bytes, 4),
        _ => None,
    }
}

/// 32-bit Arm, whose relocations are REL: each addend is in the field it
/// fixes. A call between A32 and Thumb becomes a `blx`; an import's slot
/// counts as A32 code.
fn arm(bytes: &mut [u8], offset: u64, kind: u32, fix: Fix) -> Option<()> {
    let insn = word(bytes, offset, false)?;
    let thumb = |value: u64| value & 1 != 0;
    match kind {
        R_ARM_ABS32 => put(bytes, offset, &low32(fix.target(bytes, offset)?)),
        R_ARM_REL32 => put(bytes, offset, &low32(fix.relative(bytes, offset)?)),
        // A word offset in 24 bits; a call to Thumb is a `blx`, whose H bit
        // holds the offset's halfword.
        R_ARM_PC24 | R_ARM_CALL | R_ARM_JUMP24 => {
            let addend = fix
                .addend
                .unwrap_or(i64::from(((insn & 0x00ff_ffff) << 8).cast_signed() >> 6));
            let s_a = fix.value.wrapping_add_signed(addend);
            let delta = (s_a & !1).wrapping_sub(fix.place).cast_signed();
            let imm = fits(delta >> 2, 24)?;
            let insn = if kind == R_ARM_CALL && thumb(s_a) {
                0xfa00_0000 | u32::from(delta & 2 != 0) << 24 | imm
            } else if thumb(s_a) {
                return None;
            } else {
                insn & 0xff00_0000 | imm
            };
            put_word(bytes, offset, insn, false)
        }
        // A halfword offset split over two halfwords; a call to A32 is a
        // `blx`, from the word-aligned PC.
        R_ARM_THM_CALL | R_ARM_THM_JUMP24 => {
            let (first, second) = (insn & 0xffff, insn >> 16);
            let addend = fix.addend.unwrap_or_else(|| thumb_offset(first, second));
            let s_a = fix.value.wrapping_add_signed(addend);
            let to_a32 = !thumb(s_a);
            if to_a32 && kind == R_ARM_THM_JUMP24 {
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
fn mips(bytes: &mut [u8], offset: u64, kind: u32, fix: Fix, big: bool) -> Option<()> {
    const JALR_T9: u32 = 0x0320_f809;
    const JR_T9: u32 = 0x0320_0008;
    const JAL: u32 = 0x0c00_0000;
    const J: u32 = 0x0800_0000;
    let insn = word(bytes, offset, big)?;
    let region = |target: u64| {
        if (target ^ fix.place.wrapping_add(4)) & !0x0fff_ffff != 0 {
            return None;
        }
        u32::try_from(target >> 2 & 0x03ff_ffff).ok()
    };
    match kind {
        R_MIPS_32 => {
            let addend = fix.addend.unwrap_or(i64::from(insn.cast_signed()));
            let target = fix.value.wrapping_add_signed(addend);
            put_word(bytes, offset, u32::from_le_bytes(low32(target)), big)
        }
        R_MIPS_64 => {
            let in_place = Reader::new(bytes, big).u64(offset)?.cast_signed();
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
        // The in-place addend is the 26-bit field, in words.
        R_MIPS_26 => {
            let addend = fix.addend.unwrap_or(i64::from(insn & 0x03ff_ffff) << 2);
            let target = fix.value.wrapping_add_signed(addend);
            put_word(bytes, offset, insn & 0xfc00_0000 | region(target)?, big)
        }
        R_MIPS_JALR if insn == JALR_T9 || insn == JR_T9 => {
            let target = fix.value.wrapping_add_signed(fix.addend.unwrap_or(0));
            let opcode = if insn == JALR_T9 { JAL } else { J };
            put_word(bytes, offset, opcode | region(target)?, big)
        }
        _ => None,
    }
}

/// s390x: RELA, big-endian; relative fields count halfwords.
fn s390x(bytes: &mut [u8], offset: u64, kind: u32, fix: Fix) -> Option<()> {
    let target = fix.value.wrapping_add_signed(fix.addend?);
    let relative = target.wrapping_sub(fix.place).cast_signed();
    match kind {
        R_390_32 => put_word(bytes, offset, u32::from_le_bytes(low32(target)), true),
        R_390_PC32 => put(bytes, offset, &fits(relative, 32)?.to_be_bytes()),
        R_390_64 => put(bytes, offset, &target.to_be_bytes()),
        R_390_PC16DBL | R_390_PLT16DBL => {
            let half = u16::try_from(fits(relative >> 1, 16)?).ok()?;
            put(bytes, offset, &half.to_be_bytes())
        }
        R_390_PC32DBL | R_390_PLT32DBL => {
            put(bytes, offset, &fits(relative >> 1, 32)?.to_be_bytes())
        }
        _ => None,
    }
}

/// SPARC: RELA, big-endian; `call` holds a 30-bit word displacement.
fn sparc(bytes: &mut [u8], offset: u64, kind: u32, fix: Fix) -> Option<()> {
    let target = fix.value.wrapping_add_signed(fix.addend?);
    let relative = target.wrapping_sub(fix.place).cast_signed();
    let insn = word(bytes, offset, true)?;
    match kind {
        R_SPARC_32 | R_SPARC_UA32 => {
            put_word(bytes, offset, u32::from_le_bytes(low32(target)), true)
        }
        R_SPARC_64 | R_SPARC_UA64 => put(bytes, offset, &target.to_be_bytes()),
        R_SPARC_DISP32 => put(bytes, offset, &fits(relative, 32)?.to_be_bytes()),
        // `call`, whose displacement wraps.
        R_SPARC_WDISP30 | R_SPARC_WPLT30 => {
            let disp = u32::try_from((relative >> 2) & 0x3fff_ffff).ok()?;
            put_word(bytes, offset, insn & 0xc000_0000 | disp, true)
        }
        // `b<cc>`.
        R_SPARC_WDISP22 => put_word(
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
    offset: u64,
    kind: u32,
    fix: Fix,
    high: &mut HashMap<u64, i64>,
) -> Option<()> {
    let target = fix.value.wrapping_add_signed(fix.addend?);
    let relative = target.wrapping_sub(fix.place).cast_signed();
    let insn = word(bytes, offset, false).unwrap_or(0);
    let half = Reader::new(bytes, false).u16(offset)?;
    let u_type = |insn: u32, value: u32| insn & 0xfff | value << 12;
    let i_type = |insn: u32, value: u32| insn & 0x000f_ffff | value << 20;
    let s_type =
        |insn: u32, value: u32| insn & 0x01ff_f07f | (value >> 5) << 25 | (value & 0x1f) << 7;
    match kind {
        R_RISCV_32 => put(bytes, offset, &low32(target)),
        R_RISCV_64 => put(bytes, offset, &target.to_le_bytes()),
        R_RISCV_32_PCREL => put(bytes, offset, &fits(relative, 32)?.to_le_bytes()),
        // `.eh_frame`'s and the debug sections' differences.
        R_RISCV_ADD32 | R_RISCV_SUB32 => {
            add_sub(bytes, offset, target, false, kind == R_RISCV_SUB32)
        }
        R_RISCV_ADD64 | R_RISCV_SUB64 => {
            add_sub(bytes, offset, target, true, kind == R_RISCV_SUB64)
        }
        // B-type, 13 bits.
        R_RISCV_BRANCH => {
            let imm = fits(relative, 13)?;
            let field = (imm >> 12 & 1) << 31
                | (imm >> 5 & 0x3f) << 25
                | (imm >> 1 & 0xf) << 8
                | (imm >> 11 & 1) << 7;
            put_word(bytes, offset, insn & 0x01ff_f07f | field, false)
        }
        // J-type, 21 bits.
        R_RISCV_JAL => {
            let imm = fits(relative, 21)?;
            let field = (imm >> 20 & 1) << 31
                | (imm >> 1 & 0x3ff) << 21
                | (imm >> 11 & 1) << 20
                | (imm >> 12 & 0xff) << 12;
            put_word(bytes, offset, insn & 0xfff | field, false)
        }
        // `auipc` and the `jalr` after it.
        R_RISCV_CALL | R_RISCV_CALL_PLT => {
            let (hi, lo) = split(relative)?;
            let next = offset.checked_add(4)?;
            let jalr = word(bytes, next, false)?;
            put_word(bytes, offset, u_type(insn, hi), false)?;
            put_word(bytes, next, i_type(jalr, lo), false)
        }
        // The GOT form for imports, whose slot stands in for the GOT entry.
        R_RISCV_PCREL_HI20 | R_RISCV_GOT_HI20 if kind == R_RISCV_PCREL_HI20 || fix.undefined => {
            high.insert(fix.place, relative);
            put_word(bytes, offset, u_type(insn, split(relative)?.0), false)
        }
        // The symbol is the `auipc`.
        R_RISCV_PCREL_LO12_I | R_RISCV_PCREL_LO12_S => {
            let (_, lo) = split(*high.get(&target)?)?;
            let insn = if kind == R_RISCV_PCREL_LO12_I {
                i_type(insn, lo)
            } else {
                s_type(insn, lo)
            };
            put_word(bytes, offset, insn, false)
        }
        // Absolute `lui; addi`.
        R_RISCV_HI20 => put_word(
            bytes,
            offset,
            u_type(insn, split(target.cast_signed())?.0),
            false,
        ),
        R_RISCV_LO12_I => put_word(
            bytes,
            offset,
            i_type(insn, split(target.cast_signed())?.1),
            false,
        ),
        R_RISCV_LO12_S => put_word(
            bytes,
            offset,
            s_type(insn, split(target.cast_signed())?.1),
            false,
        ),
        // CB, 9 bits.
        R_RISCV_RVC_BRANCH => {
            let imm = fits(relative, 9)?;
            let field = (imm >> 8 & 1) << 12
                | (imm >> 3 & 3) << 10
                | (imm >> 6 & 3) << 5
                | (imm >> 1 & 3) << 3
                | (imm >> 5 & 1) << 2;
            let field = u16::try_from(field).ok()?;
            put(bytes, offset, &(half & 0xe383 | field).to_le_bytes())
        }
        // CJ, 12 bits.
        R_RISCV_RVC_JUMP => {
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
fn add_sub(bytes: &mut [u8], offset: u64, value: u64, wide: bool, sub: bool) -> Option<()> {
    let r = Reader::new(bytes, false);
    let (old, value) = if wide {
        (r.u64(offset)?, value)
    } else {
        (
            u64::from(r.u32(offset)?),
            u64::from(u32::from_le_bytes(low32(value))),
        )
    };
    let new = if sub {
        old.wrapping_sub(value)
    } else {
        old.wrapping_add(value)
    };
    if wide {
        put(bytes, offset, &new.to_le_bytes())
    } else {
        put(bytes, offset, &low32(new))
    }
}

/// LoongArch: RELA, little-endian. Calls are `bl` (`B26`) or, in the
/// medium code model, `pcaddu18i; jirl` pairs (`CALL36`); addresses are
/// `pcalau12i; addi.d` (`PCALA_HI20`, `PCALA_LO12`), whose low part is the
/// target's own low 12 bits. Branches within a section are relocated too,
/// as the linker may relax what lies between.
fn loongarch(bytes: &mut [u8], offset: u64, kind: u32, fix: Fix) -> Option<()> {
    let target = fix.value.wrapping_add_signed(fix.addend?);
    let relative = target.wrapping_sub(fix.place).cast_signed();
    let insn = word(bytes, offset, false).unwrap_or(0);
    // The 20-bit field at bits 5-24, and the 12- and 16-bit ones from bit
    // 10.
    let si20 = |insn: u32, value: u32| insn & !(0xf_ffff << 5) | (value & 0xf_ffff) << 5;
    let i12 = |insn: u32, value: u32| insn & !(0xfff << 10) | (value & 0xfff) << 10;
    let i16 = |insn: u32, value: u32| insn & !(0xffff << 10) | (value & 0xffff) << 10;
    let page = |value: u64| value.wrapping_add(0x800) & !0xfff;
    let low12 = u32::try_from(target & 0xfff).ok()?;
    match kind {
        R_LARCH_32 => put(bytes, offset, &low32(target)),
        R_LARCH_64 => put(bytes, offset, &target.to_le_bytes()),
        R_LARCH_32_PCREL => put(bytes, offset, &fits(relative, 32)?.to_le_bytes()),
        R_LARCH_64_PCREL => put(bytes, offset, &relative.to_le_bytes()),
        R_LARCH_ADD32 | R_LARCH_SUB32 => {
            add_sub(bytes, offset, target, false, kind == R_LARCH_SUB32)
        }
        R_LARCH_ADD64 | R_LARCH_SUB64 => {
            add_sub(bytes, offset, target, true, kind == R_LARCH_SUB64)
        }
        // `beq` and kin; `beqz`, `bnez`; `b`, `bl`.
        R_LARCH_B16 => put_word(bytes, offset, i16(insn, fits(relative >> 2, 16)?), false),
        R_LARCH_B21 => {
            let offs = fits(relative >> 2, 21)?;
            put_word(bytes, offset, i16(insn, offs) & !0x1f | offs >> 16, false)
        }
        R_LARCH_B26 => {
            let offs = fits(relative >> 2, 26)?;
            put_word(bytes, offset, i16(insn, offs) & !0x3ff | offs >> 16, false)
        }
        // `lu12i.w; ori; lu32i.d; lu52i.d`.
        R_LARCH_ABS_HI20 => put_word(
            bytes,
            offset,
            si20(insn, u32::try_from(target >> 12 & 0xf_ffff).ok()?),
            false,
        ),
        R_LARCH_ABS_LO12 => put_word(bytes, offset, i12(insn, low12), false),
        R_LARCH_ABS64_LO20 => put_word(
            bytes,
            offset,
            si20(insn, u32::try_from(target >> 32 & 0xf_ffff).ok()?),
            false,
        ),
        R_LARCH_ABS64_HI12 => put_word(
            bytes,
            offset,
            i12(insn, u32::try_from(target >> 52).ok()?),
            false,
        ),
        // The GOT forms for imports, whose slot stands in for the GOT
        // entry.
        R_LARCH_PCALA_HI20 | R_LARCH_GOT_PC_HI20 if kind == R_LARCH_PCALA_HI20 || fix.undefined => {
            let pages = page(target).wrapping_sub(fix.place & !0xfff).cast_signed() >> 12;
            put_word(
                bytes,
                offset,
                si20(insn, u32::try_from(pages & 0xf_ffff).ok()?),
                false,
            )
        }
        R_LARCH_PCALA_LO12 | R_LARCH_GOT_PC_LO12 if kind == R_LARCH_PCALA_LO12 || fix.undefined => {
            put_word(bytes, offset, i12(insn, low12), false)
        }
        // `pcaddi`.
        R_LARCH_PCREL20_S2 => put_word(bytes, offset, si20(insn, fits(relative >> 2, 20)?), false),
        // `pcaddu18i` and the `jirl` after it.
        R_LARCH_CALL36 => {
            let high = relative.wrapping_add(0x2_0000) >> 18;
            let low = relative.wrapping_sub(high.wrapping_shl(18)) >> 2;
            let next = offset.checked_add(4)?;
            let jirl = word(bytes, next, false)?;
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
        x86_64(&mut code, 1, R_X86_64_PLT32, fix);
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
        i386(&mut code, 1, R_386_PC32, fix);
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
        aarch64(&mut code, 0, R_AARCH64_CALL26, at(0x800_1000, 0x800_1040));
        aarch64(
            &mut code,
            4,
            R_AARCH64_ADR_PREL_PG_HI21,
            at(0x800_1004, 0x800_5678),
        );
        aarch64(
            &mut code,
            8,
            R_AARCH64_ADD_ABS_LO12_NC,
            at(0x800_1008, 0x800_5678),
        );
        let words: Vec<u32> = code
            .chunks_exact(4)
            .filter_map(|w| w.try_into().ok().map(u32::from_le_bytes))
            .collect();
        // bl +0x40; adrp x0, +4 pages; add x0, x0, #0x678
        assert_eq!(words, [0x9400_0010, 0x9000_0020, 0x9100_0000 | 0x678 << 10]);
        // Backwards, and out of reach.
        let mut code = 0x9400_0000_u32.to_le_bytes();
        assert_eq!(branch26(&mut code, 0, 0x800_0ff0, 0x800_1000), Some(()));
        assert_eq!(code, 0x97ff_fffc_u32.to_le_bytes());
        assert_eq!(branch26(&mut code, 0, 0x2000_0000, 0x800_1000), None);
    }

    #[test]
    fn fits_signed_fields() {
        assert_eq!(fits(-1, 8), Some(0xff));
        assert_eq!(fits(127, 8), Some(0x7f));
        assert_eq!(fits(128, 8), None);
        assert_eq!(fits(-129, 8), None);
        assert_eq!(fits(i64::MIN, 32), None);
        assert_eq!(fits(-1, 32), Some(u32::MAX));
        assert_eq!(fits(0, 0), None);
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
        arm(&mut code, 0, R_ARM_CALL, at(0x800_0100, 0x800_0203));
        assert_eq!(arm_call(&code, 0x800_0100), Flow::Call(0x800_0203));
        // A Thumb `bl` (addend -4 in place) at a halfword-aligned place,
        // to A32 code: `blx`, from the word-aligned PC.
        let mut code = [0xff, 0xf7, 0xfe, 0xff];
        arm(&mut code, 0, R_ARM_THM_CALL, at(0x800_0102, 0x800_0400));
        assert_eq!(arm_call(&code, 0x800_0103), Flow::Call(0x800_0400));
        // And to Thumb code, backwards: `bl`.
        let mut code = [0xff, 0xf7, 0xfe, 0xff];
        arm(&mut code, 0, R_ARM_THM_CALL, at(0x800_0102, 0x800_0041));
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
        riscv(
            &mut code,
            0,
            R_RISCV_CALL_PLT,
            at(0x800_1000, 0x801_3a00),
            &mut high,
        );
        assert_eq!(riscv_flows(&code, 0x800_1000)[1], Flow::Call(0x801_3a00));
        // beq a0, a1, 0, backwards; jal ra, 0, forwards.
        let mut code = 0x00b5_0063_u32.to_le_bytes();
        riscv(
            &mut code,
            0,
            R_RISCV_BRANCH,
            at(0x800_1000, 0x800_0f00),
            &mut high,
        );
        assert_eq!(riscv_flows(&code, 0x800_1000), [Flow::Branch(0x800_0f00)]);
        let mut code = 0x0000_00ef_u32.to_le_bytes();
        riscv(
            &mut code,
            0,
            R_RISCV_JAL,
            at(0x800_1000, 0x808_0000),
            &mut high,
        );
        assert_eq!(riscv_flows(&code, 0x800_1000), [Flow::Call(0x808_0000)]);
        // c.beqz a0, 0; c.j 0.
        let mut code = 0xc101_u16.to_le_bytes();
        riscv(
            &mut code,
            0,
            R_RISCV_RVC_BRANCH,
            at(0x800_1000, 0x800_0f42),
            &mut high,
        );
        assert_eq!(riscv_flows(&code, 0x800_1000), [Flow::Branch(0x800_0f42)]);
        let mut code = 0xa001_u16.to_le_bytes();
        riscv(
            &mut code,
            0,
            R_RISCV_RVC_JUMP,
            at(0x800_1000, 0x800_17fe),
            &mut high,
        );
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
            loongarch(&mut code, 0, R_LARCH_CALL36, at(0x833_3000, to));
            assert_eq!(decode(&words(&code), 0x833_3000)[1].flow, Flow::Call(to));
        }
        // bl 0, forwards; b 0, backwards; bnez a0, 0; bltu a2, a0, 0.
        for (word, kind, to, flow) in [
            (
                0x5400_0000_u32,
                R_LARCH_B26,
                0x900_0000,
                Flow::Call(0x900_0000),
            ),
            (0x5000_0000, R_LARCH_B26, 0x7f0_0000, Flow::Jump(0x7f0_0000)),
            (
                0x4400_0080,
                R_LARCH_B21,
                0x7f8_0004,
                Flow::Branch(0x7f8_0004),
            ),
            (
                0x6800_00c4,
                R_LARCH_B16,
                0x800_1ffc,
                Flow::Branch(0x800_1ffc),
            ),
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
        loongarch(&mut code, 0, R_LARCH_PCALA_HI20, at(0x800_1000, 0x804_5ab8));
        loongarch(&mut code, 4, R_LARCH_PCALA_LO12, at(0x800_1004, 0x804_5ab8));
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
        mips(&mut code, 0, R_MIPS_JALR, at(0x800_0100), false);
        mips(&mut code, 4, R_MIPS_JALR, at(0x800_0200), false);
        assert_eq!(word(&code, 0, false), Some(0x0e00_0040));
        assert_eq!(word(&code, 4, false), Some(0x0a00_0080));
        // Out of the delay slot's 256 MB region: left alone.
        let mut code = 0x0320_f809_u32.to_be_bytes();
        assert_eq!(mips(&mut code, 0, R_MIPS_JALR, at(0x1000_0000), true), None);
        assert_eq!(code, 0x0320_f809_u32.to_be_bytes());
    }

    /// Copies for relocation stop at the byte budget; sections past it are
    /// left as the file has them.
    #[test]
    fn copies_spend_a_budget() {
        let bytes = [7_u8; 64];
        let mut budget = 100;
        let mut sections: Vec<Cow<'_, [u8]>> = (0..3).map(|_| Cow::Borrowed(&bytes[..])).collect();
        let copied = sections
            .iter_mut()
            .map(|section| writable(section, &mut budget).is_some())
            .filter(|&copied| copied)
            .count();
        assert_eq!((copied, budget), (1, 36));
        let section = sections
            .first_mut()
            .map(|section| writable(section, &mut budget));
        assert!(
            section.is_some_and(|s| s.is_some()),
            "a copy is not copied again"
        );
    }
}
