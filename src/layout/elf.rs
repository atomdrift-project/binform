//! The parts of an ELF file recovery uses, read leniently: each header and
//! table is read on its own, and one that is truncated or points outside
//! the file is cut short or left out rather than failing the whole file.
//! The loader reads only the ELF header and program headers, so a file can
//! run with a section table that no strict parser accepts.

use super::read::Reader;

pub(super) const ET_REL: u16 = 1;
const EM_MIPS: u16 = 8;
pub(super) const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
pub(super) const PF_X: u32 = 1;
const SHT_SYMTAB: u32 = 2;
const SHT_RELA: u32 = 4;
const SHT_DYNAMIC: u32 = 6;
pub(super) const SHT_NOBITS: u32 = 8;
const SHT_REL: u32 = 9;
const SHT_DYNSYM: u32 = 11;
pub(super) const SHF_ALLOC: u64 = 2;
pub(super) const SHF_EXECINSTR: u64 = 4;
pub(super) const STT_OBJECT: u8 = 1;
pub(super) const STT_FUNC: u8 = 2;
pub(super) const SHN_UNDEF: u16 = 0;
pub(super) const SHN_ABS: u16 = 0xfff1;

const DT_NULL: u64 = 0;
const DT_PLTRELSZ: u64 = 2;
pub(super) const DT_PLTGOT: u64 = 3;
const DT_HASH: u64 = 4;
const DT_STRTAB: u64 = 5;
const DT_SYMTAB: u64 = 6;
const DT_RELA: u64 = 7;
const DT_RELASZ: u64 = 8;
const DT_STRSZ: u64 = 10;
const DT_REL: u64 = 17;
const DT_RELSZ: u64 = 18;
const DT_PLTREL: u64 = 20;
const DT_JMPREL: u64 = 23;
const DT_GNU_HASH: u64 = 0x6fff_fef5;
/// MIPS: the GOT's entries before the first symbol's, and the first
/// dynamic symbol with a GOT entry (each after it has one, in order).
pub(super) const DT_MIPS_LOCAL_GOTNO: u64 = 0x7000_000a;
pub(super) const DT_MIPS_GOTSYM: u64 = 0x7000_0013;

/// The most entries read from any one table.
const MOST: u64 = 1 << 20;

pub(super) struct Elf {
    pub(super) is_64: bool,
    pub(super) big: bool,
    pub(super) machine: u16,
    /// `e_flags`: on MIPS, the release in its top four bits.
    pub(super) header_flags: u32,
    pub(super) kind: u16,
    pub(super) entry: u64,
    pub(super) programs: Vec<Program>,
    pub(super) sections: Vec<Section>,
    /// `.symtab`.
    pub(super) symbols: Vec<Symbol>,
    /// `.dynsym`, or the table the dynamic section names.
    pub(super) dynamic_symbols: Vec<Symbol>,
    /// The dynamic section's (tag, value) entries.
    pub(super) dynamic: Vec<(u64, u64)>,
    /// An object's relocations: each relocation section's target section
    /// index and entries, whose symbols index `symbols`.
    pub(super) relocations: Vec<(usize, Vec<Reloc>)>,
    /// The dynamic linker's relocations, whose symbols index
    /// `dynamic_symbols`.
    pub(super) dynamic_relocations: Vec<Reloc>,
}

pub(super) struct Program {
    pub(super) kind: u32,
    pub(super) flags: u32,
    pub(super) offset: u64,
    pub(super) vaddr: u64,
    pub(super) filesz: u64,
}

pub(super) struct Section {
    pub(super) name: String,
    pub(super) kind: u32,
    pub(super) flags: u64,
    pub(super) addr: u64,
    pub(super) offset: u64,
    pub(super) size: u64,
    pub(super) link: u32,
    pub(super) info: u32,
    pub(super) addralign: u64,
    pub(super) entsize: u64,
}

pub(super) struct Symbol {
    pub(super) name: String,
    /// `STT_*`: the low four bits of `st_info`.
    pub(super) kind: u8,
    pub(super) shndx: u16,
    pub(super) value: u64,
    pub(super) size: u64,
}

pub(super) struct Reloc {
    pub(super) offset: u64,
    pub(super) kind: u32,
    pub(super) symbol: usize,
    /// Present in `RELA` entries; a `REL` entry's addend is at the place.
    pub(super) addend: Option<i64>,
}

/// The ELF file in `bytes`, or why it is none: only an ELF header too short
/// or of no known class fails.
pub(super) fn parse(bytes: &[u8]) -> Result<Elf, String> {
    let (is_64, big) = match (bytes.get(4), bytes.get(5)) {
        (Some(1), Some(1)) => (false, false),
        (Some(1), Some(2)) => (false, true),
        (Some(2), Some(1)) => (true, false),
        (Some(2), Some(2)) => (true, true),
        _ => return Err("unknown ELF class or byte order".into()),
    };
    let r = Reader::new(bytes, big);
    let header = (|| {
        let word = |at32: u64, at64: u64| r.word(if is_64 { at64 } else { at32 }, is_64);
        let half = |at32: u64, at64: u64| r.u16(if is_64 { at64 } else { at32 }).map(u64::from);
        Some([
            u64::from(r.u16(16)?),
            u64::from(r.u16(18)?),
            word(24, 24)?,
            word(28, 32)?,
            word(32, 40)?,
            half(42, 54)?,
            half(44, 56)?,
            half(46, 58)?,
            half(48, 60)?,
            half(50, 62)?,
        ])
    })()
    .ok_or("ELF header truncated")?;
    let [
        kind,
        machine,
        entry,
        phoff,
        shoff,
        phentsize,
        phnum,
        shentsize,
        shnum,
        shstrndx,
    ] = header;

    let programs = table(phoff, phentsize, phnum, if is_64 { 56 } else { 32 })
        .map_while(|at| program(&r, is_64, at))
        .collect();
    let mut names = Vec::new();
    let mut sections: Vec<Section> = table(shoff, shentsize, shnum, if is_64 { 64 } else { 40 })
        .map_while(|at| {
            names.push(r.u32(at)?);
            section(&r, is_64, at)
        })
        .collect();
    if let Some(strings) = usize::try_from(shstrndx)
        .ok()
        .and_then(|i| sections.get(i))
        .map(|sh| (sh.offset, sh.size))
    {
        for (sh, &name) in sections.iter_mut().zip(&names) {
            sh.name = string(&r, strings, name);
        }
    }

    let mut elf = Elf {
        is_64,
        big,
        machine: u16::try_from(machine).unwrap_or(u16::MAX),
        header_flags: r.u32(if is_64 { 48 } else { 36 }).unwrap_or(0),
        kind: u16::try_from(kind).unwrap_or(u16::MAX),
        entry,
        programs,
        sections,
        symbols: Vec::new(),
        dynamic_symbols: Vec::new(),
        dynamic: Vec::new(),
        relocations: Vec::new(),
        dynamic_relocations: Vec::new(),
    };
    elf.dynamic = elf.read_dynamic(&r);
    elf.read_symbols(&r);
    elf.read_relocations(&r);
    Ok(elf)
}

/// The offsets of a table's entries: `count` entries of `size` bytes from
/// `offset`, none when the entry size is smaller than `least`.
fn table(offset: u64, size: u64, count: u64, least: u64) -> impl Iterator<Item = u64> {
    let count = if offset == 0 || size < least {
        0
    } else {
        count.min(MOST)
    };
    (0..count).map_while(move |i| offset.checked_add(i.checked_mul(size)?))
}

fn program(r: &Reader<'_>, is_64: bool, at: u64) -> Option<Program> {
    Some(if is_64 {
        Program {
            kind: r.u32(at)?,
            flags: r.u32(at + 4)?,
            offset: r.u64(at + 8)?,
            vaddr: r.u64(at + 16)?,
            filesz: r.u64(at + 32)?,
        }
    } else {
        Program {
            kind: r.u32(at)?,
            offset: u64::from(r.u32(at + 4)?),
            vaddr: u64::from(r.u32(at + 8)?),
            filesz: u64::from(r.u32(at + 16)?),
            flags: r.u32(at + 24)?,
        }
    })
}

fn section(r: &Reader<'_>, is_64: bool, at: u64) -> Option<Section> {
    let word = |at32: u64, at64: u64| r.word(at + if is_64 { at64 } else { at32 }, is_64);
    let half = |at32: u64, at64: u64| r.u32(at + if is_64 { at64 } else { at32 });
    Some(Section {
        name: String::new(),
        kind: r.u32(at + 4)?,
        flags: word(8, 8)?,
        addr: word(12, 16)?,
        offset: word(16, 24)?,
        size: word(20, 32)?,
        link: half(24, 40)?,
        info: half(28, 44)?,
        addralign: word(32, 48)?,
        entsize: word(36, 56)?,
    })
}

/// The string at `offset` in the string table at file range `strings`.
fn string(r: &Reader<'_>, (start, size): (u64, u64), offset: u32) -> String {
    if u64::from(offset) >= size {
        return String::new();
    }
    r.name(start.saturating_add(u64::from(offset))).into_owned()
}

impl Elf {
    /// The file offset of virtual address `addr`, by the loadable segments.
    fn offset_of(&self, addr: u64) -> Option<u64> {
        self.programs
            .iter()
            .filter(|ph| ph.kind == PT_LOAD)
            .find(|ph| addr >= ph.vaddr && addr - ph.vaddr < ph.filesz)
            .map(|ph| ph.offset + (addr - ph.vaddr))
    }

    /// The value of the first dynamic entry tagged `tag`.
    pub(super) fn dynamic_value(&self, tag: u64) -> Option<u64> {
        self.dynamic
            .iter()
            .find(|&&(t, _)| t == tag)
            .map(|&(_, value)| value)
    }

    fn read_dynamic(&self, r: &Reader<'_>) -> Vec<(u64, u64)> {
        let range = self
            .programs
            .iter()
            .find(|ph| ph.kind == PT_DYNAMIC)
            .map(|ph| (ph.offset, ph.filesz))
            .or_else(|| {
                self.sections
                    .iter()
                    .find(|sh| sh.kind == SHT_DYNAMIC)
                    .map(|sh| (sh.offset, sh.size))
            });
        let Some((offset, size)) = range else {
            return Vec::new();
        };
        let entry = if self.is_64 { 16 } else { 8 };
        table(offset, entry, size / entry, entry)
            .map_while(|at| {
                let tag = r.word(at, self.is_64)?;
                let value = r.word(at + entry / 2, self.is_64)?;
                (tag != DT_NULL).then_some((tag, value))
            })
            .collect()
    }

    fn read_symbols(&mut self, r: &Reader<'_>) {
        for kind in [SHT_SYMTAB, SHT_DYNSYM] {
            let Some(sh) = self.sections.iter().find(|sh| sh.kind == kind) else {
                continue;
            };
            let strings = usize::try_from(sh.link)
                .ok()
                .and_then(|i| self.sections.get(i))
                .map_or((0, 0), |strtab| (strtab.offset, strtab.size));
            let symbols = self.symbol_table(r, sh.offset, sh.size, sh.entsize, strings);
            if kind == SHT_SYMTAB {
                self.symbols = symbols;
            } else {
                self.dynamic_symbols = symbols;
            }
        }
        if self.dynamic_symbols.is_empty() {
            self.dynamic_symbols = self.dynamic_symbol_table(r);
        }
    }

    fn symbol_table(
        &self,
        r: &Reader<'_>,
        offset: u64,
        size: u64,
        entsize: u64,
        strings: (u64, u64),
    ) -> Vec<Symbol> {
        let least = if self.is_64 { 24 } else { 16 };
        let entsize = if entsize >= least { entsize } else { least };
        table(offset, entsize, size / entsize, least)
            .map_while(|at| {
                let (info, shndx, value, size) = if self.is_64 {
                    (
                        r.u8(at + 4)?,
                        r.u16(at + 6)?,
                        r.u64(at + 8)?,
                        r.u64(at + 16)?,
                    )
                } else {
                    (
                        r.u8(at + 12)?,
                        r.u16(at + 14)?,
                        u64::from(r.u32(at + 4)?),
                        u64::from(r.u32(at + 8)?),
                    )
                };
                Some(Symbol {
                    name: string(r, strings, r.u32(at)?),
                    kind: info & 0xf,
                    shndx,
                    value,
                    size,
                })
            })
            .collect()
    }

    /// The symbol table the dynamic section names, for a file whose section
    /// table is gone. Its length is the hash table's symbol count.
    fn dynamic_symbol_table(&self, r: &Reader<'_>) -> Vec<Symbol> {
        let at = |tag| {
            self.dynamic_value(tag)
                .and_then(|addr| self.offset_of(addr))
        };
        let (Some(symtab), Some(strtab)) = (at(DT_SYMTAB), at(DT_STRTAB)) else {
            return Vec::new();
        };
        let count = at(DT_HASH)
            .and_then(|hash| r.u32(hash + 4))
            .map(u64::from)
            .or_else(|| at(DT_GNU_HASH).and_then(|hash| gnu_hash_count(r, hash, self.is_64)))
            .unwrap_or(0);
        let entsize = if self.is_64 { 24 } else { 16 };
        let strsz = self.dynamic_value(DT_STRSZ).unwrap_or(u64::MAX);
        self.symbol_table(
            r,
            symtab,
            count.saturating_mul(entsize),
            entsize,
            (strtab, strsz),
        )
    }

    fn read_relocations(&mut self, r: &Reader<'_>) {
        let dynsym = self.sections.iter().position(|sh| sh.kind == SHT_DYNSYM);
        let mut relocations = Vec::new();
        let mut from_sections = Vec::new();
        for sh in &self.sections {
            let rela = match sh.kind {
                SHT_RELA => true,
                SHT_REL => false,
                _ => continue,
            };
            let entries = self.reloc_table(r, sh.offset, sh.size, rela);
            if usize::try_from(sh.link).ok() == dynsym && dynsym.is_some() {
                from_sections.extend(entries);
            } else if let Ok(target) = usize::try_from(sh.info) {
                relocations.push((target, entries));
            }
        }
        self.relocations = relocations;

        // The dynamic linker's tables, by the dynamic section; by section
        // when it names none.
        let at = |tag| {
            self.dynamic_value(tag)
                .and_then(|addr| self.offset_of(addr))
        };
        let size = |tag| self.dynamic_value(tag).unwrap_or(0);
        let mut dynamic = Vec::new();
        if let Some(offset) = at(DT_JMPREL) {
            let rela = self.dynamic_value(DT_PLTREL) == Some(DT_RELA);
            dynamic.extend(self.reloc_table(r, offset, size(DT_PLTRELSZ), rela));
        }
        if let Some(offset) = at(DT_RELA) {
            dynamic.extend(self.reloc_table(r, offset, size(DT_RELASZ), true));
        }
        if let Some(offset) = at(DT_REL) {
            dynamic.extend(self.reloc_table(r, offset, size(DT_RELSZ), false));
        }
        self.dynamic_relocations = if dynamic.is_empty() {
            from_sections
        } else {
            dynamic
        };
    }

    fn reloc_table(&self, r: &Reader<'_>, offset: u64, size: u64, rela: bool) -> Vec<Reloc> {
        let word = if self.is_64 { 8 } else { 4 };
        let entry = if rela { 3 * word } else { 2 * word };
        table(offset, entry, size / entry, entry)
            .map_while(|at| {
                let offset = r.word(at, self.is_64)?;
                let info = r.word(at + word, self.is_64)?;
                let addend = if rela {
                    let raw = r.word(at + 2 * word, self.is_64)?;
                    Some(if self.is_64 {
                        raw.cast_signed()
                    } else {
                        i64::from(u32::try_from(raw).ok()?.cast_signed())
                    })
                } else {
                    None
                };
                let (symbol, kind) = if self.is_64 && self.machine == EM_MIPS {
                    // MIPS64 stores the symbol first, then a byte each for
                    // a special symbol and three types, the first last.
                    if self.big {
                        (info >> 32, info & 0xff)
                    } else {
                        (info & 0xffff_ffff, info >> 56)
                    }
                } else if self.is_64 {
                    (info >> 32, info & 0xffff_ffff)
                } else {
                    (info >> 8, info & 0xff)
                };
                Some(Reloc {
                    offset,
                    kind: u32::try_from(kind).ok()?,
                    symbol: usize::try_from(symbol).ok()?,
                    addend,
                })
            })
            .collect()
    }
}

/// The number of symbols a `DT_GNU_HASH` table covers: one past the last
/// symbol any bucket's chain reaches.
fn gnu_hash_count(r: &Reader<'_>, at: u64, is_64: bool) -> Option<u64> {
    let buckets = u64::from(r.u32(at)?).min(MOST);
    let offset = u64::from(r.u32(at + 4)?);
    let blooms = u64::from(r.u32(at + 8)?).min(MOST);
    let words = at + 16 + blooms * if is_64 { 8 } else { 4 };
    let last = (0..buckets)
        .filter_map(|i| r.u32(words + 4 * i))
        .max()
        .map(u64::from)?;
    if last < offset {
        return Some(offset);
    }
    let chains = words + 4 * buckets;
    // The chain ends at the entry whose low bit is set.
    let mut symbol = last;
    for _ in 0..MOST {
        let value = r.u32(chains + 4 * (symbol - offset))?;
        if value & 1 != 0 {
            return Some(symbol + 1);
        }
        symbol += 1;
    }
    Some(symbol)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 64-bit little-endian ELF header with `phnum` program headers and
    /// `shnum` section headers at `shoff`.
    fn header(phnum: u16, shoff: u64, shnum: u16) -> Vec<u8> {
        let mut bytes = vec![0x7f, b'E', b'L', b'F', 2, 1, 1];
        bytes.resize(16, 0);
        bytes.extend(2_u16.to_le_bytes()); // ET_EXEC
        bytes.extend(62_u16.to_le_bytes()); // EM_X86_64
        bytes.extend(1_u32.to_le_bytes());
        bytes.extend(0x40_1000_u64.to_le_bytes()); // entry
        bytes.extend(64_u64.to_le_bytes()); // phoff
        bytes.extend(shoff.to_le_bytes());
        bytes.extend(0_u32.to_le_bytes());
        for half in [64_u16, 56, phnum, 64, shnum, 0] {
            bytes.extend(half.to_le_bytes());
        }
        bytes
    }

    fn load(bytes: &mut Vec<u8>, vaddr: u64, filesz: u64) {
        bytes.extend(PT_LOAD.to_le_bytes());
        bytes.extend((PF_X | 4).to_le_bytes());
        for word in [0, vaddr, vaddr, filesz, filesz, 0x1000] {
            bytes.extend(word.to_le_bytes());
        }
    }

    #[test]
    fn reads_the_program_headers() {
        let mut bytes = header(1, 0, 0);
        load(&mut bytes, 0x40_0000, 0x2000);
        let elf = parse(&bytes).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!((elf.machine, elf.entry, elf.is_64), (62, 0x40_1000, true));
        assert_eq!(elf.programs.len(), 1);
        assert_eq!(elf.programs.first().map(|ph| ph.vaddr), Some(0x40_0000));
    }

    /// A section table past the end of the file costs the sections, not
    /// the file: a loader never reads it.
    #[test]
    fn a_section_table_outside_the_file_is_left_out() {
        let mut bytes = header(1, 0xdead_beef, 40);
        load(&mut bytes, 0x40_0000, 0x2000);
        let elf = parse(&bytes).unwrap_or_else(|e| panic!("{e}"));
        assert!(elf.sections.is_empty());
        assert_eq!(elf.programs.len(), 1);
    }

    /// More program headers claimed than the file holds: the ones there.
    #[test]
    fn a_truncated_table_yields_what_was_read() {
        let mut bytes = header(9, 0, 0);
        load(&mut bytes, 0x40_0000, 0x2000);
        load(&mut bytes, 0x60_0000, 0x1000);
        let elf = parse(&bytes).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(elf.programs.len(), 2);
    }

    #[test]
    fn rejects_what_is_no_elf() {
        assert!(parse(b"\x7fELF").is_err());
        assert!(parse(b"\x7fELF\x03\x01").is_err());
        assert!(parse(b"\x7fELF\x02\x01\x01\0").is_err());
    }
}
