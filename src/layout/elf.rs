//! The parts of an ELF file recovery uses, read leniently: each header and
//! table is read on its own, and one that is truncated or points outside
//! the file is cut short or left out rather than failing the whole file.
//! The loader reads only the ELF header and program headers, so a file can
//! run with a section table that no strict parser accepts.

use std::collections::{HashMap, HashSet};

use super::Error;
use super::limits;
use super::read::{self, Reader};

pub(super) const ET_REL: u16 = 1;

pub(super) const EM_SPARC: u16 = 2;
pub(super) const EM_386: u16 = 3;
pub(super) const EM_68K: u16 = 4;
pub(super) const EM_MIPS: u16 = 8;
pub(super) const EM_MIPS_RS3_LE: u16 = 10;
pub(super) const EM_SPARC32PLUS: u16 = 18;
pub(super) const EM_PPC: u16 = 20;
pub(super) const EM_PPC64: u16 = 21;
pub(super) const EM_S390: u16 = 22;
pub(super) const EM_MCORE: u16 = 39;
pub(super) const EM_ARM: u16 = 40;
pub(super) const EM_SH: u16 = 42;
pub(super) const EM_SPARCV9: u16 = 43;
pub(super) const EM_X86_64: u16 = 62;
pub(super) const EM_OPENRISC: u16 = 92;
pub(super) const EM_ARC_COMPACT: u16 = 93;
pub(super) const EM_XTENSA: u16 = 94;
pub(super) const EM_ALTERA_NIOS2: u16 = 113;
pub(super) const EM_AARCH64: u16 = 183;
pub(super) const EM_MICROBLAZE: u16 = 189;
pub(super) const EM_ARC_COMPACT2: u16 = 195;
pub(super) const EM_RISCV: u16 = 243;
pub(super) const EM_BPF: u16 = 247;
pub(super) const EM_CSKY: u16 = 252;
pub(super) const EM_LOONGARCH: u16 = 258;
/// MicroBlaze's number before it had one.
pub(super) const EM_MICROBLAZE_OLD: u16 = 0xbaab;

pub(super) const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
pub(super) const PF_X: u32 = 1;
const SHT_SYMTAB: u32 = 2;
const SHT_RELA: u32 = 4;
const SHT_DYNAMIC: u32 = 6;
pub(super) const SHT_NOBITS: u32 = 8;
const SHT_REL: u32 = 9;
const SHT_DYNSYM: u32 = 11;
const SHT_GNU_VERNEED: u32 = 0x6fff_fffe;
const SHT_GNU_VERSYM: u32 = 0x6fff_ffff;
pub(super) const SHF_WRITE: u64 = 1;
pub(super) const SHF_ALLOC: u64 = 2;
pub(super) const SHF_EXECINSTR: u64 = 4;
pub(super) const STT_OBJECT: u8 = 1;
pub(super) const STT_FUNC: u8 = 2;
pub(super) const STT_SECTION: u8 = 3;
pub(super) const STT_FILE: u8 = 4;
pub(super) const STB_GLOBAL: u8 = 1;
pub(super) const STB_WEAK: u8 = 2;
/// A global symbol the dynamic linker keeps one definition of
/// process-wide.
pub(super) const STB_GNU_UNIQUE: u8 = 10;
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
pub(super) const DT_INIT: u64 = 12;
pub(super) const DT_FINI: u64 = 13;
const DT_REL: u64 = 17;
const DT_RELSZ: u64 = 18;
const DT_PLTREL: u64 = 20;
const DT_JMPREL: u64 = 23;
pub(super) const DT_INIT_ARRAY: u64 = 25;
pub(super) const DT_FINI_ARRAY: u64 = 26;
pub(super) const DT_INIT_ARRAYSZ: u64 = 27;
pub(super) const DT_FINI_ARRAYSZ: u64 = 28;
pub(super) const DT_PREINIT_ARRAY: u64 = 32;
pub(super) const DT_PREINIT_ARRAYSZ: u64 = 33;
const DT_GNU_HASH: u64 = 0x6fff_fef5;
const DT_VERSYM: u64 = 0x6fff_fff0;
const DT_VERNEED: u64 = 0x6fff_fffe;
const DT_VERNEEDNUM: u64 = 0x6fff_ffff;
/// Version indexes 0 and 1 are local and global: no version, no file.
const FIRST_VERSION: u16 = 2;
/// MIPS: the GOT's entries before the first symbol's, and the first
/// dynamic symbol with a GOT entry (each after it has one, in order).
pub(super) const DT_MIPS_LOCAL_GOTNO: u64 = 0x7000_000a;
pub(super) const DT_MIPS_GOTSYM: u64 = 0x7000_0013;

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
    /// `STB_*`: the high four bits of `st_info`.
    pub(super) bind: u8,
    pub(super) shndx: u16,
    pub(super) value: u64,
    pub(super) size: u64,
    /// For an undefined dynamic symbol of a version the binary requires,
    /// the file the version-requirement table names for it (`libc.so.6`).
    pub(super) library: Option<String>,
}

pub(super) struct Reloc {
    pub(super) offset: u64,
    pub(super) kind: u32,
    pub(super) symbol: usize,
    /// Present in `RELA` entries; a `REL` entry's addend is at the place.
    pub(super) addend: Option<i64>,
}

/// The ELF header's fields past the identification bytes.
struct Header {
    kind: u16,
    machine: u16,
    entry: u64,
    phoff: u64,
    shoff: u64,
    flags: u32,
    phentsize: u16,
    phnum: u16,
    shentsize: u16,
    shnum: u16,
    shstrndx: u16,
}

impl Header {
    fn read(r: &Reader<'_>, is_64: bool) -> Option<Self> {
        let (kind, machine) = (r.u16(16)?, r.u16(18)?);
        Some(if is_64 {
            Self {
                kind,
                machine,
                entry: r.u64(24)?,
                phoff: r.u64(32)?,
                shoff: r.u64(40)?,
                flags: r.u32(48)?,
                phentsize: r.u16(54)?,
                phnum: r.u16(56)?,
                shentsize: r.u16(58)?,
                shnum: r.u16(60)?,
                shstrndx: r.u16(62)?,
            }
        } else {
            Self {
                kind,
                machine,
                entry: u64::from(r.u32(24)?),
                phoff: u64::from(r.u32(28)?),
                shoff: u64::from(r.u32(32)?),
                flags: r.u32(36)?,
                phentsize: r.u16(42)?,
                phnum: r.u16(44)?,
                shentsize: r.u16(46)?,
                shnum: r.u16(48)?,
                shstrndx: r.u16(50)?,
            }
        })
    }
}

/// The ELF file in `bytes`, or why it is none: only an ELF header too short
/// or of no known class fails.
pub(super) fn parse(bytes: &[u8]) -> Result<Elf, Error> {
    let (is_64, big) = match (bytes.get(4), bytes.get(5)) {
        (Some(1), Some(1)) => (false, false),
        (Some(1), Some(2)) => (false, true),
        (Some(2), Some(1)) => (true, false),
        (Some(2), Some(2)) => (true, true),
        _ => return Err(Error::Unsupported("ELF class or byte order")),
    };
    let r = Reader::new(bytes, big);
    let header = Header::read(&r, is_64).ok_or(Error::Truncated("ELF header"))?;

    let programs = table(
        header.phoff,
        header.phentsize,
        header.phnum,
        if is_64 { 56 } else { 32 },
    )
    .map_while(|at| program(&r.at(at), is_64))
    .collect();
    let (names, mut sections): (Vec<u32>, Vec<Section>) = table(
        header.shoff,
        header.shentsize,
        header.shnum,
        if is_64 { 64 } else { 40 },
    )
    .map_while(|at| section(&r.at(at), is_64))
    .unzip();
    if let Some(strings) = sections
        .get(usize::from(header.shstrndx))
        .map(|sh| (sh.offset, sh.size))
    {
        for (sh, &name) in sections.iter_mut().zip(&names) {
            sh.name = string(&r, strings, name);
        }
    }

    let mut elf = Elf {
        is_64,
        big,
        machine: header.machine,
        header_flags: header.flags,
        kind: header.kind,
        entry: header.entry,
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
    elf.read_versions(&r);
    elf.read_relocations(&r);
    Ok(elf)
}

/// The offsets of a header table's entries: `count` entries of `size`
/// bytes from `offset`, none when the entry size is smaller than `least`.
fn table(offset: u64, size: u16, count: u16, least: u16) -> impl Iterator<Item = u64> {
    let count = if offset == 0 || size < least {
        0
    } else {
        count
    };
    read::table(offset, u64::from(size), u64::from(count))
}

/// The offsets of a table's entries of `size` bytes in the `bytes` from
/// `offset`; none at offset zero, where the ELF header is.
fn entries(offset: u64, bytes: u64, size: u64) -> impl Iterator<Item = u64> {
    read::entries(offset, if offset == 0 { 0 } else { bytes }, size)
}

/// The program header `r` starts at.
fn program(r: &Reader<'_>, is_64: bool) -> Option<Program> {
    Some(if is_64 {
        Program {
            kind: r.u32(0)?,
            flags: r.u32(4)?,
            offset: r.u64(8)?,
            vaddr: r.u64(16)?,
            filesz: r.u64(32)?,
        }
    } else {
        Program {
            kind: r.u32(0)?,
            offset: u64::from(r.u32(4)?),
            vaddr: u64::from(r.u32(8)?),
            filesz: u64::from(r.u32(16)?),
            flags: r.u32(24)?,
        }
    })
}

/// The section header `r` starts at, and its name's offset in the section
/// name table.
fn section(r: &Reader<'_>, is_64: bool) -> Option<(u32, Section)> {
    let word = |at32: u64, at64: u64| r.word(if is_64 { at64 } else { at32 }, is_64);
    let half = |at32: u64, at64: u64| r.u32(if is_64 { at64 } else { at32 });
    let section = Section {
        name: String::new(),
        kind: r.u32(4)?,
        flags: word(8, 8)?,
        addr: word(12, 16)?,
        offset: word(16, 24)?,
        size: word(20, 32)?,
        link: half(24, 40)?,
        info: half(28, 44)?,
        addralign: word(32, 48)?,
        entsize: word(36, 56)?,
    };
    Some((r.u32(0)?, section))
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
            .find_map(|ph| {
                let delta = addr.checked_sub(ph.vaddr).filter(|&d| d < ph.filesz)?;
                ph.offset.checked_add(delta)
            })
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
        let (entry, value) = if self.is_64 { (16, 8) } else { (8, 4) };
        entries(offset, size, entry)
            .map_while(|at| {
                let entry = r.at(at);
                let tag = entry.word(0, self.is_64)?;
                (tag != DT_NULL).then_some((tag, entry.word(value, self.is_64)?))
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
        entries(offset, size, entsize.max(least))
            .map_while(|at| {
                let entry = r.at(at);
                let (info, shndx, value, size) = if self.is_64 {
                    (entry.u8(4)?, entry.u16(6)?, entry.u64(8)?, entry.u64(16)?)
                } else {
                    (
                        entry.u8(12)?,
                        entry.u16(14)?,
                        u64::from(entry.u32(4)?),
                        u64::from(entry.u32(8)?),
                    )
                };
                Some(Symbol {
                    name: string(r, strings, entry.u32(0)?),
                    kind: info & 0xf,
                    bind: info >> 4,
                    shndx,
                    value,
                    size,
                    library: None,
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
            .and_then(|hash| r.at(hash).u32(4))
            .map(u64::from)
            .or_else(|| at(DT_GNU_HASH).and_then(|hash| gnu_hash_count(&r.at(hash), self.is_64)))
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

    /// Name each undefined dynamic symbol's library by its version: the
    /// version table (`.gnu.version`) gives each dynamic symbol's version
    /// index, and the version-requirement table (`.gnu.version_r`) the file
    /// each index is required from. Unversioned symbols name none. Read
    /// through the dynamic section, else the section table.
    fn read_versions(&mut self, r: &Reader<'_>) {
        let files = self.version_files(r);
        if files.is_empty() {
            return;
        }
        let versym = self
            .dynamic_value(DT_VERSYM)
            .and_then(|addr| self.offset_of(addr))
            .or_else(|| {
                self.sections
                    .iter()
                    .find(|sh| sh.kind == SHT_GNU_VERSYM)
                    .map(|sh| sh.offset)
            });
        let Some(versym) = versym else {
            return;
        };
        let versions = r.at(versym);
        for (i, symbol) in (0_u64..).zip(self.dynamic_symbols.iter_mut()) {
            if symbol.shndx != SHN_UNDEF {
                continue;
            }
            let Some(version) = i
                .checked_mul(2)
                .and_then(|at| versions.u16(at))
                .map(|v| v & 0x7fff)
            else {
                break;
            };
            if version >= FIRST_VERSION {
                symbol.library = files.get(&version).cloned();
            }
        }
    }

    /// Each required version's index, and the file it is required from.
    fn version_files(&self, r: &Reader<'_>) -> HashMap<u16, String> {
        let mut files = HashMap::new();
        let dynamic = (|| {
            let at = self.offset_of(self.dynamic_value(DT_VERNEED)?)?;
            let count = self.dynamic_value(DT_VERNEEDNUM)?;
            let strtab = self.offset_of(self.dynamic_value(DT_STRTAB)?)?;
            let strsz = self.dynamic_value(DT_STRSZ).unwrap_or(u64::MAX);
            Some((at, count, (strtab, strsz)))
        })();
        let table = dynamic.or_else(|| {
            let sh = self.sections.iter().find(|sh| sh.kind == SHT_GNU_VERNEED)?;
            let strings = usize::try_from(sh.link)
                .ok()
                .and_then(|i| self.sections.get(i))
                .map(|strtab| (strtab.offset, strtab.size))?;
            Some((sh.offset, u64::from(sh.info), strings))
        });
        let Some((mut at, count, strings)) = table else {
            return files;
        };
        // Entries chain by relative offsets; every one visited, file or
        // version, counts against one budget, so no chain runs long.
        let mut budget = limits::TABLE;
        for _ in 0..count {
            let need = r.at(at);
            let Some([version_count, file, aux, next]) = (|| {
                Some([
                    u32::from(need.u16(2)?),
                    need.u32(4)?,
                    need.u32(8)?,
                    need.u32(12)?,
                ])
            })() else {
                break;
            };
            let name = string(r, strings, file);
            let mut version = at.saturating_add(u64::from(aux));
            for _ in 0..version_count {
                budget = budget.saturating_sub(1);
                let aux = r.at(version);
                let (Some(index), Some(next_version)) = (aux.u16(6), aux.u32(12)) else {
                    break;
                };
                files.insert(index & 0x7fff, name.clone());
                if next_version == 0 || budget == 0 {
                    break;
                }
                version = version.saturating_add(u64::from(next_version));
            }
            budget = budget.saturating_sub(1);
            if next == 0 || budget == 0 {
                break;
            }
            at = at.saturating_add(u64::from(next));
        }
        files
    }

    /// The dynamic linker's relocations, by the dynamic section (by the
    /// section table when it names none), and an object's relocation
    /// sections. Section headers may point many times at one table: each
    /// file range is read once, and all within [`limits::RELOCATIONS`].
    fn read_relocations(&mut self, r: &Reader<'_>) {
        let mut budget = limits::RELOCATIONS;
        let at = |tag| {
            self.dynamic_value(tag)
                .and_then(|addr| self.offset_of(addr))
        };
        let size = |tag| self.dynamic_value(tag).unwrap_or(0);
        let mut dynamic = Vec::new();
        if let Some(offset) = at(DT_JMPREL) {
            let rela = self.dynamic_value(DT_PLTREL) == Some(DT_RELA);
            dynamic.extend(self.reloc_table(r, offset, size(DT_PLTRELSZ), rela, &mut budget));
        }
        if let Some(offset) = at(DT_RELA) {
            dynamic.extend(self.reloc_table(r, offset, size(DT_RELASZ), true, &mut budget));
        }
        if let Some(offset) = at(DT_REL) {
            dynamic.extend(self.reloc_table(r, offset, size(DT_RELSZ), false, &mut budget));
        }

        let dynsym = self.sections.iter().position(|sh| sh.kind == SHT_DYNSYM);
        let mut relocations = Vec::new();
        let mut seen = HashSet::new();
        for sh in &self.sections {
            let rela = match sh.kind {
                SHT_RELA => true,
                SHT_REL => false,
                _ => continue,
            };
            let for_loader = dynsym.is_some() && usize::try_from(sh.link).ok() == dynsym;
            // The dynamic section's tables stand in for the loader's.
            if (for_loader && !dynamic.is_empty()) || !seen.insert((sh.offset, sh.size)) {
                continue;
            }
            let entries = self.reloc_table(r, sh.offset, sh.size, rela, &mut budget);
            if for_loader {
                dynamic.extend(entries);
            } else if let Ok(target) = usize::try_from(sh.info) {
                relocations.push((target, entries));
            }
        }
        self.relocations = relocations;
        self.dynamic_relocations = dynamic;
    }

    /// The relocation table of `size` bytes at `offset`, spending `budget`.
    fn reloc_table(
        &self,
        r: &Reader<'_>,
        offset: u64,
        size: u64,
        rela: bool,
        budget: &mut usize,
    ) -> Vec<Reloc> {
        // Offset, info and, for RELA, addend: one word each.
        let (info_at, addend_at): (u64, u64) = if self.is_64 { (8, 16) } else { (4, 8) };
        let entry = if rela {
            addend_at.saturating_add(info_at)
        } else {
            addend_at
        };
        let relocs: Vec<Reloc> = entries(offset, size, entry)
            .take(*budget)
            .map_while(|at| {
                let entry = r.at(at);
                let offset = entry.word(0, self.is_64)?;
                let info = entry.word(info_at, self.is_64)?;
                let addend = if rela {
                    let raw = entry.word(addend_at, self.is_64)?;
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
            .collect();
        *budget = budget.saturating_sub(relocs.len());
        relocs
    }
}

/// The number of symbols the `DT_GNU_HASH` table `r` starts at covers: one
/// past the last symbol any bucket's chain reaches.
fn gnu_hash_count(r: &Reader<'_>, is_64: bool) -> Option<u64> {
    let buckets = u64::from(r.u32(0)?).min(limits::TABLE);
    let offset = u64::from(r.u32(4)?);
    let blooms = u64::from(r.u32(8)?).min(limits::TABLE);
    let words = blooms
        .checked_mul(if is_64 { 8 } else { 4 })?
        .checked_add(16)?;
    let last = read::table(words, 4, buckets)
        .filter_map(|at| r.u32(at))
        .max()
        .map(u64::from)?;
    if last < offset {
        return Some(offset);
    }
    let chains = words.checked_add(buckets.checked_mul(4)?)?;
    // The chain ends at the entry whose low bit is set.
    let mut symbol = last;
    for _ in 0..limits::TABLE {
        let index = symbol.checked_sub(offset)?;
        let value = r.u32(chains.checked_add(index.checked_mul(4)?)?)?;
        symbol = symbol.checked_add(1)?;
        if value & 1 != 0 {
            break;
        }
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

    /// One section header.
    fn section_header(
        kind: u32,
        offset: u64,
        size: u64,
        link: u32,
        info: u32,
        entsize: u64,
    ) -> Vec<u8> {
        let mut bytes = 0_u32.to_le_bytes().to_vec();
        bytes.extend(kind.to_le_bytes());
        for word in [0, 0, offset, size] {
            bytes.extend(word.to_le_bytes());
        }
        bytes.extend(link.to_le_bytes());
        bytes.extend(info.to_le_bytes());
        bytes.extend(0_u64.to_le_bytes());
        bytes.extend(entsize.to_le_bytes());
        bytes
    }

    /// An undefined symbol of a required version names the file the
    /// version is required from; an unversioned one names none.
    #[test]
    fn versioned_imports_name_their_library() {
        let strings = b"\0libc.so.6\0puts\0open\0GLIBC_2.2.5\0";
        let mut symbols = vec![0_u8; 24];
        for name in [11_u32, 16] {
            symbols.extend(name.to_le_bytes());
            symbols.extend([0x12, 0, 0, 0]); // global function, undefined
            symbols.extend([0_u8; 16]);
        }
        let versions: Vec<u8> = [0_u16, 2, 1].iter().flat_map(|v| v.to_le_bytes()).collect();
        let mut needs = Vec::new();
        for half in [1_u16, 1] {
            needs.extend(half.to_le_bytes());
        }
        for word in [1_u32, 16, 0, 0, 0] {
            needs.extend(word.to_le_bytes());
        }
        needs.truncate(16);
        needs.extend(0_u32.to_le_bytes()); // vna_hash
        needs.extend(0_u16.to_le_bytes()); // vna_flags
        needs.extend(2_u16.to_le_bytes()); // vna_other: the index
        needs.extend(21_u32.to_le_bytes()); // vna_name
        needs.extend(0_u32.to_le_bytes()); // vna_next

        let tables: [&[u8]; 4] = [&symbols, strings, &versions, &needs];
        let mut at = 0x100_u64;
        let mut offsets = Vec::new();
        for table in tables {
            offsets.push(at);
            at += table.len() as u64;
        }
        let shoff = at.next_multiple_of(8);
        let mut bytes = header(0, shoff, 5);
        bytes.resize(0x100, 0);
        for table in tables {
            bytes.extend_from_slice(table);
        }
        bytes.resize(usize::try_from(shoff).unwrap_or(0), 0);
        bytes.extend(section_header(0, 0, 0, 0, 0, 0));
        bytes.extend(section_header(
            SHT_DYNSYM,
            offsets[0],
            symbols.len() as u64,
            2,
            1,
            24,
        ));
        bytes.extend(section_header(3, offsets[1], strings.len() as u64, 0, 0, 0));
        bytes.extend(section_header(SHT_GNU_VERSYM, offsets[2], 6, 1, 0, 2));
        bytes.extend(section_header(
            SHT_GNU_VERNEED,
            offsets[3],
            needs.len() as u64,
            2,
            1,
            0,
        ));

        let elf = parse(&bytes).unwrap_or_else(|e| panic!("{e}"));
        let named: Vec<(&str, Option<&str>)> = elf
            .dynamic_symbols
            .iter()
            .skip(1)
            .map(|s| (s.name.as_str(), s.library.as_deref()))
            .collect();
        assert_eq!(named, [("puts", Some("libc.so.6")), ("open", None)]);
    }

    /// 65,535 section headers pointing at one table of 65,536 relocations
    /// (and as many again at slightly shorter views of it) claim billions:
    /// the table is read once, the views within one budget.
    #[test]
    fn relocation_tables_share_one_budget() {
        let entries = 1_usize << 16;
        let shoff = 0x40 + 24 * entries as u64;
        let mut bytes = header(0, shoff, u16::MAX);
        bytes.resize(usize::try_from(shoff).unwrap_or(0), 0);
        for i in 0..u64::from(u16::MAX) {
            // Even headers repeat the whole table; odd ones each a view
            // shorter by one entry.
            let size = if i % 2 == 0 {
                24 * entries as u64
            } else {
                24 * (entries as u64 - i)
            };
            bytes.extend(section_header(SHT_RELA, 0x40, size, 0, 1, 24));
        }
        let start = std::time::Instant::now();
        let elf = parse(&bytes).unwrap_or_else(|e| panic!("{e}"));
        let read: usize = elf.relocations.iter().map(|(_, relocs)| relocs.len()).sum();
        assert!(read <= limits::RELOCATIONS, "{read}");
        assert!(read >= entries);
        assert!(start.elapsed().as_secs() < 10);
    }

    #[test]
    fn rejects_what_is_no_elf() {
        assert!(parse(b"\x7fELF").is_err());
        assert!(parse(b"\x7fELF\x03\x01").is_err());
        assert!(parse(b"\x7fELF\x02\x01\x01\0").is_err());
    }
}
