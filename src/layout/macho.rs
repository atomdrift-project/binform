//! The parts of a Mach-O file recovery uses, read leniently: the load
//! commands are walked one by one, and a command, section or table that is
//! truncated or points outside the file is cut short or left out rather
//! than failing the whole file. Universal (fat) headers are read here too.

use std::collections::HashSet;

use super::read::{self, Reader};
use super::{Error, file_range, limits};

const MH_MAGIC: u32 = 0xfeed_face;
const MH_MAGIC_64: u32 = 0xfeed_facf;
pub(super) const MH_OBJECT: u32 = 1;

const LC_SEGMENT: u32 = 0x1;
const LC_SYMTAB: u32 = 0x2;
const LC_UNIXTHREAD: u32 = 0x5;
const LC_DYSYMTAB: u32 = 0xb;
const LC_LOAD_DYLIB: u32 = 0xc;
const LC_SEGMENT_64: u32 = 0x19;
const LC_LAZY_LOAD_DYLIB: u32 = 0x20;
const LC_DYLD_INFO: u32 = 0x22;
const LC_FUNCTION_STARTS: u32 = 0x26;
const LC_LOAD_WEAK_DYLIB: u32 = 0x8000_0018;
const LC_REEXPORT_DYLIB: u32 = 0x8000_001f;
const LC_DYLD_INFO_ONLY: u32 = 0x8000_0022;
const LC_LOAD_UPWARD_DYLIB: u32 = 0x8000_0023;
const LC_MAIN: u32 = 0x8000_0028;
const LC_DYLD_EXPORTS_TRIE: u32 = 0x8000_0033;
const LC_DYLD_CHAINED_FIXUPS: u32 = 0x8000_0034;
const EXPORT_SYMBOL_FLAGS_REEXPORT: u64 = 0x8;

pub(super) const CPU_TYPE_X86: u32 = 7;
pub(super) const CPU_TYPE_X86_64: u32 = 0x0100_0007;
pub(super) const CPU_TYPE_ARM64: u32 = 0x0100_000c;

const SECTION_TYPE: u32 = 0xff;
const S_ZEROFILL: u32 = 0x1;
pub(super) const S_NON_LAZY_SYMBOL_POINTERS: u32 = 0x6;
pub(super) const S_LAZY_SYMBOL_POINTERS: u32 = 0x7;
pub(super) const S_SYMBOL_STUBS: u32 = 0x8;
const S_GB_ZEROFILL: u32 = 0xc;
const S_THREAD_LOCAL_ZEROFILL: u32 = 0x12;
const S_ATTR_PURE_INSTRUCTIONS: u32 = 0x8000_0000;
const S_ATTR_SOME_INSTRUCTIONS: u32 = 0x0000_0400;
const VM_PROT_EXECUTE: u32 = 0x4;

/// The indirect symbol table's entries for local and absolute symbols,
/// which name no import.
pub(super) const INDIRECT_SYMBOL_LOCAL_OR_ABS: u32 = 0xc000_0000;

/// `n_type` bits: a debugging entry when any of these is set.
const N_STAB: u8 = 0xe0;
pub(super) const N_EXT: u8 = 0x01;
pub(super) const N_PEXT: u8 = 0x10;
pub(super) const N_TYPE: u8 = 0x0e;
pub(super) const N_UNDF: u8 = 0x0;
pub(super) const N_SECT: u8 = 0xe;

/// A Java class file shares the universal header's magic number, and its
/// "slice count" is its major version, 45 or more: no universal binary has
/// that many slices.
const JAVA_MAJOR_VERSIONS: u32 = 45;

pub(super) struct MachO {
    pub(super) is_64: bool,
    pub(super) big: bool,
    pub(super) cputype: u32,
    pub(super) filetype: u32,
    pub(super) segments: Vec<Segment>,
    pub(super) sections: Vec<Section>,
    /// `LC_SYMTAB`'s entries, by index.
    pub(super) symbols: Vec<Symbol>,
    /// `LC_DYSYMTAB`'s indirect symbol table: symbol indexes.
    pub(super) indirect: Vec<u32>,
    /// `LC_FUNCTION_STARTS`'s data: file offset and size.
    pub(super) function_starts: Option<(u64, u64)>,
    /// The entry point's address; zero for none.
    pub(super) entry: u64,
    /// The libraries the load commands name, in order: what a symbol's
    /// two-level namespace ordinal (from 1) counts.
    pub(super) dylibs: Vec<String>,
    /// The export trie: file offset and size.
    pub(super) exports_trie: Option<(u64, u64)>,
    /// `LC_DYLD_INFO`'s bind and lazy-bind opcode streams: file offset and
    /// size of each.
    pub(super) binds: Vec<(u64, u64)>,
    /// `LC_DYLD_CHAINED_FIXUPS`' data: file offset and size.
    pub(super) chained_fixups: Option<(u64, u64)>,
}

pub(super) struct Segment {
    name: [u8; 16],
    pub(super) vmaddr: u64,
    fileoff: u64,
}

/// One section header. `reserved1` is a pointer or stub section's index
/// into the indirect symbol table, `reserved2` a stub section's stub size.
pub(super) struct Section {
    name: [u8; 16],
    segment: [u8; 16],
    /// Its segment's initial protection: `VM_PROT_READ` 1, `WRITE` 2,
    /// `EXECUTE` 4.
    pub(super) protection: u32,
    pub(super) addr: u64,
    pub(super) size: u64,
    pub(super) offset: u64,
    /// File offset and count of the section's relocations (objects only).
    pub(super) reloff: u32,
    pub(super) nreloc: u32,
    pub(super) flags: u32,
    pub(super) reserved1: u32,
    pub(super) reserved2: u32,
    /// Its segment is executable and it holds instructions.
    pub(super) code: bool,
}

pub(super) struct Symbol {
    pub(super) name: String,
    pub(super) n_type: u8,
    /// For an undefined symbol in a two-level namespace image, the library
    /// it binds to in the high byte.
    pub(super) n_desc: u16,
    pub(super) n_value: u64,
}

impl Symbol {
    pub(super) fn is_stab(&self) -> bool {
        self.n_type & N_STAB != 0
    }
}

/// A fixed-size name field's text: up to its first NUL.
fn text(name: &[u8; 16]) -> &[u8] {
    name.split(|&b| b == 0).next().unwrap_or_default()
}

impl Segment {
    pub(super) fn named(&self, name: &str) -> bool {
        text(&self.name) == name.as_bytes()
    }
}

impl Section {
    pub(super) fn named(&self, name: &str) -> bool {
        text(&self.name) == name.as_bytes()
    }

    /// `__SEGMENT.__section`.
    pub(super) fn full_name(&self) -> String {
        let lossy = |name| String::from_utf8_lossy(text(name)).into_owned();
        format!("{}.{}", lossy(&self.segment), lossy(&self.name))
    }

    /// `S_*`: what the section holds.
    pub(super) fn kind(&self) -> u32 {
        self.flags & SECTION_TYPE
    }

    /// The loader fills the section with zeros: the file holds none of it.
    pub(super) fn zerofill(&self) -> bool {
        matches!(
            self.kind(),
            S_ZEROFILL | S_GB_ZEROFILL | S_THREAD_LOCAL_ZEROFILL
        )
    }
}

impl MachO {
    /// The `__TEXT` segment, which the image's offsets count from.
    pub(super) fn text(&self) -> Option<&Segment> {
        self.segments.iter().find(|segment| segment.named("__TEXT"))
    }

    /// The address of the `__TEXT` segment.
    pub(super) fn text_base(&self) -> Option<u64> {
        self.text().map(|segment| segment.vmaddr)
    }

    /// The section called `name`.
    pub(super) fn section(&self, name: &str) -> Option<&Section> {
        self.sections.iter().find(|section| section.named(name))
    }
}

/// The Mach-O file in `bytes`, or why it is none: only a header too short
/// or of no known magic number fails. The load commands are walked as far
/// as the header's count and size of them say, each within its own size.
pub(super) fn parse(bytes: &[u8]) -> Result<MachO, Error> {
    let magic = Reader::new(bytes, false)
        .u32(0)
        .ok_or(Error::Truncated("Mach-O header"))?;
    let (is_64, big) = match magic {
        MH_MAGIC => (false, false),
        MH_MAGIC_64 => (true, false),
        _ if magic.swap_bytes() == MH_MAGIC => (false, true),
        _ if magic.swap_bytes() == MH_MAGIC_64 => (true, true),
        _ => return Err(Error::BadMagic),
    };
    let r = Reader::new(bytes, big);
    let [cputype, filetype, ncmds, sizeofcmds] = r
        .u32s([4, 12, 16, 20])
        .ok_or(Error::Truncated("Mach-O header"))?;
    let mut macho = MachO {
        is_64,
        big,
        cputype,
        filetype,
        segments: Vec::new(),
        sections: Vec::new(),
        symbols: Vec::new(),
        indirect: Vec::new(),
        function_starts: None,
        entry: 0,
        dylibs: Vec::new(),
        exports_trie: None,
        binds: Vec::new(),
        chained_fixups: None,
    };
    let (mut main, mut thread) = (None, None);
    let mut at: u64 = if is_64 { 32 } else { 28 };
    let end = at.saturating_add(u64::from(sizeofcmds));
    // A (file offset, size) pair at `field` in the command; `None` for an
    // empty one.
    let range = |c: &Reader<'_>, field: u64| {
        let offset = c.u32(field)?;
        let size = c.at(field).u32(4).filter(|&size| size != 0)?;
        Some((u64::from(offset), u64::from(size)))
    };
    for _ in 0..u64::from(ncmds).min(limits::LOAD_COMMANDS) {
        if at >= end {
            break;
        }
        let (Some(cmd), Some(size)) = (r.at(at).u32(0), r.at(at).u32(4)) else {
            break;
        };
        // One smaller than its own header is no command: dyld stops there.
        if size < 8 {
            break;
        }
        // Each command reads its own bytes, not the next one's.
        let c = Reader::new(file_range(bytes, at, u64::from(size)), big);
        match cmd {
            LC_SEGMENT | LC_SEGMENT_64 => macho.read_segment(&c, size, cmd == LC_SEGMENT_64),
            LC_SYMTAB => macho.read_symbols(&r, &c),
            // The indirect symbol table.
            LC_DYSYMTAB => {
                if let (Some(offset), Some(count)) = (c.u32(56), c.u32(60)) {
                    macho.indirect = read::table(u64::from(offset), 4, u64::from(count))
                        .map_while(|at| r.u32(at))
                        .collect();
                }
            }
            LC_DYLD_INFO | LC_DYLD_INFO_ONLY => {
                // Bind at 16, weak bind at 24 (by name alone, no library),
                // lazy bind at 32; the export trie at 40.
                macho.binds = [16, 32]
                    .into_iter()
                    .filter_map(|field| range(&c, field))
                    .collect();
                macho.exports_trie = range(&c, 40).or(macho.exports_trie);
            }
            LC_DYLD_CHAINED_FIXUPS => {
                macho.chained_fixups = range(&c, 8);
            }
            LC_DYLD_EXPORTS_TRIE => {
                macho.exports_trie = range(&c, 8);
            }
            LC_LOAD_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB | LC_LAZY_LOAD_DYLIB
            | LC_LOAD_UPWARD_DYLIB => {
                let name = c.u32(8).map(|offset| c.name(u64::from(offset)));
                macho.dylibs.push(name.unwrap_or_default().into_owned());
            }
            LC_FUNCTION_STARTS => macho.function_starts = range(&c, 8),
            // dyld honours the first of each.
            LC_MAIN if main.is_none() => main = c.u64(8),
            LC_UNIXTHREAD if thread.is_none() => thread = thread_pc(&c, cputype),
            _ => {}
        }
        at = at.saturating_add(u64::from(size));
    }
    // dyld prefers LC_MAIN, an offset from the start of `__TEXT`.
    macho.entry = match (main, thread) {
        (Some(offset), _) => macho.text().map_or(0, |text| {
            text.vmaddr.wrapping_sub(text.fileoff).wrapping_add(offset)
        }),
        (None, Some(pc)) => pc,
        (None, None) => 0,
    };
    Ok(macho)
}

/// The program counter the `LC_UNIXTHREAD` command `c` starts at, read from
/// the thread state as the CPU type lays it out (dyld ignores the flavour).
fn thread_pc(c: &Reader<'_>, cputype: u32) -> Option<u64> {
    let words = u64::from(c.u32(12)?);
    let state = c.at(16);
    let (pc, wide) = match cputype {
        CPU_TYPE_X86 => (40_u64, false),
        CPU_TYPE_X86_64 => (128, true),
        CPU_TYPE_ARM64 => (256, true),
        _ => return None,
    };
    let width = if wide { 8 } else { 4 };
    if words.saturating_mul(4) < pc.saturating_add(width) {
        return None;
    }
    let low = u64::from(state.u32(pc)?);
    if !wide {
        return Some(low);
    }
    // Two words, low first, in the file's byte order.
    let high = u64::from(state.at(pc).u32(4)?);
    Some(low | high << 32)
}

impl MachO {
    /// The segment command `c` of `size` bytes, and as many of the sections
    /// it claims as fit in it, up to [`limits::SECTIONS`] in all.
    fn read_segment(&mut self, c: &Reader<'_>, size: u32, wide: bool) {
        // A 64-bit command widens addresses and sizes to eight bytes, which
        // moves the fields after them.
        let word = |r: &Reader<'_>, at32, at64| r.word(if wide { at64 } else { at32 }, wide);
        let field = |r: &Reader<'_>, at32, at64| r.u32(if wide { at64 } else { at32 });
        let (Some(name), Some(vmaddr), Some(fileoff), Some(initprot), Some(nsects)) = (
            c.array(8),
            word(c, 24, 24),
            word(c, 32, 40),
            field(c, 44, 60),
            field(c, 48, 64),
        ) else {
            return;
        };
        self.segments.push(Segment {
            name,
            vmaddr,
            fileoff,
        });
        let executable = initprot & VM_PROT_EXECUTE != 0;
        let (header, entry) = if wide { (72, 80) } else { (56, 68) };
        let fit = u64::from(size)
            .saturating_sub(header)
            .checked_div(entry)
            .unwrap_or(0)
            .min(u64::from(nsects))
            .min(limits::SECTIONS.saturating_sub(self.sections.len()) as u64);
        for at in read::table(header, entry, fit) {
            let s = c.at(at);
            let (
                Some(name),
                Some(segment),
                Some(addr),
                Some(size),
                Some(offset),
                Some([reloff, nreloc, flags, reserved1, reserved2]),
            ) = (
                s.array(0),
                s.array(16),
                word(&s, 32, 32),
                word(&s, 36, 40),
                field(&s, 40, 48),
                s.u32s(if wide {
                    [56, 60, 64, 68, 72]
                } else {
                    [48, 52, 56, 60, 64]
                }),
            )
            else {
                break;
            };
            self.sections.push(Section {
                name,
                segment,
                protection: initprot,
                addr,
                size,
                offset: u64::from(offset),
                reloff,
                nreloc,
                flags,
                reserved1,
                reserved2,
                code: executable
                    && flags & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS) != 0,
            });
        }
    }

    /// The symbol table `LC_SYMTAB` command `c` names in the file `r`.
    fn read_symbols(&mut self, r: &Reader<'_>, c: &Reader<'_>) {
        let Some([symoff, nsyms, stroff, strsize]) = c.u32s([8, 12, 16, 20]) else {
            return;
        };
        let stroff = u64::from(stroff);
        let size = if self.is_64 { 16 } else { 12 };
        // Every symbol may name the same long string: past a budget of name
        // bytes, symbols keep their values, not names.
        let mut names = limits::NAME_BYTES;
        self.symbols = read::table(u64::from(symoff), size, u64::from(nsyms))
            .map_while(|at| {
                let entry = r.at(at);
                let n_value = if self.is_64 {
                    entry.u64(8)?
                } else {
                    u64::from(entry.u32(8)?)
                };
                // An index past the string table names nothing.
                let strx = entry.u32(0)?;
                let name = if names == 0 || strx >= strsize {
                    String::new()
                } else {
                    r.name(stroff.saturating_add(u64::from(strx))).into_owned()
                };
                names = names.saturating_sub(name.len());
                Some(Symbol {
                    name,
                    n_type: entry.u8(4)?,
                    n_desc: entry.u16(6)?,
                    n_value,
                })
            })
            .collect();
    }
}

/// The symbols an export trie names, each with its offset from the image
/// base, or the library symbol it re-exports. Each node is visited at most
/// once, so a trie whose edges loop ends.
pub(super) fn exports_trie(trie: &[u8]) -> Vec<(String, Exported)> {
    let mut out = Vec::new();
    let mut visited = HashSet::new();
    let mut stack = vec![(0_usize, Vec::new())];
    // Name bytes built: each child copies its parent's prefix, so a chain of
    // terminal nodes costs the square of its length. Real names are short,
    // and a real trie's total well under a megabyte.
    let mut budget = limits::NAME_BYTES;
    let cstr = |at: usize| Reader::new(trie, false).cstr(at as u64);
    while let Some((node, prefix)) = stack.pop() {
        if !visited.insert(node) || visited.len() > limits::TRIE_NODES {
            continue;
        }
        let mut at = node;
        let Some(terminal) = read::uleb128(trie, &mut at) else {
            continue;
        };
        let children = at.saturating_add(usize::try_from(terminal).unwrap_or(usize::MAX));
        if terminal != 0
            && let Some(flags) = read::uleb128(trie, &mut at)
        {
            let exported = if flags & EXPORT_SYMBOL_FLAGS_REEXPORT == 0 {
                read::uleb128(trie, &mut at).map(Exported::At)
            } else {
                // The library's ordinal, then the name it exports there
                // (empty for the same name).
                read::uleb128(trie, &mut at).map(|ordinal| Exported::Reexport {
                    ordinal,
                    name: String::from_utf8_lossy(cstr(at)).into_owned(),
                })
            };
            if let Some(exported) = exported {
                out.push((String::from_utf8_lossy(&prefix).into_owned(), exported));
            }
        }
        let Some(&count) = trie.get(children) else {
            continue;
        };
        let mut at = children.saturating_add(1);
        for _ in 0..count {
            let Some(len) = trie
                .get(at..)
                .and_then(|rest| rest.iter().position(|&b| b == 0))
            else {
                break;
            };
            let edge = trie.get(at..at.saturating_add(len)).unwrap_or_default();
            at = at.saturating_add(len).saturating_add(1);
            let Some(child) = read::uleb128(trie, &mut at) else {
                break;
            };
            let size = prefix.len().saturating_add(edge.len());
            if size > limits::NAME_LEN || size > budget {
                continue;
            }
            budget = budget.saturating_sub(size);
            let mut name = prefix.clone();
            name.extend_from_slice(edge);
            if let Ok(child) = usize::try_from(child) {
                stack.push((child, name));
            }
        }
    }
    out
}

/// What an export trie entry exports.
pub(super) enum Exported {
    /// Code or data at this offset from the image's base.
    At(u64),
    /// Another library's symbol: the library's ordinal (from 1), and the
    /// name it has there, empty for the same.
    Reexport { ordinal: u64, name: String },
}

/// The library ordinal dyld binds each symbol to, by name, as the bind
/// opcode streams and the chained-fixup import table record it: what a
/// binary whose symbol table carries no two-level ordinal (Go's linker
/// writes none) says of its imports. Ordinals count the dylibs from 1;
/// zero and below are this image, the executable, and flat lookup. The
/// first binding of a name wins.
pub(super) fn bound_ordinals<'a>(bytes: &'a [u8], macho: &MachO) -> Vec<(String, i64)> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    // Name bytes looked at: every bind and import entry may name the same
    // long string, which costs a hash each time.
    let mut budget = limits::NAME_BYTES;
    let mut record = |name: &'a [u8], ordinal: i64| {
        budget = budget.saturating_sub(name.len());
        if budget > 0
            && !name.is_empty()
            && (seen.len() as u64) < limits::TABLE
            && seen.insert(name)
        {
            out.push((String::from_utf8_lossy(name).into_owned(), ordinal));
        }
    };
    for &(offset, size) in &macho.binds {
        bind_opcodes(file_range(bytes, offset, size), &mut record);
    }
    if let Some((offset, size)) = macho.chained_fixups {
        chained_imports(file_range(bytes, offset, size), macho.big, &mut record);
    }
    out
}

/// The (symbol, library ordinal) of each bind in a dyld bind opcode
/// stream. Addresses are not tracked: only which library each name binds
/// to. An unknown or truncated opcode ends the stream.
fn bind_opcodes<'a>(stream: &'a [u8], record: &mut impl FnMut(&'a [u8], i64)) {
    let mut at = 0;
    let mut ordinal = 0_i64;
    let mut symbol: &[u8] = &[];
    while let Some(&byte) = stream.get(at) {
        at = at.saturating_add(1);
        let immediate = byte & 0x0f;
        let skip = |at: &mut usize, n: usize| (0..n).all(|_| read::uleb128(stream, at).is_some());
        let ok = match byte & 0xf0 {
            // DONE ends a lazy-bind entry, not the stream; SET_TYPE_IMM.
            0x00 | 0x50 => true,
            // SET_DYLIB_ORDINAL_IMM
            0x10 => {
                ordinal = i64::from(immediate);
                true
            }
            // SET_DYLIB_ORDINAL_ULEB
            0x20 => read::uleb128(stream, &mut at)
                .map(|n| ordinal = i64::try_from(n).unwrap_or(0))
                .is_some(),
            // SET_DYLIB_SPECIAL_IMM: zero, or negative, sign-extended.
            0x30 => {
                ordinal = if immediate == 0 {
                    0
                } else {
                    i64::from((0xf0 | immediate).cast_signed())
                };
                true
            }
            // SET_SYMBOL_TRAILING_FLAGS_IMM: the name follows, to its NUL
            // however long it is; a long one is kept cut short.
            0x40 => {
                let rest = stream.get(at..).unwrap_or_default();
                match rest.iter().position(|&b| b == 0) {
                    Some(len) => {
                        let name = rest.get(..len).unwrap_or_default();
                        symbol = name.get(..limits::NAME_LEN).unwrap_or(name);
                        at = at.saturating_add(len).saturating_add(1);
                        true
                    }
                    None => false,
                }
            }
            // DO_BIND, DO_BIND_ADD_ADDR_IMM_SCALED
            0x90 | 0xb0 => {
                record(symbol, ordinal);
                true
            }
            // SET_ADDEND_SLEB, SET_SEGMENT_AND_OFFSET_ULEB, ADD_ADDR_ULEB:
            // a LEB128 number, signed or not, ends at the same byte.
            0x60..=0x80 => skip(&mut at, 1),
            // DO_BIND_ADD_ADDR_ULEB
            0xa0 => {
                record(symbol, ordinal);
                skip(&mut at, 1)
            }
            // DO_BIND_ULEB_TIMES_SKIPPING_ULEB
            0xc0 => {
                record(symbol, ordinal);
                skip(&mut at, 2)
            }
            // THREADED: SET_BIND_ORDINAL_TABLE_SIZE_ULEB, or APPLY.
            0xd0 => immediate != 0 || skip(&mut at, 1),
            _ => false,
        };
        if !ok {
            break;
        }
    }
}

/// The (symbol, library ordinal) of each entry of a chained-fixup import
/// table (`dyld_chained_fixups_header`), in any of its three formats. A
/// compressed symbol table is not read.
fn chained_imports<'a>(data: &'a [u8], big: bool, record: &mut impl FnMut(&'a [u8], i64)) {
    let r = Reader::new(data, big);
    // imports_offset, symbols_offset, imports_count, imports_format,
    // symbols_format.
    let Some([imports, symbols, count, format, 0]) = r.u32s([8, 12, 16, 20, 24]) else {
        return;
    };
    let size = match format {
        // DYLD_CHAINED_IMPORT, DYLD_CHAINED_IMPORT_ADDEND,
        // DYLD_CHAINED_IMPORT_ADDEND64.
        1 => 4,
        2 => 8,
        3 => 16,
        _ => return,
    };
    // The low byte (or, in the 64-bit format, half-word) is a signed ordinal.
    let small = |v: u32| i64::from(v.to_le_bytes()[0].cast_signed());
    for at in read::table(u64::from(imports), size, u64::from(count)) {
        let entry = if format == 3 {
            // Ordinal 16 bits, weak 1, reserved 15, name offset 32; then a
            // 64-bit addend.
            r.u64(at).map(|v| {
                let [low, high, ..] = v.to_le_bytes();
                (i64::from(i16::from_le_bytes([low, high])), v >> 32)
            })
        } else {
            // Ordinal 8 bits, weak 1, name offset 23; then, in the second
            // format, a 32-bit addend.
            r.u32(at).map(|v| (small(v), u64::from(v >> 9)))
        };
        let Some((ordinal, name)) = entry else {
            break;
        };
        record(r.cstr(u64::from(symbols).saturating_add(name)), ordinal);
    }
}

/// One slice of a universal binary: its CPU type and file range.
pub(super) struct Slice {
    pub(super) cputype: u32,
    pub(super) offset: u64,
    pub(super) size: u64,
}

/// The slices a universal header (`0xcafebabe`, or `0xcafebabf` with
/// 64-bit offsets) lists.
pub(super) fn fat(bytes: &[u8]) -> Result<Vec<Slice>, Error> {
    let r = Reader::new(bytes, true);
    let wide = match r.u32(0) {
        Some(0xcafe_babe) => false,
        Some(0xcafe_babf) => true,
        _ => return Err(Error::BadMagic),
    };
    let count = r.u32(4).ok_or(Error::Truncated("universal header"))?;
    if count >= JAVA_MAJOR_VERSIONS {
        return Err(Error::NotExecutable("a Java class file"));
    }
    let (entry, size_at) = if wide { (32, 16) } else { (20, 12) };
    Ok(read::table(8, entry, u64::from(count))
        .map_while(|at| {
            let slice = r.at(at);
            Some(Slice {
                cputype: slice.u32(0)?,
                offset: slice.word(8, wide)?,
                size: slice.word(size_at, wide)?,
            })
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 64-bit little-endian Mach-O header with `ncmds` commands in
    /// `commands`.
    fn header(ncmds: u32, commands: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for word in [MH_MAGIC_64, CPU_TYPE_ARM64, 0, 2, ncmds] {
            bytes.extend(word.to_le_bytes());
        }
        bytes.extend(u32::try_from(commands.len()).unwrap_or(0).to_le_bytes());
        bytes.extend([0; 8]);
        bytes.extend(commands);
        bytes
    }

    /// An `LC_SEGMENT_64` named `__TEXT` with `nsects` sections, of which
    /// the first is `__text`.
    fn text(nsects: u32) -> Vec<u8> {
        let mut command = Vec::new();
        command.extend(LC_SEGMENT_64.to_le_bytes());
        command.extend((72 + 80 * nsects).to_le_bytes());
        command.extend(b"__TEXT\0\0\0\0\0\0\0\0\0\0");
        for word in [0x1_0000_0000_u64, 0x4000, 0, 0x4000] {
            command.extend(word.to_le_bytes());
        }
        for word in [5_u32, 5, nsects, 0] {
            command.extend(word.to_le_bytes());
        }
        command.extend(b"__text\0\0\0\0\0\0\0\0\0\0");
        command.extend(b"__TEXT\0\0\0\0\0\0\0\0\0\0");
        for word in [0x1_0000_1000_u64, 0x100] {
            command.extend(word.to_le_bytes());
        }
        for word in [0x1000_u32, 2, 0, 0, 0x8000_0400, 0, 0, 0] {
            command.extend(word.to_le_bytes());
        }
        command
    }

    #[test]
    fn reads_segments_sections_and_the_entry() {
        let mut commands = text(1);
        for word in [LC_MAIN, 24] {
            commands.extend(word.to_le_bytes());
        }
        commands.extend(0x1010_u64.to_le_bytes());
        commands.extend(0_u64.to_le_bytes());
        let bytes = header(2, &commands);
        let macho = parse(&bytes).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            (macho.cputype, macho.is_64, macho.big),
            (CPU_TYPE_ARM64, true, false)
        );
        assert_eq!(macho.sections.len(), 1);
        let section = macho.sections.first();
        assert!(section.is_some_and(|s| s.named("__text") && s.code && s.addr == 0x1_0000_1000));
        assert_eq!(macho.entry, 0x1_0000_1010);
    }

    /// A command reads only its own bytes: a segment command too small for
    /// a segment's fields is none, not one made of the next command's.
    #[test]
    fn a_command_too_small_for_its_fields_reads_none_past_it() {
        let mut commands: Vec<u8> = [LC_SEGMENT_64, 16, 0, 0]
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect();
        commands.extend(text(1));
        let macho = parse(&header(2, &commands)).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!((macho.segments.len(), macho.sections.len()), (1, 1));
        assert_eq!(super::text(&macho.segments[0].name), b"__TEXT");
    }

    /// More sections and commands claimed than the file holds: the ones
    /// there.
    #[test]
    fn truncated_tables_yield_what_was_read() {
        let mut bytes = header(40, &text(9));
        bytes.extend([0; 7]);
        let macho = parse(&bytes).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(macho.segments.len(), 1);
        assert_eq!(macho.sections.len(), 1);
    }

    /// Commands past the size the header gives them are not read, and a
    /// segment's sections are those that fit in its command.
    #[test]
    fn commands_and_sections_stay_inside_their_sizes() {
        let mut commands = text(1);
        // Claims four sections in a command with room for one.
        commands[64..68].copy_from_slice(&4_u32.to_le_bytes());
        commands.extend(text(1));
        commands.extend(text(1));
        let mut bytes = header(3, &commands);
        bytes[20..24].copy_from_slice(&(2 * (72_u32 + 80)).to_le_bytes());
        let macho = parse(&bytes).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!((macho.segments.len(), macho.sections.len()), (2, 2));
    }

    /// More than 65,536 segment commands, one after another, each claiming
    /// every section there could be: none has room for any past its own
    /// header, and only the first 65,536 commands are read.
    #[test]
    fn overlapping_segment_commands_claim_no_sections() {
        let mut command = [0_u32; 18];
        command[0] = LC_SEGMENT_64;
        command[1] = 72;
        command[16] = u32::MAX; // nsects
        let commands: Vec<u8> = command
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .cycle()
            .take(72 << 16 | 4096)
            .collect();
        let bytes = header(u32::MAX, &commands);
        let start = std::time::Instant::now();
        let macho = parse(&bytes).unwrap_or_else(|e| panic!("{e}"));
        assert!(macho.sections.is_empty());
        assert_eq!(macho.segments.len() as u64, limits::LOAD_COMMANDS);
        assert!(start.elapsed().as_secs() < 5);
    }

    /// A symbol's name lies in the string table `LC_SYMTAB` sizes: an index
    /// past it names nothing, not whatever follows the table.
    #[test]
    fn symbol_names_lie_in_the_string_table() {
        let (symoff, strings) = (32 + 24, 32 + 24 + 2 * 16);
        let mut commands = Vec::new();
        for word in [LC_SYMTAB, 24, symoff, 2, strings, 4] {
            commands.extend(word.to_le_bytes());
        }
        for strx in [1_u32, 4] {
            commands.extend(strx.to_le_bytes());
            commands.extend([0x0f, 1, 0, 0]); // N_SECT | N_EXT, section 1
            commands.extend(0x1_0000_0000_u64.to_le_bytes());
        }
        commands.extend(b"\0_a\0_beyond\0");
        let bytes = header(1, &commands[..24]);
        let bytes = [bytes.as_slice(), &commands[24..]].concat();
        let macho = parse(&bytes).unwrap_or_else(|e| panic!("{e}"));
        let names: Vec<&str> = macho.symbols.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["_a", ""]);
    }

    /// Tables past the end of the file, and absurd counts, cost those
    /// tables only.
    #[test]
    fn tables_outside_the_file_are_left_out() {
        let mut commands = text(1);
        for word in [LC_SYMTAB, 24, 0xffff_0000, 0xffff_ffff, 0xffff_ff00, 16] {
            commands.extend(word.to_le_bytes());
        }
        let mut dysymtab = [0_u32; 20];
        dysymtab[0] = LC_DYSYMTAB;
        dysymtab[1] = 80;
        dysymtab[14] = 0x7fff_0000;
        dysymtab[15] = 0xffff_ffff;
        commands.extend(dysymtab.iter().flat_map(|w| w.to_le_bytes()));
        let bytes = header(3, &commands);
        let macho = parse(&bytes).unwrap_or_else(|e| panic!("{e}"));
        assert!(macho.symbols.is_empty() && macho.indirect.is_empty());
        assert_eq!(macho.sections.len(), 1);
    }

    #[test]
    fn reads_the_thread_state_pc() {
        let mut command = Vec::new();
        for word in [LC_UNIXTHREAD, 16 + 68 * 4, 6, 68] {
            command.extend(word.to_le_bytes());
        }
        let mut state = vec![0_u32; 68];
        state[64] = 0x0000_1234;
        state[65] = 0x1;
        command.extend(state.iter().flat_map(|w| w.to_le_bytes()));
        let bytes = header(1, &command);
        let macho = parse(&bytes).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(macho.entry, 0x1_0000_1234);
    }

    #[test]
    fn rejects_what_is_no_macho() {
        assert!(parse(b"\xcf\xfa").is_err());
        assert!(parse(b"\xcf\xfa\xed\xfe\x0c\0\0\x01").is_err());
        assert!(parse(b"not mach-o").is_err());
    }

    #[test]
    fn universal_headers_and_java_classes() {
        let mut bytes = Vec::new();
        for word in [0xcafe_babe_u32, 1, CPU_TYPE_X86_64, 3, 0x1000, 0x2000, 12] {
            bytes.extend(word.to_be_bytes());
        }
        let slices = fat(&bytes).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(slices.len(), 1);
        assert!(slices.first().is_some_and(|s| s.cputype == CPU_TYPE_X86_64
            && s.offset == 0x1000
            && s.size == 0x2000));
        // A class file: magic, minor version 0, major version 52.
        let class = [0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 52];
        assert!(matches!(fat(&class), Err(Error::NotExecutable(_))));
        // Slices past the end are left out.
        assert!(fat(&bytes[..16]).is_ok_and(|s| s.is_empty()));
    }

    #[test]
    fn bind_opcodes_name_each_symbols_library() {
        let mut stream = vec![0x11]; // SET_DYLIB_ORDINAL_IMM 1
        stream.extend(b"@_malloc\0"); // SET_SYMBOL_TRAILING_FLAGS_IMM
        stream.extend([0x51, 0x72, 0x10, 0x90]); // type, segment+offset, DO_BIND
        stream.extend([0x20, 0x82, 0x01]); // SET_DYLIB_ORDINAL_ULEB 130
        stream.extend(b"@_free\0");
        stream.extend([0xc0, 0x02, 0x08]); // DO_BIND_ULEB_TIMES_SKIPPING_ULEB
        stream.extend([0x00, 0x3e]); // DONE, SET_DYLIB_SPECIAL_IMM -2
        stream.extend(b"@_napi_get_cb_info\0");
        stream.extend([0xa0, 0x08]); // DO_BIND_ADD_ADDR_ULEB
        stream.extend(b"@_cut"); // a name the stream ends inside
        let mut found = Vec::new();
        bind_opcodes(&stream, &mut |name, ordinal| {
            found.push((String::from_utf8_lossy(name).into_owned(), ordinal));
        });
        assert_eq!(
            found,
            [
                ("_malloc".to_owned(), 1),
                ("_free".to_owned(), 130),
                ("_napi_get_cb_info".to_owned(), -2),
            ]
        );
    }

    /// A name longer than names are kept runs to its NUL all the same: the
    /// opcodes go on after it, not inside it (where `@_evil` would set
    /// another symbol).
    #[test]
    fn bind_opcodes_step_over_a_long_name() {
        let mut long = b"_".to_vec();
        long.resize(limits::NAME_LEN + 5, b'a');
        long.extend(b"@_evil");
        let mut stream = vec![0x11, 0x40]; // SET_DYLIB_ORDINAL_IMM 1, SET_SYMBOL
        stream.extend(&long);
        stream.extend([0x00, 0x90]); // its NUL, DO_BIND
        stream.extend(b"@_free\0");
        stream.push(0x90);
        let mut found = Vec::new();
        bind_opcodes(&stream, &mut |name, ordinal| found.push((name, ordinal)));
        assert_eq!(
            found,
            [(&long[..limits::NAME_LEN], 1), (b"_free".as_slice(), 1)]
        );
    }

    #[test]
    fn chained_imports_in_each_format() {
        let table = |format: u32, entries: &[u8]| {
            let mut data = Vec::new();
            // version, starts, imports at 32, symbols after them, count 2.
            let symbols = 32 + u32::try_from(entries.len()).unwrap_or(0);
            for word in [0, 0, 32, symbols, 2, format, 0, 0] {
                data.extend(word.to_le_bytes());
            }
            data.extend(entries);
            data.extend(b"_open\0_write\0");
            let mut found = Vec::new();
            chained_imports(&data, false, &mut |name, ordinal| {
                found.push((String::from_utf8_lossy(name).into_owned(), ordinal));
            });
            found
        };
        let expected = [("_open".to_owned(), 2), ("_write".to_owned(), -2)];
        // DYLD_CHAINED_IMPORT: ordinal in the low byte, name offset from bit 9.
        let import = |ordinal: u32, name: u32| (ordinal | name << 9).to_le_bytes();
        let one: Vec<u8> = [import(2, 0), import(0xfe, 6)].concat();
        assert_eq!(table(1, &one), expected);
        let two: Vec<u8> = [import(2, 0), [0; 4], import(0xfe, 6), [0; 4]].concat();
        assert_eq!(table(2, &two), expected);
        let wide = |ordinal: u64, name: u64| (ordinal | name << 32).to_le_bytes();
        let three: Vec<u8> = [wide(2, 0), [0; 8], wide(0xfffe, 6), [0; 8]].concat();
        assert_eq!(table(3, &three), expected);
    }

    #[test]
    fn export_trie_keeps_reexports() {
        // Root: no terminal, two children; `_a` at 0x10, `_b` re-exported
        // from library 2 as `_c`, and `_d` as itself from library 1.
        let mut trie = vec![0, 3];
        trie.extend(b"_a\0\x10_b\0\x14_d\0\x1b");
        trie.resize(0x10, 0);
        trie.extend([2, 0, 0x10, 0]); // flags 0, offset 0x10, no children
        trie.extend([5, 8, 2]); // flags REEXPORT, ordinal 2, then the name
        trie.extend(b"_c\0\0");
        trie.extend([3, 8, 1, 0, 0]); // REEXPORT, ordinal 1, same name
        let mut found: Vec<String> = exports_trie(&trie)
            .into_iter()
            .map(|(name, exported)| match exported {
                Exported::At(offset) => format!("{name}@{offset:#x}"),
                Exported::Reexport {
                    ordinal,
                    name: there,
                } => format!("{name}<{ordinal}:{there}"),
            })
            .collect();
        found.sort();
        assert_eq!(found, ["_a@0x10", "_b<2:_c", "_d<1:"]);
    }

    /// A chain of terminal nodes, each a one-byte edge below the last,
    /// names every prefix of a long run: the square of its length. The walk
    /// stops at names longer than any real symbol.
    #[test]
    fn a_deep_export_trie_builds_bounded_names() {
        // Each node: terminal size 2, flags, offset; one child, edge `a`,
        // the child's offset as a three-byte LEB128.
        let nodes = 100_000_usize;
        let mut trie = Vec::with_capacity(nodes * 9);
        for i in 1..=nodes {
            let next = u32::try_from(9 * i).unwrap_or(0);
            trie.extend([2, 0, 0, 1, b'a', 0]);
            trie.extend([
                0x80 | (next & 0x7f) as u8,
                0x80 | (next >> 7 & 0x7f) as u8,
                (next >> 14 & 0x7f) as u8,
            ]);
        }
        let found = exports_trie(&trie);
        assert!(found.len() > 1000);
        assert!(found.iter().all(|(name, _)| name.len() <= limits::NAME_LEN));
    }
}
