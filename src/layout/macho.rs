//! The parts of a Mach-O file recovery uses, read leniently: the load
//! commands are walked one by one, and a command, section or table that is
//! truncated or points outside the file is cut short or left out rather
//! than failing the whole file. Universal (fat) headers are read here too.

use super::read::Reader;

/// The most entries read from any one table.
const MOST: u64 = 1 << 20;

const MH_MAGIC: u32 = 0xfeed_face;
const MH_MAGIC_64: u32 = 0xfeed_facf;
pub(super) const MH_OBJECT: u32 = 1;

const LC_SEGMENT: u32 = 0x1;
const LC_SYMTAB: u32 = 0x2;
const LC_UNIXTHREAD: u32 = 0x5;
const LC_DYSYMTAB: u32 = 0xb;
const LC_SEGMENT_64: u32 = 0x19;
const LC_FUNCTION_STARTS: u32 = 0x26;
const LC_MAIN: u32 = 0x8000_0028;
const LC_LOAD_DYLIB: u32 = 0xc;
const LC_DYLD_INFO: u32 = 0x22;
const LC_DYLD_INFO_ONLY: u32 = 0x8000_0022;
const LC_DYLD_EXPORTS_TRIE: u32 = 0x8000_0033;
const LC_DYLD_CHAINED_FIXUPS: u32 = 0x8000_0034;
const EXPORT_SYMBOL_FLAGS_REEXPORT: u64 = 0x8;
const LC_LOAD_WEAK_DYLIB: u32 = 0x8000_0018;
const LC_REEXPORT_DYLIB: u32 = 0x8000_001f;
const LC_LAZY_LOAD_DYLIB: u32 = 0x20;
const LC_LOAD_UPWARD_DYLIB: u32 = 0x8000_0023;

pub(super) const CPU_TYPE_X86: u32 = 7;
pub(super) const CPU_TYPE_X86_64: u32 = 0x0100_0007;
pub(super) const CPU_TYPE_ARM64: u32 = 0x0100_000c;

pub(super) const SECTION_TYPE: u32 = 0xff;
const S_ATTR_PURE_INSTRUCTIONS: u32 = 0x8000_0000;
const S_ATTR_SOME_INSTRUCTIONS: u32 = 0x0000_0400;
const VM_PROT_EXECUTE: u32 = 0x4;

/// `n_type` bits: a debugging entry when any of these is set.
const N_STAB: u8 = 0xe0;
pub(super) const N_EXT: u8 = 0x01;
pub(super) const N_PEXT: u8 = 0x10;
pub(super) const N_TYPE: u8 = 0x0e;
pub(super) const N_UNDF: u8 = 0x0;
pub(super) const N_SECT: u8 = 0xe;

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

fn named(name: &[u8; 16], wanted: &str) -> bool {
    let len = name.iter().position(|&b| b == 0).unwrap_or(16);
    name.get(..len) == Some(wanted.as_bytes())
}

impl Segment {
    pub(super) fn named(&self, name: &str) -> bool {
        named(&self.name, name)
    }
}

impl Section {
    pub(super) fn named(&self, name: &str) -> bool {
        named(&self.name, name)
    }

    /// `__SEGMENT.__section`.
    pub(super) fn full_name(&self) -> String {
        let text = |name: &[u8; 16]| {
            let len = name.iter().position(|&b| b == 0).unwrap_or(16);
            String::from_utf8_lossy(name.get(..len).unwrap_or_default()).into_owned()
        };
        format!("{}.{}", text(&self.segment), text(&self.name))
    }
}

/// The Mach-O file in `bytes`, or why it is none: only a header too short
/// or of no known magic number fails.
pub(super) fn parse(bytes: &[u8]) -> Result<MachO, String> {
    let magic = Reader::new(bytes, false).u32(0).ok_or("too short")?;
    let (is_64, big) = match magic {
        MH_MAGIC => (false, false),
        MH_MAGIC_64 => (true, false),
        _ if magic.swap_bytes() == MH_MAGIC => (false, true),
        _ if magic.swap_bytes() == MH_MAGIC_64 => (true, true),
        _ => return Err(format!("unknown magic number {magic:#010x}")),
    };
    let r = Reader::new(bytes, big);
    let (cputype, filetype, ncmds) =
        (|| Some((r.u32(4)?, r.u32(12)?, r.u32(16)?)))().ok_or("Mach-O header truncated")?;
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
    for _ in 0..ncmds.min(1 << 16) {
        let (Some(cmd), Some(size)) = (r.u32(at), r.u32(at + 4)) else {
            break;
        };
        match cmd {
            LC_SEGMENT | LC_SEGMENT_64 => macho.read_segment(&r, at, cmd == LC_SEGMENT_64),
            LC_SYMTAB => macho.read_symbols(&r, at),
            LC_DYSYMTAB => macho.read_indirect(&r, at),
            LC_DYLD_INFO | LC_DYLD_INFO_ONLY => {
                // Bind at 16, weak bind at 24 (by name alone, no library),
                // lazy bind at 32.
                macho.binds = [16, 32]
                    .into_iter()
                    .filter_map(|field| {
                        Some((
                            u64::from(r.u32(at + field)?),
                            u64::from(r.u32(at + field + 4)?),
                        ))
                    })
                    .filter(|&(_, size)| size != 0)
                    .collect();
                macho.exports_trie =
                    (|| Some((u64::from(r.u32(at + 40)?), u64::from(r.u32(at + 44)?))))()
                        .filter(|&(_, size)| size != 0)
                        .or(macho.exports_trie);
            }
            LC_DYLD_CHAINED_FIXUPS => {
                macho.chained_fixups =
                    (|| Some((u64::from(r.u32(at + 8)?), u64::from(r.u32(at + 12)?))))()
                        .filter(|&(_, size)| size != 0);
            }
            LC_DYLD_EXPORTS_TRIE => {
                macho.exports_trie =
                    (|| Some((u64::from(r.u32(at + 8)?), u64::from(r.u32(at + 12)?))))()
                        .filter(|&(_, size)| size != 0);
            }
            LC_LOAD_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB | LC_LAZY_LOAD_DYLIB
            | LC_LOAD_UPWARD_DYLIB => {
                let name = r.u32(at + 8).map(|offset| r.name(at + u64::from(offset)));
                macho.dylibs.push(name.unwrap_or_default().into_owned());
            }
            LC_FUNCTION_STARTS => {
                macho.function_starts =
                    (|| Some((u64::from(r.u32(at + 8)?), u64::from(r.u32(at + 12)?))))();
            }
            // dyld honours the first of each.
            LC_MAIN if main.is_none() => main = r.u64(at + 8),
            LC_UNIXTHREAD if thread.is_none() => thread = thread_pc(&r, at, cputype),
            _ => {}
        }
        if size < 8 {
            break;
        }
        at += u64::from(size);
    }
    // dyld prefers LC_MAIN, an offset from the start of `__TEXT`.
    macho.entry = match (main, thread) {
        (Some(offset), _) => macho
            .segments
            .iter()
            .find(|segment| segment.named("__TEXT"))
            .map_or(0, |text| {
                text.vmaddr.wrapping_sub(text.fileoff).wrapping_add(offset)
            }),
        (None, Some(pc)) => pc,
        (None, None) => 0,
    };
    Ok(macho)
}

/// The program counter an `LC_UNIXTHREAD` command at `at` starts at, read
/// from the thread state as the CPU type lays it out (dyld ignores the
/// flavour).
fn thread_pc(r: &Reader<'_>, at: u64, cputype: u32) -> Option<u64> {
    let count = u64::from(r.u32(at + 12)?);
    let state = at + 16;
    let (offset, wide) = match cputype {
        CPU_TYPE_X86 => (40, false),
        CPU_TYPE_X86_64 => (128, true),
        CPU_TYPE_ARM64 => (256, true),
        _ => return None,
    };
    let width = if wide { 8 } else { 4 };
    if offset + width > 4 * count {
        return None;
    }
    if wide {
        // Two words, low first, in the file's byte order.
        let low = u64::from(r.u32(state + offset)?);
        let high = u64::from(r.u32(state + offset + 4)?);
        Some(low | high << 32)
    } else {
        r.u32(state + offset).map(u64::from)
    }
}

impl MachO {
    fn read_segment(&mut self, r: &Reader<'_>, at: u64, wide: bool) {
        let name = |at: u64| -> Option<[u8; 16]> {
            let at = usize::try_from(at).ok()?;
            r.bytes.get(at..at.checked_add(16)?)?.try_into().ok()
        };
        let segment = if wide {
            (|| {
                Some((
                    Segment {
                        name: name(at + 8)?,
                        vmaddr: r.u64(at + 24)?,
                        fileoff: r.u64(at + 40)?,
                    },
                    r.u32(at + 60)?,
                    r.u32(at + 64)?,
                ))
            })()
        } else {
            (|| {
                Some((
                    Segment {
                        name: name(at + 8)?,
                        vmaddr: u64::from(r.u32(at + 24)?),
                        fileoff: u64::from(r.u32(at + 32)?),
                    },
                    r.u32(at + 44)?,
                    r.u32(at + 48)?,
                ))
            })()
        };
        let Some((segment, initprot, nsects)) = segment else {
            return;
        };
        self.segments.push(segment);
        let executable = initprot & VM_PROT_EXECUTE != 0;
        let (first, size) = if wide { (72, 80) } else { (56, 68) };
        for i in 0..u64::from(nsects).min(1 << 12) {
            let at = at + first + i * size;
            let section = if wide {
                (|| {
                    Some(Section {
                        name: name(at)?,
                        segment: name(at + 16)?,
                        protection: initprot,
                        addr: r.u64(at + 32)?,
                        size: r.u64(at + 40)?,
                        offset: u64::from(r.u32(at + 48)?),
                        reloff: r.u32(at + 56)?,
                        nreloc: r.u32(at + 60)?,
                        flags: r.u32(at + 64)?,
                        reserved1: r.u32(at + 68)?,
                        reserved2: r.u32(at + 72)?,
                        code: false,
                    })
                })()
            } else {
                (|| {
                    Some(Section {
                        name: name(at)?,
                        segment: name(at + 16)?,
                        protection: initprot,
                        addr: u64::from(r.u32(at + 32)?),
                        size: u64::from(r.u32(at + 36)?),
                        offset: u64::from(r.u32(at + 40)?),
                        reloff: r.u32(at + 48)?,
                        nreloc: r.u32(at + 52)?,
                        flags: r.u32(at + 56)?,
                        reserved1: r.u32(at + 60)?,
                        reserved2: r.u32(at + 64)?,
                        code: false,
                    })
                })()
            };
            let Some(mut section) = section else { break };
            section.code = executable
                && section.flags & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS) != 0;
            self.sections.push(section);
        }
    }

    fn read_symbols(&mut self, r: &Reader<'_>, at: u64) {
        let Some((symoff, nsyms, stroff)) =
            (|| Some((r.u32(at + 8)?, r.u32(at + 12)?, r.u32(at + 16)?)))()
        else {
            return;
        };
        let (symoff, stroff) = (u64::from(symoff), u64::from(stroff));
        let size = if self.is_64 { 16 } else { 12 };
        self.symbols = (0..u64::from(nsyms).min(MOST))
            .map_while(|i| {
                let at = symoff + i * size;
                let n_value = if self.is_64 {
                    r.u64(at + 8)?
                } else {
                    u64::from(r.u32(at + 8)?)
                };
                Some(Symbol {
                    name: r.name(stroff + u64::from(r.u32(at)?)).into_owned(),
                    n_type: r.u8(at + 4)?,
                    n_desc: r.u16(at + 6)?,
                    n_value,
                })
            })
            .collect();
    }

    fn read_indirect(&mut self, r: &Reader<'_>, at: u64) {
        let (Some(offset), Some(count)) = (r.u32(at + 56), r.u32(at + 60)) else {
            return;
        };
        let offset = u64::from(offset);
        self.indirect = (0..u64::from(count).min(MOST))
            .map_while(|i| r.u32(offset + 4 * i))
            .collect();
    }
}

/// The symbols an export trie names, each with its offset from the image
/// base, or the library symbol it re-exports. Each node is visited at most
/// once, so a trie whose edges loop ends.
pub(super) fn exports_trie(trie: &[u8]) -> Vec<(String, Exported)> {
    let mut out = Vec::new();
    let mut visited = std::collections::HashSet::new();
    let mut stack = vec![(0_usize, Vec::new())];
    // Name bytes built: each child copies its parent's prefix, so a chain of
    // terminal nodes costs the square of its length. Real names are short,
    // and a real trie's total well under a megabyte.
    let mut budget: usize = 32 << 20;
    while let Some((node, prefix)) = stack.pop() {
        if !visited.insert(node) || visited.len() > 1 << 20 {
            continue;
        }
        let mut at = node;
        let Some(terminal) = uleb(trie, &mut at) else {
            continue;
        };
        let children = at.saturating_add(usize::try_from(terminal).unwrap_or(usize::MAX));
        if terminal != 0
            && let Some(flags) = uleb(trie, &mut at)
        {
            let exported = if flags & EXPORT_SYMBOL_FLAGS_REEXPORT == 0 {
                uleb(trie, &mut at).map(Exported::At)
            } else {
                // The library's ordinal, then the name it exports there
                // (empty for the same name).
                uleb(trie, &mut at).map(|ordinal| Exported::Reexport {
                    ordinal,
                    name: String::from_utf8_lossy(cstr(trie, at)).into_owned(),
                })
            };
            if let Some(exported) = exported {
                out.push((String::from_utf8_lossy(&prefix).into_owned(), exported));
            }
        }
        let mut at = children;
        let Some(&count) = trie.get(at) else {
            continue;
        };
        at += 1;
        for _ in 0..count {
            let Some(len) = trie
                .get(at..)
                .and_then(|rest| rest.iter().position(|&b| b == 0))
            else {
                break;
            };
            let edge = trie.get(at..at + len).unwrap_or_default();
            at += len + 1;
            let Some(child) = uleb(trie, &mut at) else {
                break;
            };
            let size = prefix.len() + edge.len();
            if size > 1 << 12 || size > budget {
                continue;
            }
            budget -= size;
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

/// The NUL-terminated bytes at `at`; empty past the end.
fn cstr(data: &[u8], at: usize) -> &[u8] {
    data.get(at..)
        .map(|rest| rest.get(..1 << 12).unwrap_or(rest))
        .and_then(|rest| rest.split(|&b| b == 0).next())
        .unwrap_or_default()
}

/// The library ordinal dyld binds each symbol to, by name, as the bind
/// opcode streams and the chained-fixup import table record it: what a
/// binary whose symbol table carries no two-level ordinal (Go's linker
/// writes none) says of its imports. Ordinals count the dylibs from 1;
/// zero and below are this image, the executable, and flat lookup. The
/// first binding of a name wins.
pub(super) fn bound_ordinals(bytes: &[u8], macho: &MachO) -> Vec<(String, i64)> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::<Vec<u8>>::new();
    // Name bytes looked at: every bind and import entry may name the same
    // long string, which costs a hash each time.
    let mut budget: usize = 32 << 20;
    let mut record = |name: &[u8], ordinal: i64| {
        budget = budget.saturating_sub(name.len());
        if budget > 0 && !name.is_empty() && (seen.len() as u64) < MOST && !seen.contains(name) {
            seen.insert(name.to_vec());
            out.push((String::from_utf8_lossy(name).into_owned(), ordinal));
        }
    };
    for &(offset, size) in &macho.binds {
        bind_opcodes(slice(bytes, offset, size), &mut record);
    }
    if let Some((offset, size)) = macho.chained_fixups {
        chained_imports(slice(bytes, offset, size), macho.big, &mut record);
    }
    out
}

/// The file's bytes from `offset`, `size` of them or as many as there are.
fn slice(bytes: &[u8], offset: u64, size: u64) -> &[u8] {
    let start = usize::try_from(offset).unwrap_or(usize::MAX);
    let end = start
        .saturating_add(usize::try_from(size).unwrap_or(usize::MAX))
        .min(bytes.len());
    bytes.get(start..end).unwrap_or_default()
}

/// The (symbol, library ordinal) of each bind in a dyld bind opcode
/// stream. Addresses are not tracked: only which library each name binds
/// to. An unknown or truncated opcode ends the stream.
fn bind_opcodes(stream: &[u8], record: &mut impl FnMut(&[u8], i64)) {
    let mut at = 0;
    let mut ordinal = 0_i64;
    let mut symbol: &[u8] = &[];
    while let Some(&byte) = stream.get(at) {
        at += 1;
        let immediate = byte & 0x0f;
        let skip = |at: &mut usize, n: usize| (0..n).all(|_| uleb(stream, at).is_some());
        let ok = match byte & 0xf0 {
            // DONE ends a lazy-bind entry, not the stream; SET_TYPE_IMM.
            0x00 | 0x50 => true,
            // SET_DYLIB_ORDINAL_IMM
            0x10 => {
                ordinal = i64::from(immediate);
                true
            }
            // SET_DYLIB_ORDINAL_ULEB
            0x20 => uleb(stream, &mut at)
                .map(|n| ordinal = i64::try_from(n).unwrap_or(0))
                .is_some(),
            // SET_DYLIB_SPECIAL_IMM: zero, or negative, sign-extended.
            0x30 => {
                ordinal = if immediate == 0 {
                    0
                } else {
                    i64::from(i8::from_ne_bytes([0xf0 | immediate]))
                };
                true
            }
            // SET_SYMBOL_TRAILING_FLAGS_IMM: the name follows.
            0x40 => {
                symbol = cstr(stream, at);
                at = at.saturating_add(symbol.len() + 1);
                at <= stream.len()
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
fn chained_imports(data: &[u8], big: bool, record: &mut impl FnMut(&[u8], i64)) {
    let r = Reader::new(data, big);
    // imports_offset, symbols_offset, imports_count, imports_format,
    // symbols_format.
    let header = (|| Some((r.u32(8)?, r.u32(12)?, r.u32(16)?, r.u32(20)?, r.u32(24)?)))();
    let Some((imports, symbols, count, format, 0)) = header else {
        return;
    };
    let (imports, symbols) = (u64::from(imports), u64::from(symbols));
    // The low byte (or, in the 64-bit format, half-word) is a signed ordinal.
    let small = |v: u32| i64::from(i8::from_ne_bytes([v.to_le_bytes()[0]]));
    for i in 0..u64::from(count).min(MOST) {
        let entry = match format {
            // DYLD_CHAINED_IMPORT: ordinal 8 bits, weak 1, name offset 23.
            1 => r
                .u32(imports + 4 * i)
                .map(|v| (small(v), u64::from(v >> 9))),
            // DYLD_CHAINED_IMPORT_ADDEND: the same, and a 32-bit addend.
            2 => r
                .u32(imports + 8 * i)
                .map(|v| (small(v), u64::from(v >> 9))),
            // DYLD_CHAINED_IMPORT_ADDEND64: ordinal 16 bits, weak 1,
            // reserved 15, name offset 32; then a 64-bit addend.
            3 => r.u64(imports + 16 * i).map(|v| {
                let [low, high, ..] = v.to_le_bytes();
                (i64::from(i16::from_le_bytes([low, high])), v >> 32)
            }),
            _ => None,
        };
        let Some((ordinal, name)) = entry else {
            break;
        };
        let at = usize::try_from(symbols.saturating_add(name)).unwrap_or(usize::MAX);
        record(cstr(data, at), ordinal);
    }
}

/// The unsigned LEB128 number at `*at`, advancing past it.
fn uleb(data: &[u8], at: &mut usize) -> Option<u64> {
    let mut value = 0_u64;
    for shift in (0..64).step_by(7) {
        let byte = *data.get(*at)?;
        *at += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

/// One slice of a universal binary: its CPU type and file range.
pub(super) struct Slice {
    pub(super) cputype: u32,
    pub(super) offset: u64,
    pub(super) size: u64,
}

/// The slices a universal header (`0xcafebabe`, or `0xcafebabf` with
/// 64-bit offsets) lists. A Java class file shares the magic number, and
/// its "slice count" is its major version, 45 or more: no universal binary
/// has that many slices.
pub(super) fn fat(bytes: &[u8]) -> Result<Vec<Slice>, String> {
    let r = Reader::new(bytes, true);
    let wide = match r.u32(0) {
        Some(0xcafe_babe) => false,
        Some(0xcafe_babf) => true,
        _ => return Err("no universal header".into()),
    };
    let count = r.u32(4).ok_or("universal header truncated")?;
    if count >= 45 {
        return Err("a Java class file".into());
    }
    let size = if wide { 32 } else { 20 };
    Ok((0..u64::from(count))
        .map_while(|i| {
            let at = 8 + i * size;
            Some(Slice {
                cputype: r.u32(at)?,
                offset: r.word(at + 8, wide)?,
                size: r.word(at + if wide { 16 } else { 12 }, wide)?,
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
        assert_eq!(fat(&class).err().as_deref(), Some("a Java class file"));
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
        assert!(found.iter().all(|(name, _)| name.len() <= 1 << 12));
    }
}
