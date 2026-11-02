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

pub(super) const CPU_TYPE_X86: u32 = 7;
pub(super) const CPU_TYPE_X86_64: u32 = 0x0100_0007;
pub(super) const CPU_TYPE_ARM64: u32 = 0x0100_000c;

pub(super) const SECTION_TYPE: u32 = 0xff;
const S_ATTR_PURE_INSTRUCTIONS: u32 = 0x8000_0000;
const S_ATTR_SOME_INSTRUCTIONS: u32 = 0x0000_0400;
const VM_PROT_EXECUTE: u32 = 0x4;

/// `n_type` bits: a debugging entry when any of these is set.
const N_STAB: u8 = 0xe0;
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
}
