//! The parts of a PE file recovery uses, read leniently. The headers and
//! the section table are read first; each directory is then read on its
//! own, so one that is truncated or points nowhere costs that directory,
//! not the file. The CLR (COR20) directory is never read: recovery does not
//! need it, and a malformed one is common in obfuscated .NET binaries.

use std::collections::{BTreeSet, HashMap};

use super::read::{self, Reader};
use super::{Error, limits};

/// `PE\0\0`.
const PE_SIGNATURE: u32 = 0x0000_4550;
const PE32: u16 = 0x10b;
const PE32_PLUS: u16 = 0x20b;
/// The data directories an optional header can hold.
const DIRECTORIES: u64 = 16;

const DIRECTORY_EXPORT: usize = 0;
const DIRECTORY_IMPORT: usize = 1;
const DIRECTORY_RESOURCE: usize = 2;
const DIRECTORY_EXCEPTION: usize = 3;
const DIRECTORY_TLS: usize = 9;
const DIRECTORY_DELAY_IMPORT: usize = 13;

/// `UNW_FLAG_CHAININFO`: the unwind data continues another entry's.
const UNW_FLAG_CHAININFO: u8 = 4;
/// An A64 `.pdata` entry whose packed data describes a fragment.
const ARM64_PACKED_FRAGMENT: u32 = 2;
/// An A64 unwind code: `end_c`, the end of a fragment's absent prologue.
const ARM64_END_C: u8 = 0xe5;

pub(super) struct Pe<'a> {
    r: Reader<'a>,
    pub(super) machine: u16,
    pub(super) is_64: bool,
    pub(super) image_base: u64,
    /// The entry point's RVA; zero for none.
    pub(super) entry: u32,
    pub(super) sections: Vec<Section>,
    /// Each data directory's (RVA, size).
    directories: Vec<(u32, u32)>,
    /// What the file backs, as [`spans`] gives it.
    spans: Vec<Span>,
}

/// One exported function: by name, or `Ordinal_n`; a forwarder names
/// another DLL's export instead of code.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Export {
    pub(super) rva: u32,
    pub(super) name: String,
    pub(super) forward: Option<String>,
}

/// One imported symbol and the address-table slot the loader fills.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Import {
    pub(super) slot: u32,
    pub(super) library: String,
    pub(super) name: String,
    pub(super) ordinal: Option<u16>,
    /// From the delay-load table.
    pub(super) delayed: bool,
}

pub(super) struct Section {
    /// The header's name; a `/N` long name read from the COFF string table.
    pub(super) name: String,
    pub(super) virtual_size: u32,
    pub(super) virtual_address: u32,
    pub(super) size_of_raw_data: u32,
    pub(super) pointer_to_raw_data: u32,
    pub(super) characteristics: u32,
}

/// RVAs from `start` to `end` that the file backs from `offset` on.
#[derive(Clone, Copy)]
struct Span {
    start: u64,
    end: u64,
    offset: u64,
}

/// The PE file in `bytes`, or why it is none: only a missing signature or
/// an unknown optional header fails.
pub(super) fn parse(bytes: &[u8]) -> Result<Pe<'_>, Error> {
    let r = Reader::new(bytes, false);
    let nt = r.u32(0x3c).ok_or(Error::Truncated("DOS header"))?;
    let nt = r.at(u64::from(nt));
    if nt.u32(0) != Some(PE_SIGNATURE) {
        return Err(Error::BadMagic);
    }
    let coff = nt.at(4);
    let (machine, count, optional_size) = (|| Some((coff.u16(0)?, coff.u16(2)?, coff.u16(16)?)))()
        .ok_or(Error::Truncated("COFF header"))?;
    let optional = coff.at(20);
    let is_64 = match optional.u16(0) {
        Some(PE32) => false,
        Some(PE32_PLUS) => true,
        Some(_) => return Err(Error::Unsupported("PE optional header magic")),
        None => return Err(Error::Truncated("PE optional header")),
    };
    let entry = optional.u32(16).unwrap_or(0);
    let image_base = if is_64 {
        optional.u64(24)
    } else {
        optional.u32(28).map(u64::from)
    }
    .unwrap_or(0);
    let file_alignment = optional.u32(36).unwrap_or(0);
    let (count_at, first) = if is_64 { (108, 112) } else { (92, 96) };
    // The directories that fit in the optional header the COFF header sizes.
    let fit = u64::from(optional_size).saturating_sub(first) / 8;
    let claimed = optional.u32(count_at).map_or(0, u64::from);
    let directories = read::table(first, 8, claimed.min(fit).min(DIRECTORIES))
        .map_while(|at| Some((optional.u32(at)?, optional.at(at).u32(4)?)))
        .collect();
    // Long section names (`/4`) are offsets into the COFF string table,
    // which follows the symbol table and starts with its own size. A strip
    // can leave the pointer behind with other bytes where the table was
    // (MinGW images whose resources were rewritten): a table whose size
    // does not fit the file, or a name that runs past it or is no text,
    // leaves the section with the name its header holds.
    let strings = coff
        .u32(8)
        .filter(|&symbols| symbols != 0)
        .map(|symbols| {
            let count = u64::from(coff.u32(12).unwrap_or(0));
            u64::from(symbols).saturating_add(count.saturating_mul(18))
        })
        .and_then(|start| {
            let size = u64::from(r.u32(start)?);
            let table = r
                .bytes
                .get(usize::try_from(start).ok()?..)?
                .get(..usize::try_from(size).ok()?)?;
            (size >= 4).then_some(table)
        });
    let long_name = |offset: u64| -> Option<String> {
        let rest = strings?.get(usize::try_from(offset).ok().filter(|&o| o >= 4)?..)?;
        let rest = rest.get(..limits::NAME_LEN).unwrap_or(rest);
        let name = std::str::from_utf8(rest.get(..rest.iter().position(|&b| b == 0)?)?).ok()?;
        (!name.is_empty() && !name.chars().any(char::is_control)).then(|| name.to_owned())
    };
    let headers = optional.at(u64::from(optional_size));
    // Every section may name the same long string: past a budget of name
    // bytes, sections keep the names their headers hold.
    let mut names = limits::NAME_BYTES;
    let sections: Vec<Section> = read::table(0, 40, u64::from(count))
        .map_while(|at| {
            let header = headers.at(at);
            let raw = header.array::<8>(0)?;
            let raw = raw.split(|&b| b == 0).next().unwrap_or_default();
            let long = raw
                .strip_prefix(b"/")
                .filter(|_| names > 0)
                .and_then(|digits| std::str::from_utf8(digits).ok()?.parse::<u64>().ok())
                .and_then(long_name);
            names = names.saturating_sub(long.as_ref().map_or(0, String::len));
            Some(Section {
                name: long.unwrap_or_else(|| String::from_utf8_lossy(raw).into_owned()),
                virtual_size: header.u32(8)?,
                virtual_address: header.u32(12)?,
                size_of_raw_data: header.u32(16)?,
                pointer_to_raw_data: header.u32(20)?,
                characteristics: header.u32(36)?,
            })
        })
        .collect();
    // An alignment that is no power of two is the loader's default.
    let alignment = match u64::from(file_alignment) {
        a if a.is_power_of_two() => a,
        _ => 0x200,
    };
    let spans = spans(&sections, alignment);
    Ok(Pe {
        r,
        machine,
        is_64,
        image_base,
        entry,
        sections,
        directories,
        spans,
    })
}

impl Section {
    /// How many bytes from the section's RVA the file backs, as the loader
    /// rounds them: the raw pointer down to 512 bytes, the end up to the
    /// file alignment, and neither size past its 4 KiB rounding.
    fn read_size(&self, file_alignment: u64) -> u64 {
        let raw = u64::from(self.size_of_raw_data);
        if raw == 0 {
            return 0;
        }
        let page = |size: u64| size.saturating_add(0xfff) & !0xfff;
        let pointer = u64::from(self.pointer_to_raw_data);
        let end = pointer
            .saturating_add(raw)
            .checked_next_multiple_of(file_alignment)
            .unwrap_or(u64::MAX);
        let size = end.saturating_sub(pointer & !0x1ff).min(page(raw));
        match u64::from(self.virtual_size) {
            0 => size,
            virtual_size => size.min(page(virtual_size)),
        }
    }
}

/// The RVAs the file backs, as sorted spans that do not overlap: each RVA
/// by the first section, in header order, that backs it, as the loader
/// would map it. Built once, so finding an RVA's offset is a binary search
/// however many sections there are.
fn spans(sections: &[Section], alignment: u64) -> Vec<Span> {
    let backed: Vec<Span> = sections
        .iter()
        .filter_map(|section| {
            let start = u64::from(section.virtual_address);
            let end = start.checked_add(section.read_size(alignment))?;
            let offset = u64::from(section.pointer_to_raw_data);
            (end > start).then_some(Span { start, end, offset })
        })
        .collect();
    // Sweep the sections' starts and ends; between two, the first section
    // open owns the RVAs.
    let mut edges: Vec<(u64, usize)> = backed
        .iter()
        .enumerate()
        .flat_map(|(i, span)| [(span.start, i), (span.end, i)])
        .collect();
    edges.sort_unstable();
    let mut open = BTreeSet::new();
    let mut spans = Vec::new();
    let mut groups = edges.chunk_by(|a, b| a.0 == b.0).peekable();
    while let Some(group) = groups.next() {
        let Some(&(at, _)) = group.first() else {
            continue;
        };
        for &(_, i) in group {
            if backed.get(i).is_some_and(|span| span.start == at) {
                open.insert(i);
            } else {
                open.remove(&i);
            }
        }
        let next = groups.peek().and_then(|group| group.first());
        let owner = open.first().and_then(|&i| backed.get(i));
        if let (Some(&(end, _)), Some(owner)) = (next, owner)
            && let Some(offset) = owner.offset.checked_add(at.saturating_sub(owner.start))
        {
            spans.push(Span {
                start: at,
                end,
                offset,
            });
        }
    }
    spans
}

/// One import descriptor: the DLL's name and its lookup and address
/// tables, as RVAs.
struct Descriptor {
    name: u32,
    lookup: u32,
    address: u32,
    /// Subtracted from name addresses that are no RVAs.
    base: u64,
    /// From the delay-load table.
    delayed: bool,
}

/// The imports read so far, and the name bytes they may still spend.
struct ImportWalk {
    imports: Vec<Import>,
    /// Name bytes left to copy.
    budget: usize,
    /// Lookup-table entries left to look at: descriptors may all share one
    /// table of entries that name nothing.
    entries: usize,
}

impl Pe<'_> {
    /// The file offset of `rva`, by the first section that backs it.
    pub(super) fn offset(&self, rva: u32) -> Option<u64> {
        let rva = u64::from(rva);
        let i = self.spans.partition_point(|span| span.end <= rva);
        let span = self.spans.get(i).filter(|span| span.start <= rva)?;
        span.offset.checked_add(rva.checked_sub(span.start)?)
    }

    /// The RVA of the resource directory, which old linkers put in a
    /// section they mark executable.
    pub(super) fn resources(&self) -> Option<u32> {
        self.directory(DIRECTORY_RESOURCE).map(|(rva, _)| rva)
    }

    fn directory(&self, index: usize) -> Option<(u32, u32)> {
        self.directories
            .get(index)
            .copied()
            .filter(|&(rva, _)| rva != 0)
    }

    /// The bytes from `rva` on, if the file backs it.
    fn at(&self, rva: u32) -> Option<Reader<'_>> {
        Some(self.r.at(self.offset(rva)?))
    }

    /// The NUL-terminated name at `rva`.
    fn name_at(&self, rva: u32) -> Option<String> {
        Some(self.r.name(self.offset(rva)?).into_owned())
    }

    /// The exports, by function index: each one's RVA, and its name or
    /// `Ordinal_n` for one exported by ordinal only. A forwarder, whose RVA
    /// lies inside the export directory, names another DLL's export in
    /// `forward`.
    pub(super) fn exports(&self) -> Vec<Export> {
        let Some((dir, size)) = self.directory(DIRECTORY_EXPORT) else {
            return Vec::new();
        };
        let Some(header) = self.at(dir) else {
            return Vec::new();
        };
        let fields = (|| {
            Some((
                header.u32(20)?,
                header.u32(24)?,
                header.u32(28)?,
                header.u32(32)?,
                header.u32(36)?,
            ))
        })();
        let Some((functions, names, function_table, name_table, ordinal_table)) = fields else {
            return Vec::new();
        };
        let ordinal_base = header.u32(16).unwrap_or(1);
        let (Some(function_table), Some(name_table), Some(ordinal_table)) = (
            self.offset(function_table),
            self.offset(name_table),
            self.offset(ordinal_table),
        ) else {
            return Vec::new();
        };
        let r = &self.r;
        let functions = u64::from(functions);
        // The names table names some functions, by index; the rest are
        // exported by ordinal only.
        let mut budget = limits::NAME_BYTES;
        let mut named: HashMap<u16, String> = HashMap::new();
        let count = u64::from(names);
        for (index_at, name_at) in
            read::table(ordinal_table, 2, count).zip(read::table(name_table, 4, count))
        {
            let Some(index) = r.u16(index_at) else {
                break;
            };
            if u64::from(index) >= functions.min(limits::TABLE) || named.contains_key(&index) {
                continue;
            }
            if let Some(name) = r.u32(name_at).and_then(|name| self.name_at(name)) {
                budget = budget.saturating_sub(name.len());
                named.insert(index, name);
            }
            if budget == 0 {
                break;
            }
        }
        (0_u32..)
            .zip(read::table(function_table, 4, functions))
            .filter_map(|(index, at)| {
                let rva = r.u32(at)?;
                if rva == 0 {
                    return None;
                }
                let forward = (rva.checked_sub(dir).is_some_and(|d| d < size) && budget > 0)
                    .then(|| self.name_at(rva))
                    .flatten();
                budget = budget.saturating_sub(forward.as_ref().map_or(0, String::len));
                let name = u16::try_from(index)
                    .ok()
                    .and_then(|index| named.remove(&index));
                Some(Export {
                    rva,
                    name: name
                        .unwrap_or_else(|| format!("Ordinal_{}", ordinal_base.wrapping_add(index))),
                    forward,
                })
            })
            .collect()
    }

    /// The import address table's slots, then the delay-load table's, with
    /// the DLL each imports from and the name it imports (`Ordinal_n` for
    /// one imported by ordinal only). Stops after [`limits::IMPORTS`]
    /// lookup-table entries, or once the names spend [`limits::NAME_BYTES`].
    pub(super) fn imports(&self) -> Vec<Import> {
        let mut walk = ImportWalk {
            imports: Vec::new(),
            budget: limits::NAME_BYTES,
            entries: limits::IMPORTS,
        };
        if let Some(table) = self
            .directory(DIRECTORY_IMPORT)
            .and_then(|(rva, _)| self.at(rva))
        {
            for at in read::table(0, 20, limits::DESCRIPTORS) {
                let d = table.at(at);
                let Some([lookup, name, address]) =
                    (|| Some([d.u32(0)?, d.u32(12)?, d.u32(16)?]))()
                else {
                    break;
                };
                // The table ends at an empty descriptor, or one naming no
                // DLL or slots.
                if name == 0 || address == 0 {
                    break;
                }
                let descriptor = Descriptor {
                    name,
                    lookup,
                    address,
                    base: 0,
                    delayed: false,
                };
                self.thunks(&descriptor, &mut walk);
            }
        }
        let delayed = self
            .directory(DIRECTORY_DELAY_IMPORT)
            .and_then(|(rva, _)| self.at(rva));
        if let Some(table) = delayed {
            for at in read::table(0, 32, limits::DESCRIPTORS) {
                let d = table.at(at);
                let fields = (|| Some([d.u32(0)?, d.u32(4)?, d.u32(12)?, d.u32(16)?]))();
                let Some([attributes, name, address, lookup]) = fields else {
                    break;
                };
                if name == 0 || address == 0 {
                    break;
                }
                // Before Visual C++ 7, the fields were addresses, not RVAs.
                let base = if attributes & 1 == 0 {
                    self.image_base
                } else {
                    0
                };
                let rva = |va: u32| u32::try_from(u64::from(va).wrapping_sub(base)).unwrap_or(0);
                let descriptor = Descriptor {
                    name: rva(name),
                    lookup: rva(lookup),
                    address: rva(address),
                    base,
                    delayed: true,
                };
                self.thunks(&descriptor, &mut walk);
            }
        }
        walk.imports
    }

    /// The imports of one descriptor.
    fn thunks(&self, d: &Descriptor, walk: &mut ImportWalk) {
        let r = &self.r;
        let width: u32 = if self.is_64 { 8 } else { 4 };
        let ordinal_flag = if self.is_64 { 1 << 63 } else { 1 << 31 };
        // The lookup table names the imports; the address table holds the
        // same until the loader binds it.
        let Some(table) = self.offset(d.lookup).or_else(|| self.offset(d.address)) else {
            return;
        };
        let library = self.name_at(d.name).unwrap_or_default();
        for (i, at) in (0_u32..).zip(read::table(table, u64::from(width), limits::THUNKS)) {
            if walk.entries == 0 || walk.budget == 0 {
                return;
            }
            walk.entries = walk.entries.saturating_sub(1);
            let Some(entry) = r.word(at, self.is_64) else {
                break;
            };
            if entry == 0 {
                break;
            }
            let (name, ordinal) = if entry & ordinal_flag != 0 {
                let ordinal = (entry & 0xffff) as u16;
                (format!("Ordinal_{ordinal}"), Some(ordinal))
            } else {
                // The hint, then the name.
                let rva = u32::try_from(entry.wrapping_sub(d.base) & 0x7fff_ffff).unwrap_or(0);
                match self.at(rva) {
                    Some(hint) if hint.u16(0).is_some() => (hint.name(2).into_owned(), None),
                    _ => continue,
                }
            };
            walk.budget = walk
                .budget
                .saturating_sub(name.len().saturating_add(library.len()));
            walk.imports.push(Import {
                slot: d.address.wrapping_add(width.wrapping_mul(i)),
                library: library.clone(),
                name,
                ordinal,
                delayed: d.delayed,
            });
        }
    }

    /// The TLS callbacks' addresses, which the loader runs before the entry
    /// point: the null-terminated array at `AddressOfCallBacks`.
    pub(super) fn tls_callbacks(&self) -> Vec<u64> {
        let Some(tls) = self
            .directory(DIRECTORY_TLS)
            .and_then(|(rva, _)| self.at(rva))
        else {
            return Vec::new();
        };
        let to_rva = |va: u64| u32::try_from(va.checked_sub(self.image_base)?).ok();
        let array = tls
            .word(if self.is_64 { 24 } else { 12 }, self.is_64)
            .and_then(to_rva)
            .and_then(|rva| self.offset(rva));
        let Some(array) = array else {
            return Vec::new();
        };
        let width = if self.is_64 { 8 } else { 4 };
        read::table(array, width, limits::TLS_CALLBACKS)
            .map_while(|at| self.r.word(at, self.is_64))
            .take_while(|&callback| callback != 0)
            // A callback outside the image's mapped bytes is no code.
            .filter(|&callback| to_rva(callback).and_then(|rva| self.offset(rva)).is_some())
            .collect()
    }

    /// The file offsets of the exception directory's entries of `size`
    /// bytes.
    fn runtime_functions(&self, size: u64) -> impl Iterator<Item = u64> + '_ {
        let (at, bytes) = self
            .directory(DIRECTORY_EXCEPTION)
            .and_then(|(rva, bytes)| Some((self.offset(rva)?, u64::from(bytes))))
            .unwrap_or((0, 0));
        read::entries(at, bytes, size)
    }

    /// The x64 `.pdata` entries that start functions, as (begin, end) RVAs.
    /// A chained entry continues a function that starts elsewhere.
    pub(super) fn x64_functions(&self) -> Vec<(u32, u32)> {
        let r = &self.r;
        self.runtime_functions(12)
            .map_while(|at| {
                let entry = r.at(at);
                Some((entry.u32(0)?, entry.u32(4)?, entry.u32(8)?))
            })
            .filter(|&(_, _, unwind)| !self.x64_chained(unwind))
            .map(|(begin, end, _)| (begin, end))
            .collect()
    }

    /// Whether the `UNWIND_INFO` at `unwind` has `UNW_FLAG_CHAININFO`. An
    /// odd RVA names another entry, whose unwind data this shares.
    fn x64_chained(&self, mut unwind: u32) -> bool {
        for _ in 0..limits::UNWIND_CHAIN {
            if unwind & 1 == 0 {
                break;
            }
            match self.at(unwind & !1).and_then(|entry| entry.u32(8)) {
                Some(next) => unwind = next,
                None => return false,
            }
        }
        let Some(info) = self.at(unwind) else {
            return false;
        };
        let (Some(header), Some(codes)) = (info.u8(0), info.u8(2)) else {
            return false;
        };
        let (version, flags) = (header & 7, header >> 3);
        if !(1..=2).contains(&version) || flags & UNW_FLAG_CHAININFO == 0 {
            return false;
        }
        // The chained entry (begin, end, unwind) follows the codes, padded
        // to an even count.
        let chained = u64::from(codes).next_multiple_of(2).saturating_mul(2);
        info.at(chained).u32(12).is_some()
    }

    /// The A64 `.pdata` entries that start functions, as RVAs: all but
    /// fragments, which continue a function MSVC shrink-wrapped.
    pub(super) fn arm64_functions(&self) -> Vec<u32> {
        let r = &self.r;
        self.runtime_functions(8)
            .map_while(|at| Some((r.u32(at)?, r.at(at).u32(4)?)))
            .filter(|&(_, unwind)| !self.arm64_fragment(unwind))
            .map(|(begin, _)| begin)
            .collect()
    }

    /// Windows CE's Arm `.pdata`, as (begin, end) addresses, begin odd for
    /// Thumb. An entry holds the function's address (not an RVA) and a word
    /// that packs the prologue's length (8 bits), the function's in
    /// instructions (22 bits), a flag set for 32-bit (Arm) code and one for
    /// an exception handler.
    pub(super) fn wince_functions(&self) -> Vec<(u64, u64)> {
        let r = &self.r;
        self.runtime_functions(8)
            .map_while(|at| Some((r.u32(at)?, r.at(at).u32(4)?)))
            .map(|(begin, packed)| {
                let arm = packed >> 30 & 1 != 0;
                let size = u64::from(packed >> 8 & 0x3f_ffff) << if arm { 2 } else { 1 };
                let begin = u64::from(begin);
                (begin | u64::from(!arm), begin.saturating_add(size))
            })
            .collect()
    }

    /// The 32-bit Arm (`ARMNT`) `.pdata` entries that start functions, as
    /// RVAs (Thumb, so odd): all but fragments, whose packed flag or
    /// `.xdata` `F` bit says they have no prologue of their own.
    pub(super) fn arm_functions(&self) -> Vec<u32> {
        let r = &self.r;
        self.runtime_functions(8)
            .map_while(|at| Some((r.u32(at)?, r.at(at).u32(4)?)))
            .filter(|&(_, unwind)| match unwind & 3 {
                0 => self
                    .at(unwind)
                    .and_then(|xdata| xdata.u32(0))
                    .is_some_and(|header| header >> 22 & 1 == 0),
                flag => flag == 1,
            })
            .map(|(begin, _)| begin | 1)
            .collect()
    }

    /// Whether an A64 entry's unwind data describes a fragment: packed data
    /// that says so, or `.xdata` whose unwind codes begin with `end_c`,
    /// which stands for the prologue a fragment does not have.
    fn arm64_fragment(&self, unwind: u32) -> bool {
        match unwind & 3 {
            0 => self.arm64_xdata_fragment(unwind).unwrap_or(false),
            flag => flag == ARM64_PACKED_FRAGMENT,
        }
    }

    fn arm64_xdata_fragment(&self, unwind: u32) -> Option<bool> {
        let xdata = self.at(unwind)?;
        let header = xdata.u32(0)?;
        if header >> 18 & 3 != 0 {
            return Some(false);
        }
        let exception_data = header >> 20 & 1 != 0;
        let epilog_in_header = header >> 21 & 1 != 0;
        let (mut epilogs, mut words) = (header >> 22 & 0x1f, header >> 27 & 0x1f);
        let mut codes: u64 = 4;
        if epilogs == 0 && words == 0 {
            let extension = xdata.u32(codes)?;
            (epilogs, words) = (extension & 0xffff, extension >> 16 & 0xff);
            codes = 8;
        }
        if !epilog_in_header {
            codes = codes.saturating_add(u64::from(epilogs) << 2);
        }
        let end = codes.saturating_add(u64::from(words) << 2);
        // The codes, and the handler's RVA after them, must be there.
        if words == 0 || xdata.u8(end.checked_sub(1)?).is_none() {
            return Some(false);
        }
        if exception_data && xdata.u32(end).is_none() {
            return Some(false);
        }
        Some(xdata.u8(codes) == Some(ARM64_END_C))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A PE32+ file with one section, `.text`, at RVA 0x1000 and file
    /// offset 0x200, holding `body`; the directories are (RVA, size) pairs.
    fn image(directories: &[(u32, u32)], body: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0; 0x40];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x40_u32.to_le_bytes());
        bytes.extend(b"PE\0\0");
        let optional_size = 112 + 8 * 16_u16;
        for half in [0x8664_u16, 1] {
            bytes.extend(half.to_le_bytes());
        }
        bytes.extend([0; 12]);
        bytes.extend(optional_size.to_le_bytes());
        bytes.extend(0x22_u16.to_le_bytes());
        let optional = bytes.len();
        bytes.resize(optional + usize::from(optional_size), 0);
        let mut put = |at: usize, value: &[u8]| {
            bytes[optional + at..optional + at + value.len()].copy_from_slice(value);
        };
        put(0, &0x20b_u16.to_le_bytes());
        put(16, &0x1010_u32.to_le_bytes());
        put(24, &0x1_4000_0000_u64.to_le_bytes());
        put(36, &0x200_u32.to_le_bytes());
        put(108, &16_u32.to_le_bytes());
        for (i, &(rva, size)) in directories.iter().enumerate() {
            put(112 + 8 * i, &rva.to_le_bytes());
            put(116 + 8 * i, &size.to_le_bytes());
        }
        bytes.extend(b".text\0\0\0");
        let raw = u32::try_from(body.len())
            .unwrap_or(0)
            .next_multiple_of(0x200);
        for word in [raw, 0x1000, raw, 0x200, 0, 0, 0] {
            bytes.extend(word.to_le_bytes());
        }
        bytes.extend(0x6000_0020_u32.to_le_bytes());
        bytes.resize(0x200, 0);
        bytes.extend(body);
        bytes.resize(0x200 + raw as usize, 0);
        bytes
    }

    fn parsed(bytes: &[u8]) -> Pe<'_> {
        parse(bytes).unwrap_or_else(|e| panic!("{e}"))
    }

    #[test]
    fn reads_the_headers_and_sections() {
        let bytes = image(&[], &[0xc3]);
        let pe = parsed(&bytes);
        assert_eq!((pe.machine, pe.is_64, pe.entry), (0x8664, true, 0x1010));
        assert_eq!(pe.image_base, 0x1_4000_0000);
        assert_eq!(pe.sections.len(), 1);
        assert_eq!(pe.offset(0x1004), Some(0x204));
        assert_eq!(pe.offset(0x3000), None);
    }

    #[test]
    fn long_section_names_only_from_a_string_table_that_fits() {
        // The section table follows the optional header; the COFF header's
        // symbol-table pointer is at 0x4c, its symbol count at 0x50.
        let named = |table: &[u8]| {
            let mut bytes = image(&[], &[0xc3]);
            bytes[0x148..0x150].copy_from_slice(b"/4\0\0\0\0\0\0");
            let at = u32::try_from(bytes.len()).unwrap_or(0);
            bytes[0x4c..0x50].copy_from_slice(&at.to_le_bytes());
            bytes.extend(table);
            parse(&bytes)
                .ok()
                .and_then(|pe| pe.sections.first().map(|s| s.name.clone()))
        };
        let mut table = 16_u32.to_le_bytes().to_vec();
        table.extend(b".debug_info\0");
        assert_eq!(named(&table).as_deref(), Some(".debug_info"));
        // A size past the end: what was there is no string table.
        table[..4].copy_from_slice(&0xaa0d_6469_u32.to_le_bytes());
        assert_eq!(named(&table).as_deref(), Some("/4"));
        // A name that is no text, or runs past the table.
        let mut table = 8_u32.to_le_bytes().to_vec();
        table.extend(b"\x07\x20\xa3\0");
        assert_eq!(named(&table).as_deref(), Some("/4"));
        let mut table = 6_u32.to_le_bytes().to_vec();
        table.extend(b".debug\0");
        assert_eq!(named(&table).as_deref(), Some("/4"));
    }

    #[test]
    fn rejects_what_is_no_pe() {
        assert!(parse(b"MZ").is_err());
        let mut bytes = image(&[], &[]);
        bytes[0x40] = b'X';
        assert!(parse(&bytes).is_err());
    }

    /// Directories past the end of the file, or with absurd counts, cost
    /// those directories only.
    #[test]
    fn bad_directories_cost_only_themselves() {
        let mut body = vec![0; 0x40];
        // An export directory claiming 2^31 names, its tables outside the file.
        body[24..28].copy_from_slice(&0x8000_0000_u32.to_le_bytes());
        body[28..32].copy_from_slice(&0xdead_0000_u32.to_le_bytes());
        let directories = [
            (0x1000, 0x28),
            (0x7fff_0000, 20),
            (0, 0),
            (0x1ff0, 0xffff_fff0),
        ];
        let bytes = image(&directories, &body);
        let pe = parsed(&bytes);
        assert!(pe.exports().is_empty());
        assert!(pe.imports().is_empty());
        assert!(pe.tls_callbacks().is_empty());
        // The exception table runs off the section: the entries there.
        assert!(pe.x64_functions().len() <= 2);
        assert_eq!(pe.entry, 0x1010);
    }

    /// A section table claiming more sections than the file holds.
    #[test]
    fn a_truncated_section_table_yields_what_was_read() {
        let mut bytes = image(&[], &[]);
        let count = 0x40 + 4 + 2;
        bytes[count..count + 2].copy_from_slice(&90_u16.to_le_bytes());
        bytes.truncate(0x200);
        let pe = parsed(&bytes);
        // Each 40-byte header that fits before the end.
        assert!(!pe.sections.is_empty() && pe.sections.len() < 90);
    }

    #[test]
    fn reads_exports_imports_and_tls() {
        let mut body = vec![0; 0x200];
        let mut put = |at: usize, value: &[u8]| body[at..at + value.len()].copy_from_slice(value);
        // Exports at 0x1000: two functions, two names; the second a forwarder.
        put(20, &2_u32.to_le_bytes());
        put(24, &2_u32.to_le_bytes());
        put(28, &0x1040_u32.to_le_bytes());
        put(32, &0x1050_u32.to_le_bytes());
        put(36, &0x1060_u32.to_le_bytes());
        put(0x40, &0x1100_u32.to_le_bytes());
        put(0x44, &0x1030_u32.to_le_bytes());
        put(0x30, b"k.Fwd\0");
        put(0x50, &0x1070_u32.to_le_bytes());
        put(0x54, &0x1078_u32.to_le_bytes());
        put(0x60, &[0, 0, 1, 0]);
        put(0x70, b"first\0");
        put(0x78, b"second\0");
        // Imports at 0x1080: one DLL, a name and an ordinal.
        put(0x80, &0x10c0_u32.to_le_bytes());
        put(0x8c, &0x10f0_u32.to_le_bytes());
        put(0x90, &0x10d8_u32.to_le_bytes());
        put(0xc0, &0x10e0_u64.to_le_bytes());
        put(0xc8, &(1_u64 << 63 | 7).to_le_bytes());
        put(0xe2, b"Sleep\0");
        put(0xf0, b"k.dll\0");
        // TLS at 0x1140, callbacks at 0x1180.
        put(0x158, &0x1_4000_1180_u64.to_le_bytes());
        put(0x180, &0x1_4000_1100_u64.to_le_bytes());
        // x64 .pdata at 0x11a0: one plain entry; unwind info at 0x11c0.
        put(0x1a0, &0x1100_u32.to_le_bytes());
        put(0x1a4, &0x1110_u32.to_le_bytes());
        put(0x1a8, &0x11c0_u32.to_le_bytes());
        put(0x1c0, &[1, 0, 0, 0]);
        let mut directories = [(0, 0); 10];
        directories[0] = (0x1000, 0x80);
        directories[1] = (0x1080, 40);
        directories[3] = (0x11a0, 12);
        directories[9] = (0x1140, 40);
        let bytes = image(&directories, &body);
        let pe = parsed(&bytes);
        let export = |rva, name: &str, forward: Option<&str>| Export {
            rva,
            name: name.into(),
            forward: forward.map(Into::into),
        };
        assert_eq!(
            pe.exports(),
            [
                export(0x1100, "first", None),
                export(0x1030, "second", Some("k.Fwd")),
            ]
        );
        let import = |slot, name: &str, ordinal| Import {
            slot,
            library: "k.dll".into(),
            name: name.into(),
            ordinal,
            delayed: false,
        };
        assert_eq!(
            pe.imports(),
            [
                import(0x10d8, "Sleep", None),
                import(0x10e0, "Ordinal_7", Some(7))
            ]
        );
        assert_eq!(pe.tls_callbacks(), [0x1_4000_1100]);
        assert_eq!(pe.x64_functions(), [(0x1100, 0x1110)]);
    }

    /// Import descriptors sharing one lookup table, every entry naming the
    /// same long string, claim gigabytes of names from a hundred kilobytes;
    /// the walk stops once the names spend its budget.
    #[test]
    fn shared_import_names_spend_a_budget() {
        let (lookup, name, entries) = (0x1_4000_usize, 0x1_6000_usize, 1000);
        // The table's and the name's RVAs: the section starts at 0x1000.
        let (lookup_rva, name_rva) = (0x1_5000_u32, 0x1_7000_u32);
        let mut body = vec![0; name + 0x1000];
        for d in 0..0x1000 {
            let at = 20 * d;
            body[at..at + 4].copy_from_slice(&lookup_rva.to_le_bytes());
            body[at + 12..at + 16].copy_from_slice(&name_rva.to_le_bytes());
            body[at + 16..at + 20].copy_from_slice(&lookup_rva.to_le_bytes());
        }
        for e in 0..entries {
            let at = lookup + 8 * e;
            body[at..at + 8].copy_from_slice(&u64::from(name_rva - 2).to_le_bytes());
        }
        body[name..name + 0xfff].fill(b'A');
        let bytes = image(&[(0, 0), (0x1000, 0x1000 * 20)], &body);
        let imports = parsed(&bytes).imports();
        assert!(!imports.is_empty());
        let names: usize = imports.iter().map(|i| i.name.len() + i.library.len()).sum();
        assert!(names <= limits::NAME_BYTES + 2 * 0x1000, "{names}");
    }

    #[test]
    fn chained_and_fragment_entries_start_nothing() {
        let mut body = vec![0; 0x100];
        let mut put = |at: usize, value: &[u8]| body[at..at + value.len()].copy_from_slice(value);
        // x64: a chained UNWIND_INFO (version 1, flags 4, no codes).
        put(0x40, &[1 | 4 << 3, 0, 0, 0]);
        // A64 .xdata: one code word, whose first code is end_c.
        put(0x60, &(1_u32 << 27).to_le_bytes());
        put(0x64, &[ARM64_END_C, 0xe4, 0xe4, 0xe4]);
        // ... and one whose first code is a prologue's.
        put(0x70, &(1_u32 << 27).to_le_bytes());
        put(0x74, &[0xe1, 0xe4, 0xe4, 0xe4]);
        let bytes = image(&[], &body);
        let pe = parsed(&bytes);
        assert!(pe.x64_chained(0x1040));
        assert!(!pe.x64_chained(0x1060));
        assert!(pe.arm64_fragment(0x1060));
        assert!(!pe.arm64_fragment(0x1070));
        assert!(pe.arm64_fragment(0x0004_0002));
        assert!(!pe.arm64_fragment(0x0004_0001));
        // Unwind data past the end of the file is no fragment.
        assert!(!pe.arm64_fragment(0x0fff_0000));
    }

    /// Overlapping sections: each RVA is the first section's, in header
    /// order, that backs it.
    #[test]
    fn overlapping_sections_back_rvas_in_header_order() {
        let section = |va: u32, size: u32, pointer: u32| Section {
            name: String::new(),
            virtual_size: size,
            virtual_address: va,
            size_of_raw_data: size,
            pointer_to_raw_data: pointer,
            characteristics: 0,
        };
        let sections = [
            section(0x2000, 0x1000, 0x400),
            section(0x1000, 0x3000, 0x1400),
            section(0x2800, 0x1000, 0x9000),
        ];
        let pe = Pe {
            r: Reader::new(&[], false),
            machine: 0,
            is_64: true,
            image_base: 0,
            entry: 0,
            directories: Vec::new(),
            spans: spans(&sections, 0x200),
            sections: Vec::new(),
        };
        assert_eq!(pe.offset(0x1004), Some(0x1404));
        assert_eq!(pe.offset(0x2004), Some(0x404));
        assert_eq!(pe.offset(0x2804), Some(0xc04));
        assert_eq!(pe.offset(0x3004), Some(0x3404));
        assert_eq!(pe.offset(0x3804), Some(0x3c04));
        assert_eq!(pe.offset(0x3fff), Some(0x43ff));
        assert_eq!(pe.offset(0x0fff), None);
        assert_eq!(pe.offset(0x4000), None);
    }

    /// 65,535 section headers, the one that backs the export directory
    /// last, and 200,000 named exports: each name's offset is a binary
    /// search, not a walk of the section table.
    #[test]
    fn many_sections_and_exports_read_fast() {
        let count = 200_000_u32;
        let (functions, names, ordinals, name) =
            (0x2000_u32, 0xd_0000_u32, 0x1a_0000_u32, 0x20_8000_u32);
        let mut body = vec![0_u8; 0x20_9000];
        let mut put = |at: u32, value: &[u8]| {
            let at = at as usize - 0x1000;
            body[at..at + value.len()].copy_from_slice(value);
        };
        for (at, word) in [(0x1014, count), (0x1018, count), (0x101c, functions)] {
            put(at, &word.to_le_bytes());
        }
        put(0x1020, &names.to_le_bytes());
        put(0x1024, &ordinals.to_le_bytes());
        put(name, b"a\0");
        for i in 0..count {
            put(functions + 4 * i, &0x1100_u32.to_le_bytes());
            put(names + 4 * i, &name.to_le_bytes());
            put(
                ordinals + 2 * i,
                &u16::try_from(i % 0x1_0000).unwrap_or(0).to_le_bytes(),
            );
        }
        let mut bytes = image(&[(0x1000, 0x28)], &[]);
        bytes.truncate(0x148);
        let sections = u16::MAX;
        bytes[0x46..0x48].copy_from_slice(&sections.to_le_bytes());
        let data = 0x148 + 40 * usize::from(sections);
        let data = data.next_multiple_of(0x200);
        for i in 1..u32::from(sections) {
            bytes.extend(b".junk\0\0\0");
            for word in [
                0x200,
                0x4000_0000 + 0x1000 * i,
                0x200,
                0x200,
                0,
                0,
                0,
                0x4000_0040,
            ] {
                bytes.extend(u32::to_le_bytes(word));
            }
        }
        bytes.extend(b".text\0\0\0");
        let size = u32::try_from(body.len()).unwrap_or(0);
        let pointer = u32::try_from(data).unwrap_or(0);
        for word in [size, 0x1000, size, pointer, 0, 0, 0, 0x6000_0020] {
            bytes.extend(u32::to_le_bytes(word));
        }
        bytes.resize(data, 0);
        bytes.extend(&body);
        let start = std::time::Instant::now();
        let pe = parsed(&bytes);
        let exports = pe.exports();
        assert_eq!(exports.len(), count as usize);
        assert_eq!(exports.first().map(|e| e.name.as_str()), Some("a"));
        assert!(start.elapsed().as_secs() < 5);
    }
}
