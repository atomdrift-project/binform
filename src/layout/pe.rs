//! The parts of a PE file recovery uses, read leniently. The headers and
//! the section table are read first; each directory is then read on its
//! own, so one that is truncated or points nowhere costs that directory,
//! not the file. The CLR (COR20) directory is never read: recovery does not
//! need it, and a malformed one is common in obfuscated .NET binaries.

use super::read::Reader;

/// The most entries read from any one table.
const MOST: u64 = 1 << 20;

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
    pub(super) file_alignment: u32,
    pub(super) section_alignment: u32,
    pub(super) sections: Vec<Section>,
    /// Each data directory's (RVA, size).
    directories: Vec<(u32, u32)>,
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

/// The PE file in `bytes`, or why it is none: only a missing signature or
/// an unknown optional header fails.
pub(super) fn parse(bytes: &[u8]) -> Result<Pe<'_>, String> {
    let r = Reader::new(bytes, false);
    let nt = u64::from(r.u32(0x3c).ok_or("DOS header truncated")?);
    if r.u32(nt) != Some(0x0000_4550) {
        return Err("no PE signature".into());
    }
    let coff = nt + 4;
    let (machine, count, optional_size) =
        (|| Some((r.u16(coff)?, r.u16(coff + 2)?, r.u16(coff + 16)?)))()
            .ok_or("COFF header truncated")?;
    let optional = coff + 20;
    let is_64 = match r.u16(optional) {
        Some(0x10b) => false,
        Some(0x20b) => true,
        Some(magic) => return Err(format!("unknown optional header magic {magic:#x}")),
        None => return Err("optional header truncated".into()),
    };
    let entry = r.u32(optional + 16).unwrap_or(0);
    let image_base = if is_64 {
        r.u64(optional + 24)
    } else {
        r.u32(optional + 28).map(u64::from)
    }
    .unwrap_or(0);
    let section_alignment = r.u32(optional + 32).unwrap_or(0);
    let file_alignment = r.u32(optional + 36).unwrap_or(0);
    let (count_at, first) = if is_64 { (108, 112) } else { (92, 96) };
    // The directories that fit in the optional header the COFF header sizes.
    let fit = u64::from(optional_size).saturating_sub(first) / 8;
    let directories = (0..r
        .u32(optional + count_at)
        .map_or(0, u64::from)
        .min(fit)
        .min(16))
        .map_while(|i| {
            let at = optional + first + 8 * i;
            Some((r.u32(at)?, r.u32(at + 4)?))
        })
        .collect();
    let table = optional + u64::from(optional_size);
    // Long section names (`/4`) are offsets into the COFF string table,
    // which follows the symbol table.
    let strings = r
        .u32(coff + 8)
        .filter(|&symbols| symbols != 0)
        .map(|symbols| u64::from(symbols) + 18 * u64::from(r.u32(coff + 12).unwrap_or(0)));
    let sections = (0..u64::from(count))
        .map_while(|i| {
            let at = table + 40 * i;
            let raw = r.array::<8>(at)?;
            let raw = raw.split(|&b| b == 0).next().unwrap_or_default();
            let long = raw
                .strip_prefix(b"/")
                .and_then(|digits| std::str::from_utf8(digits).ok()?.parse::<u64>().ok())
                .zip(strings)
                .map(|(offset, strings)| r.name(strings + offset).into_owned());
            Some(Section {
                name: long.unwrap_or_else(|| String::from_utf8_lossy(raw).into_owned()),
                virtual_size: r.u32(at + 8)?,
                virtual_address: r.u32(at + 12)?,
                size_of_raw_data: r.u32(at + 16)?,
                pointer_to_raw_data: r.u32(at + 20)?,
                characteristics: r.u32(at + 36)?,
            })
        })
        .collect();
    Ok(Pe {
        r,
        machine,
        is_64,
        image_base,
        entry,
        file_alignment,
        section_alignment,
        sections,
        directories,
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
            .saturating_add(file_alignment - 1)
            & !(file_alignment - 1);
        let size = end.saturating_sub(pointer & !0x1ff).min(page(raw));
        match u64::from(self.virtual_size) {
            0 => size,
            virtual_size => size.min(page(virtual_size)),
        }
    }
}

impl Pe<'_> {
    /// The file offset of `rva`, by the first section that backs it.
    pub(super) fn offset(&self, rva: u32) -> Option<u64> {
        // An alignment that is no power of two is the loader's default.
        let alignment = match u64::from(self.file_alignment) {
            a if a.is_power_of_two() => a,
            _ => 0x200,
        };
        let rva = u64::from(rva);
        self.sections
            .iter()
            .find(|section| {
                let start = u64::from(section.virtual_address);
                rva >= start && rva - start < section.read_size(alignment)
            })
            .map(|section| {
                u64::from(section.pointer_to_raw_data) + (rva - u64::from(section.virtual_address))
            })
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

    /// The NUL-terminated name at `rva`.
    fn name_at(&self, rva: u32) -> Option<String> {
        Some(self.r.name(self.offset(rva)?).into_owned())
    }

    /// The named exports: each one's RVA and name. A forwarder, whose RVA
    /// lies inside the export directory and names another DLL's export,
    /// is left out.
    pub(super) fn exports(&self) -> Vec<Export> {
        let Some((dir, size)) = self.directory(DIRECTORY_EXPORT) else {
            return Vec::new();
        };
        let Some(at) = self.offset(dir) else {
            return Vec::new();
        };
        let r = &self.r;
        let fields = (|| {
            Some((
                r.u32(at + 20)?,
                r.u32(at + 24)?,
                r.u32(at + 28)?,
                r.u32(at + 32)?,
                r.u32(at + 36)?,
            ))
        })();
        let Some((functions, names, function_table, name_table, ordinal_table)) = fields else {
            return Vec::new();
        };
        let ordinal_base = r.u32(at + 16).unwrap_or(1);
        let (Some(function_table), Some(name_table), Some(ordinal_table)) = (
            self.offset(function_table),
            self.offset(name_table),
            self.offset(ordinal_table),
        ) else {
            return Vec::new();
        };
        // Each function by its index: the names table names some of them;
        // the rest are exported by ordinal only.
        let mut named: Vec<Option<String>> =
            vec![None; usize::try_from(u64::from(functions).min(MOST)).unwrap_or(0)];
        for i in 0..u64::from(names).min(MOST) {
            let Some(index) = r.u16(ordinal_table + 2 * i) else {
                break;
            };
            if let Some(slot) = named.get_mut(usize::from(index))
                && slot.is_none()
            {
                *slot = r
                    .u32(name_table + 4 * i)
                    .and_then(|name| self.name_at(name));
            }
        }
        (0_u32..)
            .zip(named)
            .filter_map(|(index, name)| {
                let rva = r.u32(function_table + 4 * u64::from(index))?;
                if rva == 0 {
                    return None;
                }
                // A forwarder's RVA lies inside the export directory and
                // names another DLL's export.
                let forward = (rva >= dir && rva - dir < size)
                    .then(|| self.name_at(rva))
                    .flatten();
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
    /// one imported by ordinal only).
    pub(super) fn imports(&self) -> Vec<Import> {
        let r = &self.r;
        let mut imports = Vec::new();
        if let Some(mut at) = self
            .directory(DIRECTORY_IMPORT)
            .and_then(|(rva, _)| self.offset(rva))
        {
            for _ in 0..1 << 12 {
                let descriptor = (|| Some([r.u32(at)?, r.u32(at + 12)?, r.u32(at + 16)?]))();
                let Some([lookup, name, address]) = descriptor else {
                    break;
                };
                at += 20;
                // The table ends at an empty descriptor, or one naming no
                // DLL or slots.
                if name == 0 || address == 0 {
                    break;
                }
                self.thunks(lookup, name, address, 0, &mut imports);
            }
        }
        if let Some(mut at) = self
            .directory(DIRECTORY_DELAY_IMPORT)
            .and_then(|(rva, _)| self.offset(rva))
        {
            for _ in 0..1 << 12 {
                let descriptor =
                    (|| Some([r.u32(at)?, r.u32(at + 4)?, r.u32(at + 12)?, r.u32(at + 16)?]))();
                let Some([attributes, name, address, lookup]) = descriptor else {
                    break;
                };
                at += 32;
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
                self.thunks(rva(lookup), rva(name), rva(address), base, &mut imports);
            }
        }
        imports
    }

    /// The imports of one descriptor: DLL `name`, its lookup and address
    /// tables. `base` is subtracted from name addresses that are no RVAs.
    fn thunks(&self, lookup: u32, name: u32, address: u32, base: u64, out: &mut Vec<Import>) {
        let r = &self.r;
        let width: u32 = if self.is_64 { 8 } else { 4 };
        let ordinal_flag = if self.is_64 { 1 << 63 } else { 1 << 31 };
        // The lookup table names the imports; the address table holds the
        // same until the loader binds it.
        let Some(table) = self.offset(lookup).or_else(|| self.offset(address)) else {
            return;
        };
        let library = self.name_at(name).unwrap_or_default();
        for i in 0..1_u32 << 16 {
            let Some(entry) = r.word(table + u64::from(width * i), self.is_64) else {
                break;
            };
            if entry == 0 {
                break;
            }
            let slot = address.wrapping_add(width * i);
            let (name, ordinal) = if entry & ordinal_flag != 0 {
                let ordinal = (entry & 0xffff) as u16;
                (format!("Ordinal_{ordinal}"), Some(ordinal))
            } else {
                // The hint, then the name.
                let rva = u32::try_from(entry.wrapping_sub(base) & 0x7fff_ffff).unwrap_or(0);
                match self.offset(rva) {
                    Some(hint) if r.u16(hint).is_some() => (r.name(hint + 2).into_owned(), None),
                    _ => continue,
                }
            };
            out.push(Import {
                slot,
                library: library.clone(),
                name,
                ordinal,
            });
        }
    }

    /// The TLS callbacks' addresses, which the loader runs before the entry
    /// point: the null-terminated array at `AddressOfCallBacks`.
    pub(super) fn tls_callbacks(&self) -> Vec<u64> {
        let Some(at) = self
            .directory(DIRECTORY_TLS)
            .and_then(|(rva, _)| self.offset(rva))
        else {
            return Vec::new();
        };
        let array = self
            .r
            .word(at + if self.is_64 { 24 } else { 12 }, self.is_64)
            .and_then(|va| va.checked_sub(self.image_base))
            .and_then(|rva| u32::try_from(rva).ok())
            .and_then(|rva| self.offset(rva));
        let Some(array) = array else {
            return Vec::new();
        };
        let width = if self.is_64 { 8 } else { 4 };
        (0..1 << 12)
            .map_while(|i| self.r.word(array + width * i, self.is_64))
            .take_while(|&callback| callback != 0)
            // A callback outside the image's mapped bytes is no code.
            .filter(|&callback| {
                callback
                    .checked_sub(self.image_base)
                    .and_then(|rva| u32::try_from(rva).ok())
                    .and_then(|rva| self.offset(rva))
                    .is_some()
            })
            .collect()
    }

    /// The exception directory's entries: the file offset of the first and
    /// how many there are of `size` bytes.
    fn runtime_functions(&self, size: u64) -> impl Iterator<Item = u64> + '_ {
        let (at, count) = self
            .directory(DIRECTORY_EXCEPTION)
            .and_then(|(rva, bytes)| Some((self.offset(rva)?, u64::from(bytes) / size)))
            .unwrap_or((0, 0));
        (0..count.min(MOST)).map(move |i| at + size * i)
    }

    /// The x64 `.pdata` entries that start functions, as (begin, end) RVAs.
    /// A chained entry continues a function that starts elsewhere.
    pub(super) fn x64_functions(&self) -> Vec<(u32, u32)> {
        let r = &self.r;
        self.runtime_functions(12)
            .map_while(|at| Some((r.u32(at)?, r.u32(at + 4)?, r.u32(at + 8)?)))
            .filter(|&(_, _, unwind)| !self.x64_chained(unwind))
            .map(|(begin, end, _)| (begin, end))
            .collect()
    }

    /// Whether the `UNWIND_INFO` at `unwind` has `UNW_FLAG_CHAININFO`. An
    /// odd RVA names another entry, whose unwind data this shares.
    fn x64_chained(&self, mut unwind: u32) -> bool {
        let r = &self.r;
        for _ in 0..32 {
            if unwind & 1 == 0 {
                break;
            }
            match self.offset(unwind & !1).and_then(|at| r.u32(at + 8)) {
                Some(next) => unwind = next,
                None => return false,
            }
        }
        let Some(at) = self.offset(unwind) else {
            return false;
        };
        let (Some(header), Some(codes)) = (r.u8(at), r.u8(at + 2)) else {
            return false;
        };
        let (version, flags) = (header & 7, header >> 3);
        if !(1..=2).contains(&version) || flags & UNW_FLAG_CHAININFO == 0 {
            return false;
        }
        // The chained entry follows the codes, padded to an even count.
        let codes = u64::from(codes).next_multiple_of(2);
        r.u32(at + 4 + 2 * codes + 8).is_some()
    }

    /// The A64 `.pdata` entries that start functions, as RVAs: all but
    /// fragments, which continue a function MSVC shrink-wrapped.
    pub(super) fn arm64_functions(&self) -> Vec<u32> {
        let r = &self.r;
        self.runtime_functions(8)
            .map_while(|at| Some((r.u32(at)?, r.u32(at + 4)?)))
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
            .map_while(|at| Some((r.u32(at)?, r.u32(at + 4)?)))
            .map(|(begin, packed)| {
                let arm = packed >> 30 & 1 != 0;
                let size = u64::from(packed >> 8 & 0x3f_ffff) * if arm { 4 } else { 2 };
                let begin = u64::from(begin);
                (begin | u64::from(!arm), begin + size)
            })
            .collect()
    }

    /// The 32-bit Arm (`ARMNT`) `.pdata` entries that start functions, as
    /// RVAs (Thumb, so odd): all but fragments, whose packed flag or
    /// `.xdata` `F` bit says they have no prologue of their own.
    pub(super) fn arm_functions(&self) -> Vec<u32> {
        let r = &self.r;
        self.runtime_functions(8)
            .map_while(|at| Some((r.u32(at)?, r.u32(at + 4)?)))
            .filter(|&(_, unwind)| match unwind & 3 {
                0 => self
                    .offset(unwind)
                    .and_then(|at| r.u32(at))
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
            0 => {}
            flag => return flag == ARM64_PACKED_FRAGMENT,
        }
        let r = &self.r;
        let Some(at) = self.offset(unwind) else {
            return false;
        };
        let Some(header) = r.u32(at) else {
            return false;
        };
        if header >> 18 & 3 != 0 {
            return false;
        }
        let exception_data = header >> 20 & 1 != 0;
        let epilog_in_header = header >> 21 & 1 != 0;
        let (mut epilogs, mut words) = (header >> 22 & 0x1f, header >> 27 & 0x1f);
        let mut codes = at + 4;
        if epilogs == 0 && words == 0 {
            let Some(extension) = r.u32(codes) else {
                return false;
            };
            (epilogs, words) = (extension & 0xffff, extension >> 16 & 0xff);
            codes += 4;
        }
        if !epilog_in_header {
            codes += 4 * u64::from(epilogs);
        }
        let end = codes + 4 * u64::from(words);
        // The codes, and the handler's RVA after them, must be there.
        if words == 0 || r.u8(end - 1).is_none() {
            return false;
        }
        if exception_data && r.u32(end).is_none() {
            return false;
        }
        r.u8(codes) == Some(ARM64_END_C)
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
}
