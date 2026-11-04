//! A Mach-O file's [`Binary`]: its code, where its functions start, and its
//! import slots.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};

use super::macho::{self, MachO};
use super::read::{self, Reader};
use super::{
    Error, Tables, bare, eh, file_range, go_seeds, gopclntab, import_table, limits, relocate, seed,
    unwind_seeds,
};
use crate::isa::Memory;
use crate::{Arch, Binary, Export, Format, Origin, Section, Segment, Slot};

/// The [`Binary`] of a universal binary's preferred slice.
pub(super) fn universal(bytes: &[u8]) -> Result<Binary<'_>, Error> {
    let slices = macho::fat(bytes)?;
    let slice = preferred_slice(&slices)
        .ok_or(Error::NotExecutable("a universal binary with no slices"))?;
    let slice = file_range(bytes, slice.offset, slice.size);
    Ok(binary(slice, &macho::parse(slice)?))
}

/// The [`Binary`] of a Mach-O file; its layout alone when binform does not
/// decode its instruction set.
pub(super) fn binary<'a>(bytes: &'a [u8], macho: &MachO) -> Binary<'a> {
    match arch(macho.cputype).filter(|_| !macho.big) {
        Some(arch) => image(bytes, macho, arch),
        None => {
            let slots = slots(macho);
            let tables = tables(bytes, macho, &slots);
            bare(Format::MachO, macho.entry, tables, slots)
        }
    }
}

fn arch(cputype: u32) -> Option<Arch> {
    match cputype {
        macho::CPU_TYPE_X86 => Some(Arch::X86),
        macho::CPU_TYPE_X86_64 => Some(Arch::X86_64),
        macho::CPU_TYPE_ARM64 => Some(Arch::Arm64),
        _ => None,
    }
}

/// The slice of a universal binary to read: the one a 64-bit x86 host
/// runs, else Apple silicon's, else 32-bit x86's, else the first. Fixed,
/// not the host's, so every machine reads the same slice.
fn preferred_slice(slices: &[macho::Slice]) -> Option<&macho::Slice> {
    let rank = |slice: &&macho::Slice| match arch(slice.cputype) {
        Some(Arch::X86_64) => 0,
        Some(Arch::Arm64) => 1,
        Some(_) => 2,
        None => 3,
    };
    // `min_by_key` keeps the first of equals: header order breaks ties.
    slices.iter().min_by_key(rank)
}

fn image<'a>(bytes: &'a [u8], macho: &MachO, arch: Arch) -> Binary<'a> {
    let sections = &macho.sections;
    let symbols = &macho.symbols;
    // An object's calls are linked to their symbols first.
    let (mut linked, mut slots) = if macho.filetype == macho::MH_OBJECT {
        relocate::macho(bytes, sections, symbols, arch)
    } else {
        (Vec::new(), Vec::new())
    };
    let segments: Vec<Segment<'a>> = sections
        .iter()
        .enumerate()
        .filter(|(_, section)| !section.zerofill())
        .map(|(i, section)| Segment {
            addr: section.addr,
            bytes: match linked.get_mut(i).and_then(Option::take) {
                Some(owned) => Cow::Owned(owned),
                None => Cow::Borrowed(file_range(bytes, section.offset, section.size)),
            },
            executable: section.code,
        })
        .collect();
    slots.extend(self::slots(macho));

    let mut seeds = Vec::new();
    if macho.entry != 0 {
        seeds.push(seed(macho.entry, Origin::Entry));
    }
    for symbol in symbols {
        if !symbol.is_stab()
            && symbol.n_type & macho::N_TYPE == macho::N_SECT
            && symbol.n_value != 0
        {
            seeds.push(seed(symbol.n_value, Origin::Symbol(symbol.name.clone())));
        }
    }
    let text = macho.text_base();
    if let (Some(mut addr), Some((offset, size))) = (text, macho.function_starts) {
        for delta in uleb128s(file_range(bytes, offset, size)).take_while(|&delta| delta != 0) {
            addr = addr.wrapping_add(delta);
            seeds.push(seed(addr, Origin::FunctionStarts));
        }
    }
    if let Some(section) = macho.section("__gopclntab") {
        let text = macho.section("__text").map(|section| section.addr);
        let table = file_range(bytes, section.offset, section.size);
        seeds.extend(go_seeds(gopclntab::functions(table, text, true, false)));
    }
    // Stubs: each jumps through the symbol pointer its index names.
    for section in sections {
        if section.kind() != macho::S_SYMBOL_STUBS || section.reserved2 == 0 {
            continue;
        }
        seeds.extend(
            read::entries(section.addr, section.size, u64::from(section.reserved2))
                .take(limits::STUBS)
                .map(|stub| seed(stub, Origin::Stub)),
        );
    }

    let memory = Memory::new(&segments);
    let mut pads = eh::Pads::new(if macho.is_64 { 8 } else { 4 });
    let mut extents = Vec::new();
    if let Some(section) = macho.section("__eh_frame") {
        extents = eh::eh_frame(&memory, section.addr, section.size, &mut pads);
        seeds.extend(unwind_seeds(&extents));
    }
    if let (Some(base), Some(section)) = (text, macho.section("__unwind_info")) {
        let info = file_range(bytes, section.offset, section.size);
        for (function, lsda) in unwind_info_lsdas(info) {
            let function = base.wrapping_add(u64::from(function));
            pads.add(&memory, function, base.wrapping_add(u64::from(lsda)));
        }
    }

    let tables = tables(bytes, macho, &slots);
    Binary {
        arch: Some(arch),
        segments,
        seeds,
        handlers: pads.handlers,
        extents,
        ..bare(Format::MachO, macho.entry, tables, slots)
    }
}

/// A Mach-O file's import slots: the symbol pointers the indirect symbol
/// table names.
fn slots(macho: &MachO) -> Vec<Slot> {
    let pointer: u64 = if macho.is_64 { 8 } else { 4 };
    let mut slots = Vec::new();
    for section in &macho.sections {
        let kind = section.kind();
        if kind != macho::S_NON_LAZY_SYMBOL_POINTERS && kind != macho::S_LAZY_SYMBOL_POINTERS {
            continue;
        }
        let first = usize::try_from(section.reserved1).unwrap_or(usize::MAX);
        let entries = macho.indirect.iter().skip(first);
        for (slot, &index) in read::entries(section.addr, section.size, pointer).zip(entries) {
            if index & macho::INDIRECT_SYMBOL_LOCAL_OR_ABS != 0 {
                continue;
            }
            if let Some(symbol) = usize::try_from(index)
                .ok()
                .and_then(|index| macho.symbols.get(index))
                && !symbol.name.is_empty()
            {
                slots.push(Slot {
                    slot,
                    name: symbol.name.clone(),
                    import: None,
                });
            }
        }
    }
    slots
}

/// An install name's library stem: `/usr/lib/libSystem.B.dylib` is
/// `libSystem.B`.
fn dylib_stem(path: &str) -> &str {
    let base = path.rsplit_once('/').map_or(path, |(_, base)| base);
    base.strip_suffix(".dylib")
        .or_else(|| base.strip_suffix(".tbd"))
        .unwrap_or(base)
}

/// A Mach-O file's sections, imports and exports.
fn tables(bytes: &[u8], macho: &MachO, slots: &[Slot]) -> Tables {
    let symbols = &macho.symbols;
    let sections = macho
        .sections
        .iter()
        .map(|section| Section {
            name: section.full_name(),
            addr: section.addr,
            size: section.size,
            offset: section.offset,
            file_size: if section.zerofill() { 0 } else { section.size },
            flags: u64::from(section.flags),
            readable: section.protection & 1 != 0,
            writable: section.protection & 2 != 0,
            executable: section.protection & 4 != 0,
        })
        .collect();
    let external = |symbol: &&macho::Symbol| {
        !symbol.is_stab() && symbol.n_type & macho::N_EXT != 0 && !symbol.name.is_empty()
    };
    // Ordinals count the dylibs from 1; 0 is this image, 0xfe (or, bound,
    // -1) the executable, 0xff (-2) whichever library defines the symbol.
    let dylib = |ordinal: i64| {
        usize::try_from(ordinal)
            .ok()?
            .checked_sub(1)
            .and_then(|i| macho.dylibs.get(i))
            .map(String::as_str)
    };
    // dyld's binds name the library where the symbol table does not: Go's
    // linker leaves the two-level ordinal zero, and a chained-fixups
    // binary's import table is the record dyld reads.
    let binds = macho::bound_ordinals(bytes, macho);
    let bound: HashMap<&str, i64> = binds.iter().map(|(name, n)| (name.as_str(), *n)).collect();
    let undefined: Vec<(&str, Option<&str>)> = symbols
        .iter()
        .filter(external)
        .filter(|symbol| symbol.n_type & macho::N_TYPE == macho::N_UNDF)
        .map(|symbol| {
            let library = dylib(i64::from(symbol.n_desc >> 8))
                .or_else(|| bound.get(symbol.name.as_str()).copied().and_then(dylib));
            (symbol.name.as_str(), library)
        })
        .collect();
    // Names only the binds hold: a binary stripped of its undefined symbols.
    let listed: HashSet<&str> = undefined.iter().map(|&(name, _)| name).collect();
    let unlisted = binds
        .iter()
        .filter(|(name, _)| !listed.contains(name.as_str()))
        .map(|(name, ordinal)| (name.as_str(), dylib(*ordinal)));
    let imports = import_table(slots, undefined.iter().copied().chain(unlisted));
    // The symbol table's defined external symbols, and the export trie's
    // (all a stripped dylib has), once per name. A re-export forwards to
    // its library's stem and symbol, as a PE forwarder names its DLL.
    let text = macho.text_base().unwrap_or(0);
    let trie = macho
        .exports_trie
        .map(|(offset, size)| macho::exports_trie(file_range(bytes, offset, size)))
        .unwrap_or_default();
    let mut exports: Vec<Export> = symbols
        .iter()
        .filter(external)
        // A private external symbol is linked as one but not exported.
        .filter(|symbol| symbol.n_type & macho::N_TYPE == macho::N_SECT)
        .filter(|symbol| symbol.n_type & macho::N_PEXT == 0)
        .map(|symbol| (symbol.name.clone(), symbol.n_value, None))
        .chain(trie.into_iter().map(|(name, exported)| match exported {
            macho::Exported::At(offset) => (name, text.wrapping_add(offset), None),
            macho::Exported::Reexport {
                ordinal,
                name: there,
            } => {
                let library = i64::try_from(ordinal).ok().and_then(dylib).map(dylib_stem);
                let there = if there.is_empty() {
                    name.clone()
                } else {
                    there
                };
                let forward = library.map(|library| format!("{library}.{there}"));
                (name, 0, Some(forward.unwrap_or(there)))
            }
        }))
        .map(|(name, addr, forward)| Export {
            name,
            addr: (addr != 0).then_some(addr),
            forward,
        })
        .collect();
    let mut seen = HashSet::new();
    let first: Vec<bool> = exports
        .iter()
        .map(|export| seen.insert(export.name.as_str()))
        .collect();
    let mut first = first.into_iter();
    exports.retain(|_| first.next().unwrap_or(false));

    Tables {
        sections,
        imports,
        exports,
    }
}

/// The (function, LSDA) pairs of a compact unwind table, as offsets from
/// the image base. The first-level index's entries each point at a run of
/// LSDA entries; the runs are contiguous, so the table is the span from the
/// first entry's run to the last's (the sentinel).
fn unwind_info_lsdas(info: &[u8]) -> impl Iterator<Item = (u32, u32)> + '_ {
    let r = Reader::new(info, false);
    let span = (|| {
        if r.u32(0)? != 1 {
            return None;
        }
        let index = u64::from(r.u32(20)?);
        let count = u64::from(r.u32(24)?);
        let last = index.checked_add(count.checked_sub(1)?.checked_mul(12)?)?;
        let start = usize::try_from(r.at(index).u32(8)?).ok()?;
        let end = usize::try_from(r.at(last).u32(8)?).ok()?;
        info.get(start..end.max(start))
    })()
    .unwrap_or_default();
    span.chunks_exact(8).filter_map(|pair| {
        let pair = Reader::new(pair, false);
        Some((pair.u32(0)?, pair.u32(4)?))
    })
}

/// The ULEB128 values packed in `data`, ending at the first truncated one.
fn uleb128s(data: &[u8]) -> impl Iterator<Item = u64> + '_ {
    let mut at = 0;
    std::iter::from_fn(move || read::uleb128(data, &mut at))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uleb128() {
        let values: Vec<u64> = uleb128s(&[0x02, 0xe5, 0x8e, 0x26, 0x80]).collect();
        assert_eq!(values, [2, 624_485]);
    }

    /// A compact unwind table: two first-level entries (the second the
    /// sentinel) and the run of LSDA entries between them.
    #[test]
    fn unwind_info_names_lsdas() {
        let words: [u32; 17] = [
            1, 28, 0, 28, 0, 28, 2, // header: version, encodings, personalities, index
            0x1000, 0, 52, // index entry: its LSDA run starts at 52
            0x2000, 0, 68, // sentinel: the run ends at 68
            0x1000, 0x4000, 0x1100, 0x4010, // (function, LSDA) pairs
        ];
        let info: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        let pairs: Vec<(u32, u32)> = unwind_info_lsdas(&info).collect();
        assert_eq!(pairs, [(0x1000, 0x4000), (0x1100, 0x4010)]);
        assert_eq!(
            unwind_info_lsdas(info.get(..30).unwrap_or_default()).count(),
            0
        );
        assert_eq!(unwind_info_lsdas(&[]).count(), 0);
    }

    #[test]
    fn a_universal_binary_reads_its_x86_64_slice_first() {
        let slice = |cputype| macho::Slice {
            cputype,
            offset: 0,
            size: 0,
        };
        let pick = |types: &[u32]| {
            let slices: Vec<macho::Slice> = types.iter().copied().map(slice).collect();
            preferred_slice(&slices).map(|s| s.cputype)
        };
        let (i386, x64, a64, ppc) = (
            macho::CPU_TYPE_X86,
            macho::CPU_TYPE_X86_64,
            macho::CPU_TYPE_ARM64,
            18,
        );
        assert_eq!(pick(&[i386, x64, ppc]), Some(x64));
        assert_eq!(pick(&[a64, x64]), Some(x64));
        assert_eq!(pick(&[ppc, a64, i386]), Some(a64));
        assert_eq!(pick(&[ppc, i386]), Some(i386));
        assert_eq!(pick(&[ppc]), Some(ppc));
        assert_eq!(pick(&[]), None);
    }

    /// A chained-fixups binary's import table (`DYLD_CHAINED_IMPORT`)
    /// binds every import to the library its symbol's two-level ordinal
    /// names: the table read right, on a real file.
    #[test]
    fn chained_fixup_imports_agree_with_the_symbol_table() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testdata/chained-fixups-ios-arm64.zst"
        );
        let compressed = std::fs::read(path).unwrap_or_else(|e| panic!("{path}: {e}"));
        let bytes = zstd::decode_all(&compressed[..]).unwrap_or_else(|e| panic!("{path}: {e}"));
        let image = macho::parse(&bytes).unwrap_or_else(|e| panic!("{e}"));
        assert!(image.binds.is_empty() && image.chained_fixups.is_some());
        let bound: HashMap<String, i64> =
            macho::bound_ordinals(&bytes, &image).into_iter().collect();
        let undefined: Vec<&macho::Symbol> = image
            .symbols
            .iter()
            .filter(|s| s.n_type & macho::N_EXT != 0 && s.n_type & macho::N_TYPE == macho::N_UNDF)
            .collect();
        assert_eq!((undefined.len(), bound.len()), (93, 93));
        for symbol in undefined {
            assert_eq!(
                bound.get(&symbol.name).copied(),
                Some(i64::from(symbol.n_desc >> 8)),
                "{}",
                symbol.name
            );
        }
        let bin = crate::parse(&bytes).unwrap_or_else(|e| panic!("{e}"));
        let library = |name: &str| {
            bin.imports
                .iter()
                .find(|i| i.name == name)
                .and_then(|i| i.library.as_deref())
        };
        assert_eq!(library("_sqlite3_close"), Some("/usr/lib/libsqlite3.dylib"));
        assert!(bin.imports.iter().all(|i| i.library.is_some()));
    }
}
