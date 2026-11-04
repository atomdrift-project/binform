//! `binform-ab goblin`: binform's layout tables against goblin's, as filefacts
//! reads goblin today.
//!
//! goblin is a dependency of this tools crate only, never of `binform`: the
//! comparison exists so filefacts can move its section, import and export
//! views from goblin to binform knowing, file by file, what changes.
//!
//! Each side is normalised to the convention filefacts emits, so a reported
//! difference is one a filefacts consumer would see:
//!
//! - sections: PE addresses as RVAs; Mach-O names `__SEGMENT.__section`;
//!   permissions as binform derives them (ELF readable = `SHF_ALLOC`,
//!   Mach-O from the segment's `initprot`); file size zero for a section
//!   the file holds no bytes of (`SHT_NOBITS`, Mach-O zero-fill).
//! - imports: PE keyed by lowercase DLL and name, an ordinal import as
//!   `#n` on both sides, located at its address-table slot's RVA; ELF the
//!   dynamic symbols with no section; Mach-O the dyld binds, else the
//!   undefined external symbols, each library reduced to its stem.
//! - exports: PE the named exports at their RVA, forwarders as `LIB.name`
//!   or `LIB.#n`; ELF the defined function and object dynamic symbols;
//!   Mach-O the export trie.
//!
//! A universal Mach-O is compared slice by slice: `binform::parse` is run on
//! each slice's bytes, so the comparison does not depend on which slice
//! either side would pick for the whole file.

use std::collections::BTreeMap;
use std::panic::{AssertUnwindSafe, catch_unwind};

use goblin::elf::Elf;
use goblin::mach::{Mach, MachO};
use goblin::pe::PE;
use serde_json::{Value, json};

/// Entries listed per difference kind, per table, per file: 8, or
/// `BINFORM_AB_SHOWN`.
fn shown() -> usize {
    static SHOWN: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *SHOWN.get_or_init(|| {
        std::env::var("BINFORM_AB_SHOWN")
            .ok()
            .and_then(|n| n.parse().ok())
            .unwrap_or(8)
    })
}

/// One section, in the shape both sides are compared in.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Section {
    name: String,
    addr: u64,
    size: u64,
    offset: u64,
    file_size: u64,
    flags: u64,
    readable: bool,
    writable: bool,
    executable: bool,
}

/// One import, keyed by `(library, name)`.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Import {
    library: Option<String>,
    name: String,
    /// PE only: the address-table slot's RVA.
    slot: Option<u64>,
}

/// One export, keyed by name.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Export {
    name: String,
    addr: Option<u64>,
    forward: Option<String>,
}

#[derive(Default)]
struct Tables {
    sections: Vec<Section>,
    imports: Vec<Import>,
    exports: Vec<Export>,
}

/// Compare one file; `None` for a file neither side reads as ELF, PE or
/// Mach-O.
pub(crate) fn compare(file: &std::path::Path) -> Option<Vec<Value>> {
    let name = file.to_string_lossy();
    if name.ends_with(".json.zst") {
        return None;
    }
    let bytes = std::fs::read(file).ok()?;
    // binform's fixtures are zstd-compressed.
    let bytes = if name.ends_with(".zst") {
        zstd::decode_all(bytes.as_slice()).ok()?
    } else {
        bytes
    };
    let path = file.display().to_string();
    let kind = match bytes.get(..4)? {
        b"\x7fELF" => "Elf",
        [b'M', b'Z', ..] => "Pe",
        [0xca, 0xfe, 0xba, 0xbe | 0xbf] => "Fat",
        [0xfe, 0xed, 0xfa, 0xce | 0xcf] | [0xce | 0xcf, 0xfa, 0xed, 0xfe] => "MachO",
        _ => return None,
    };
    if kind != "Fat" {
        return Some(vec![compare_image(&path, None, kind, &bytes)]);
    }
    // A universal binary: every slice goblin's arch table lists.
    let arches = guarded(|| match Mach::parse(&bytes) {
        Ok(Mach::Fat(fat)) => Ok(fat
            .iter_arches()
            .take(64)
            .map_while(Result::ok)
            .map(|arch| (arch.offset as usize, arch.size as usize))
            .collect::<Vec<_>>()),
        Ok(Mach::Binary(_)) => Err("not universal".to_owned()),
        Err(e) => Err(e.to_string()),
    });
    let arches = match arches {
        Ok(arches) => arches,
        Err(error) => {
            return Some(vec![json!({
                "path": path,
                "format": "MachO",
                "goblin_error": error,
            })]);
        }
    };
    Some(
        arches
            .into_iter()
            .enumerate()
            .filter_map(|(i, (start, size))| {
                let slice = bytes.get(start..start.checked_add(size)?)?;
                Some(compare_image(&path, Some(i), "MachO", slice))
            })
            .collect(),
    )
}

fn compare_image(path: &str, slice: Option<usize>, kind: &str, bytes: &[u8]) -> Value {
    let mut report = json!({ "path": path, "format": kind });
    if let Some(slice) = slice {
        report["slice"] = json!(slice);
    }
    let theirs = guarded(|| match kind {
        "Elf" => goblin_elf(bytes),
        "Pe" => goblin_pe(bytes),
        _ => goblin_macho(bytes),
    });
    // binform's PE addresses are VAs; filefacts' are RVAs. The image base is
    // goblin's, which binform reads from the same header field.
    let image_base = theirs.as_ref().ok().map_or(0, |(_, base)| *base);
    let ours = binform::parse(bytes)
        .map_err(|e| e.to_string())
        .map(|bin| from_binform(&bin, image_base));
    let (theirs, ours) = match (theirs, ours) {
        (Ok((theirs, _)), Ok(ours)) => (theirs, ours),
        (theirs, ours) => {
            if let Err(e) = theirs {
                report["goblin_error"] = json!(e);
            }
            if let Err(e) = ours {
                report["binform_error"] = json!(e);
            }
            return report;
        }
    };
    report["sections"] = diff(
        &theirs.sections,
        &ours.sections,
        |s| s.name.clone(),
        section_fields,
    );
    // A PE import repeats across DLLs; elsewhere a name is one import, and
    // its library a field.
    let pe = kind == "Pe";
    report["imports"] = diff(
        &theirs.imports,
        &ours.imports,
        |i| {
            if pe {
                format!("{}!{}", i.library.as_deref().unwrap_or("?"), i.name)
            } else {
                i.name.clone()
            }
        },
        |a, b| {
            let mut fields = Vec::new();
            if !pe && a.library != b.library {
                fields.push(field(
                    "library",
                    a.library.clone().unwrap_or_default(),
                    b.library.clone().unwrap_or_default(),
                ));
            }
            if a.slot.is_some() && b.slot.is_some() && a.slot != b.slot {
                fields.push(field("slot", hex(a.slot), hex(b.slot)));
            }
            fields
        },
    );
    report["exports"] = diff(
        &theirs.exports,
        &ours.exports,
        |e| e.name.clone(),
        |a, b| {
            let mut fields = Vec::new();
            if a.addr.is_some() && b.addr.is_some() && a.addr != b.addr {
                fields.push(field("addr", hex(a.addr), hex(b.addr)));
            }
            let lower = |f: &Option<String>| f.as_deref().map(str::to_ascii_lowercase);
            if lower(&a.forward) != lower(&b.forward) {
                fields.push(field(
                    "forward",
                    a.forward.clone().unwrap_or_default(),
                    b.forward.clone().unwrap_or_default(),
                ));
            }
            fields
        },
    );
    report
}

/// Run a goblin walk, turning a panic into an error.
fn guarded<T>(walk: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
    catch_unwind(AssertUnwindSafe(walk)).unwrap_or_else(|panic| {
        let message = panic
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| panic.downcast_ref::<&str>().map(|s| (*s).to_owned()))
            .unwrap_or_default();
        Err(format!("panicked: {message}"))
    })
}

fn hex(value: Option<u64>) -> String {
    value.map_or_else(String::new, |v| format!("{v:#x}"))
}

fn field(name: &str, goblin: String, binform: String) -> (String, String, String) {
    (name.to_owned(), goblin, binform)
}

fn section_fields(a: &Section, b: &Section) -> Vec<(String, String, String)> {
    let mut fields = Vec::new();
    let mut num = |name: &str, x: u64, y: u64| {
        if x != y {
            fields.push(field(name, format!("{x:#x}"), format!("{y:#x}")));
        }
    };
    num("addr", a.addr, b.addr);
    num("size", a.size, b.size);
    num("offset", a.offset, b.offset);
    num("file_size", a.file_size, b.file_size);
    num("flags", a.flags, b.flags);
    let perm = |s: &Section| {
        format!(
            "{}{}{}",
            if s.readable { 'r' } else { '-' },
            if s.writable { 'w' } else { '-' },
            if s.executable { 'x' } else { '-' }
        )
    };
    if perm(a) != perm(b) {
        fields.push(field("perm", perm(a), perm(b)));
    }
    fields
}

/// Pair entries by key and occurrence (the second `.text` with the second),
/// and report what only one side has and which fields of the pairs differ.
fn diff<T>(
    theirs: &[T],
    ours: &[T],
    key: impl Fn(&T) -> String,
    fields: impl Fn(&T, &T) -> Vec<(String, String, String)>,
) -> Value {
    fn index<'t, T>(
        entries: &'t [T],
        key: &impl Fn(&T) -> String,
    ) -> BTreeMap<(String, usize), &'t T> {
        let mut seen: BTreeMap<String, usize> = BTreeMap::new();
        entries
            .iter()
            .map(|entry| {
                let k = key(entry);
                let n = seen.entry(k.clone()).or_insert(0);
                *n += 1;
                ((k, *n), entry)
            })
            .collect()
    }
    let (a, b) = (index(theirs, &key), index(ours, &key));
    let label = |(k, n): &(String, usize)| {
        if *n == 1 {
            k.clone()
        } else {
            format!("{k} #{n}")
        }
    };
    let only_goblin: Vec<String> = a
        .keys()
        .filter(|k| !b.contains_key(*k))
        .map(label)
        .collect();
    let only_binform: Vec<String> = b
        .keys()
        .filter(|k| !a.contains_key(*k))
        .map(label)
        .collect();
    let mut differ = Vec::new();
    let mut fields_differ: BTreeMap<String, usize> = BTreeMap::new();
    for (k, x) in &a {
        let Some(y) = b.get(k) else { continue };
        let changed = fields(x, y);
        if changed.is_empty() {
            continue;
        }
        for (name, _, _) in &changed {
            *fields_differ.entry(name.clone()).or_insert(0) += 1;
        }
        differ.push(format!(
            "{}: {}",
            label(k),
            changed
                .iter()
                .map(|(name, g, n)| format!("{name} {g}/{n}"))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    json!({
        "goblin": theirs.len(),
        "binform": ours.len(),
        "shared": a.keys().filter(|k| b.contains_key(*k)).count(),
        "only_goblin_count": only_goblin.len(),
        "only_binform_count": only_binform.len(),
        "differ_count": differ.len(),
        "fields_differ": fields_differ,
        "only_goblin": only_goblin.into_iter().take(shown()).collect::<Vec<_>>(),
        "only_binform": only_binform.into_iter().take(shown()).collect::<Vec<_>>(),
        "differ": differ.into_iter().take(shown()).collect::<Vec<_>>(),
    })
}

// ---------------------------------------------------------------------------
// binform
// ---------------------------------------------------------------------------

fn from_binform(bin: &binform::Binary<'_>, image_base: u64) -> Tables {
    let pe = bin.format == binform::Format::Pe;
    let macho = bin.format == binform::Format::MachO;
    let rva = |va: u64| if pe { va.wrapping_sub(image_base) } else { va };
    Tables {
        sections: bin
            .sections
            .iter()
            .map(|s| Section {
                name: s.name.clone(),
                addr: rva(s.addr),
                size: s.size,
                offset: s.offset,
                file_size: s.file_size,
                flags: s.flags,
                readable: s.readable,
                writable: s.writable,
                executable: s.executable,
            })
            .collect(),
        // filefacts walks the delay-load table itself; goblin does not.
        imports: bin
            .imports
            .iter()
            .filter(|i| !i.delayed)
            .map(|i| Import {
                library: i.library.as_deref().map(|l| library(bin.format, l)),
                name: match i.ordinal {
                    Some(n) if pe => format!("#{n}"),
                    _ => i.name.clone(),
                },
                slot: if pe { i.slot.map(rva) } else { None },
            })
            .collect(),
        exports: bin
            .exports
            .iter()
            .map(|e| Export {
                name: e.name.clone(),
                addr: (!macho).then(|| rva(e.addr)),
                forward: e.forward.clone(),
            })
            .collect(),
    }
}

/// A library as filefacts compares it: a PE DLL lowercased, a Mach-O dylib
/// reduced to its lowercase stem.
fn library(format: binform::Format, name: &str) -> String {
    match format {
        binform::Format::MachO => {
            let base = name.rsplit_once('/').map_or(name, |(_, base)| base);
            base.strip_suffix(".dylib")
                .or_else(|| base.strip_suffix(".tbd"))
                .unwrap_or(base)
                .to_ascii_lowercase()
        }
        _ => name.to_ascii_lowercase(),
    }
}

// ---------------------------------------------------------------------------
// goblin, as filefacts reads it
// ---------------------------------------------------------------------------

/// filefacts' PE parse: strict, then permissive.
fn goblin_pe(bytes: &[u8]) -> Result<(Tables, u64), String> {
    let pe = PE::parse(bytes).or_else(|strict| {
        let opts = goblin::pe::options::ParseOptions::default()
            .with_parse_mode(goblin::options::ParseMode::Permissive);
        PE::parse_with_opts(bytes, &opts).map_err(|_| strict.to_string())
    })?;
    use goblin::pe::section_table::{
        IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE,
    };
    let sections = pe
        .sections
        .iter()
        .map(|s| Section {
            name: s.name().unwrap_or("").to_owned(),
            addr: u64::from(s.virtual_address),
            size: u64::from(s.virtual_size),
            offset: u64::from(s.pointer_to_raw_data),
            file_size: u64::from(s.size_of_raw_data),
            flags: u64::from(s.characteristics),
            readable: s.characteristics & IMAGE_SCN_MEM_READ != 0,
            writable: s.characteristics & IMAGE_SCN_MEM_WRITE != 0,
            executable: s.characteristics & IMAGE_SCN_MEM_EXECUTE != 0,
        })
        .collect();
    let imports = pe
        .imports
        .iter()
        .map(|i| {
            let by_ordinal = i
                .name
                .strip_prefix("ORDINAL ")
                .is_some_and(|n| n.parse() == Ok(i.ordinal));
            Import {
                library: Some(i.dll.to_ascii_lowercase()),
                name: if by_ordinal {
                    format!("#{}", i.ordinal)
                } else {
                    i.name.to_string()
                },
                // goblin's `offset` is the slot's RVA, not a file offset.
                slot: Some(i.offset as u64),
            }
        })
        .collect();
    use goblin::pe::export::Reexport;
    let exports = pe
        .exports
        .iter()
        .filter_map(|e| {
            Some(Export {
                name: e.name?.to_owned(),
                addr: Some(e.rva as u64),
                forward: match e.reexport {
                    Some(Reexport::DLLName { export, lib }) => Some(format!("{lib}.{export}")),
                    Some(Reexport::DLLOrdinal { ordinal, lib }) => {
                        Some(format!("{lib}.#{ordinal}"))
                    }
                    None => None,
                },
            })
        })
        .collect();
    Ok((
        Tables {
            sections,
            imports,
            exports,
        },
        pe.image_base,
    ))
}

fn goblin_elf(bytes: &[u8]) -> Result<(Tables, u64), String> {
    use goblin::elf::section_header::{SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE, SHT_NOBITS};
    use goblin::elf::sym::{STT_FUNC, STT_GNU_IFUNC, STT_OBJECT};
    let elf = Elf::parse(bytes).map_err(|e| e.to_string())?;
    let sections = elf
        .section_headers
        .iter()
        .map(|sh| Section {
            name: elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("").to_owned(),
            addr: sh.sh_addr,
            size: sh.sh_size,
            offset: sh.sh_offset,
            file_size: if sh.sh_type == SHT_NOBITS {
                0
            } else {
                sh.sh_size
            },
            flags: sh.sh_flags,
            readable: sh.sh_flags & u64::from(SHF_ALLOC) != 0,
            writable: sh.sh_flags & u64::from(SHF_WRITE) != 0,
            executable: sh.sh_flags & u64::from(SHF_EXECINSTR) != 0,
        })
        .collect();
    let mut imports = Vec::new();
    let mut exports = Vec::new();
    for sym in &elf.dynsyms {
        let Some(name) = elf.dynstrtab.get_at(sym.st_name).filter(|n| !n.is_empty()) else {
            continue;
        };
        if sym.st_shndx == 0 {
            imports.push(Import {
                library: None,
                name: name.to_owned(),
                slot: None,
            });
        } else if matches!(sym.st_type(), STT_FUNC | STT_GNU_IFUNC | STT_OBJECT) {
            exports.push(Export {
                name: name.to_owned(),
                addr: Some(sym.st_value),
                forward: None,
            });
        }
    }
    Ok((
        Tables {
            sections,
            imports,
            exports,
        },
        0,
    ))
}

fn goblin_macho(bytes: &[u8]) -> Result<(Tables, u64), String> {
    use goblin::mach::constants::{
        S_GB_ZEROFILL, S_THREAD_LOCAL_ZEROFILL, S_ZEROFILL, SECTION_TYPE,
    };
    let macho = MachO::parse(bytes, 0).map_err(|e| e.to_string())?;
    let mut sections = Vec::new();
    for segment in &macho.segments {
        let segname = segment.name().unwrap_or("");
        let Ok(secs) = segment.sections() else {
            continue;
        };
        for (section, _) in secs {
            let zero = matches!(
                section.flags & SECTION_TYPE,
                S_ZEROFILL | S_GB_ZEROFILL | S_THREAD_LOCAL_ZEROFILL
            );
            sections.push(Section {
                name: format!("{segname}.{}", section.name().unwrap_or("")),
                addr: section.addr,
                size: section.size,
                offset: u64::from(section.offset),
                file_size: if zero { 0 } else { section.size },
                flags: u64::from(section.flags),
                readable: segment.initprot & 1 != 0,
                writable: segment.initprot & 2 != 0,
                executable: segment.initprot & 4 != 0,
            });
        }
    }
    let lib = |l: &str| library(binform::Format::MachO, l);
    let mut imports: Vec<Import> = macho
        .imports()
        .unwrap_or_default()
        .iter()
        .map(|i| Import {
            library: Some(lib(i.dylib)),
            name: i.name.to_owned(),
            slot: None,
        })
        .collect();
    if imports.is_empty() {
        // filefacts' chained-fixup fallback: the undefined external symbols.
        let mut names: Vec<String> = macho
            .symbols()
            .filter_map(Result::ok)
            .filter(|(name, nlist)| {
                nlist.n_type & 0x01 != 0 && nlist.n_type & 0x0e == 0 && !name.is_empty()
            })
            .map(|(name, _)| name.to_owned())
            .collect();
        names.sort_unstable();
        names.dedup();
        imports = names
            .into_iter()
            .map(|name| Import {
                library: None,
                name,
                slot: None,
            })
            .collect();
    }
    use goblin::mach::exports::ExportInfo;
    let exports = macho
        .exports()
        .unwrap_or_default()
        .into_iter()
        .map(|e| Export {
            forward: match e.info {
                ExportInfo::Reexport {
                    lib,
                    lib_symbol_name,
                    ..
                } => Some(format!(
                    "{}.{}",
                    self::lib_stem(lib),
                    lib_symbol_name.unwrap_or(&e.name)
                )),
                _ => None,
            },
            name: e.name,
            addr: None,
        })
        .collect();
    Ok((
        Tables {
            sections,
            imports,
            exports,
        },
        0,
    ))
}

fn lib_stem(lib: &str) -> String {
    library(binform::Format::MachO, lib)
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

pub(crate) fn summarize(reports: &[Value]) {
    let mut by_format: BTreeMap<String, Vec<&Value>> = BTreeMap::new();
    for report in reports {
        by_format
            .entry(report["format"].as_str().unwrap_or("?").to_owned())
            .or_default()
            .push(report);
    }
    for (format, reports) in by_format {
        let compared: Vec<&&Value> = reports
            .iter()
            .filter(|r| r["sections"].is_object())
            .collect();
        let errors = |key: &str| reports.iter().filter(|r| r[key].is_string()).count();
        eprintln!(
            "{format}: {} images compared; goblin failed on {}, binform on {}",
            compared.len(),
            errors("goblin_error"),
            errors("binform_error"),
        );
        for table in ["sections", "imports", "exports"] {
            let total =
                |key: &str| -> u64 { compared.iter().filter_map(|r| r[table][key].as_u64()).sum() };
            let files = |key: &str| {
                compared
                    .iter()
                    .filter(|r| r[table][key].as_u64().is_some_and(|n| n > 0))
                    .count()
            };
            let mut fields: BTreeMap<String, u64> = BTreeMap::new();
            for r in &compared {
                if let Some(map) = r[table]["fields_differ"].as_object() {
                    for (name, n) in map {
                        *fields.entry(name.clone()).or_insert(0) += n.as_u64().unwrap_or(0);
                    }
                }
            }
            eprintln!(
                "  {table}: goblin {}, binform {}, shared {}; only goblin {} ({} files), \
                 only binform {} ({} files), differ {} ({} files) {:?}",
                total("goblin"),
                total("binform"),
                total("shared"),
                total("only_goblin_count"),
                files("only_goblin_count"),
                total("only_binform_count"),
                files("only_binform_count"),
                total("differ_count"),
                files("differ_count"),
                fields,
            );
        }
    }
}
