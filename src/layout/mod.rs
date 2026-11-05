//! Build a [`Binary`] from the bytes of an ELF, PE or Mach-O file.
//!
//! Everything a loader or linker leaves behind that names function starts
//! becomes a [`Seed`]: entry points, initializers, TLS callbacks, symbols,
//! exports, unwind tables and Mach-O function starts. Import slots come
//! from the PE import table, ELF relocations against undefined symbols, and
//! the Mach-O indirect symbol table.
//!
//! Every file is read as hostile, by one rule: a malformed entry ends its
//! table, never the file. A count past the end, an offset to nowhere or a
//! chain that loops yields the entries read before it; only a file whose
//! first header cannot be read fails. What a header claims is cut to the
//! bounds in [`limits`], so a file costs time and memory in proportion to
//! its size, not to its claims.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::ops::Range;

use crate::{Binary, Export, Format, Import, Origin, Section, Seed, Slot};

mod eh;
mod elf;
mod elf_image;
mod gopclntab;
mod limits;
mod macho;
mod macho_image;
mod pe;
mod pe_image;
mod read;
mod relocate;

/// Why bytes could not become a [`Binary`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The file ends inside the header named.
    Truncated(&'static str),
    /// No magic number of a format binform reads: not ELF, PE or Mach-O.
    BadMagic,
    /// The field named holds a value binform does not read.
    Unsupported(&'static str),
    /// A file of another kind, named, that shares a magic number.
    NotExecutable(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated(what) => write!(f, "truncated {what}"),
            Self::BadMagic => f.write_str("not an ELF, PE or Mach-O file"),
            Self::Unsupported(what) => write!(f, "unsupported {what}"),
            Self::NotExecutable(what) => write!(f, "not an executable: {what}"),
        }
    }
}

impl std::error::Error for Error {}

/// The [`Binary`] of an ELF, PE or Mach-O file. A universal Mach-O yields its
/// first slice of an instruction set binform decodes, else its first slice.
/// A binary of an instruction set binform does not decode has its layout
/// and no [`Binary::arch`].
///
/// # Errors
///
/// An [`Error`] when the file's first header cannot be read: too short,
/// no known magic number, or a kind of file that is no executable. A
/// damaged table further in is read as far as it goes instead.
pub fn parse(bytes: &[u8]) -> Result<Binary<'_>, Error> {
    let mut bin = match bytes.get(..4) {
        Some(b"\x7fELF") => elf_image::binary(bytes, &elf::parse(bytes)?),
        Some([b'M', b'Z', ..]) => pe_image::binary(bytes, &pe::parse(bytes)?),
        Some(&[0xca, 0xfe, 0xba, 0xbe | 0xbf]) => macho_image::universal(bytes)?,
        Some(_) => macho_image::binary(bytes, &macho::parse(bytes)?),
        None => return Err(Error::Truncated("magic number")),
    };
    bin.index_slots();
    Ok(bin)
}

/// The sections, imports and exports a format's headers list.
struct Tables {
    sections: Vec<Section>,
    imports: Vec<Import>,
    exports: Vec<Export>,
}

/// The layout of a binary, with no code to recover functions from: all a
/// binary of an instruction set binform does not decode has, and what the
/// others start from.
fn bare<'a>(format: Format, entry: u64, tables: Tables, slots: Vec<Slot>) -> Binary<'a> {
    Binary {
        format,
        arch: None,
        entry: (entry != 0).then_some(entry),
        sections: tables.sections,
        imports: tables.imports,
        exports: tables.exports,
        segments: Vec::new(),
        seeds: Vec::new(),
        slots,
        handlers: Vec::new(),
        extents: Vec::new(),
        got: None,
        rebased: Vec::new(),
    }
}

/// `len` bytes at file offset `offset`, cut short at the end of the file.
fn file_range(bytes: &[u8], offset: u64, len: u64) -> &[u8] {
    let start = usize::try_from(offset)
        .unwrap_or(usize::MAX)
        .min(bytes.len());
    let end = usize::try_from(offset.saturating_add(len))
        .unwrap_or(usize::MAX)
        .min(bytes.len());
    bytes.get(start..end).unwrap_or_default()
}

fn seed(addr: u64, origin: Origin) -> Seed {
    Seed { addr, origin }
}

/// A seed at the start of each function an unwind table describes.
fn unwind_seeds(extents: &[Range<u64>]) -> impl Iterator<Item = Seed> + '_ {
    extents
        .iter()
        .map(|extent| seed(extent.start, Origin::Unwind))
}

/// A seed at each function of a Go function table, by its name.
fn go_seeds(functions: Vec<(u64, String)>) -> impl Iterator<Item = Seed> {
    functions
        .into_iter()
        .map(|(addr, name)| seed(addr, Origin::Symbol(name)))
}

/// One import per name, in first-seen order, each with the first slot that
/// names it.
fn import_table<'s>(
    slots: &[Slot],
    symbols: impl Iterator<Item = (&'s str, Option<&'s str>)>,
) -> Vec<Import> {
    let mut first: HashMap<&str, u64> = HashMap::new();
    for slot in slots {
        first.entry(slot.name.as_str()).or_insert(slot.slot);
    }
    let mut seen = HashSet::new();
    symbols
        .filter(|&(name, _)| !name.is_empty() && seen.insert(name))
        .map(|(name, library)| Import {
            slot: first.get(name).copied(),
            name: name.to_owned(),
            library: library.map(str::to_owned),
            ordinal: None,
            delayed: false,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_ranges_clamp() {
        let bytes = [1, 2, 3, 4];
        assert_eq!(file_range(&bytes, 2, 10), [3, 4]);
        assert!(file_range(&bytes, 9, 1).is_empty());
        assert!(file_range(&bytes, u64::MAX, u64::MAX).is_empty());
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(parse(b"").err(), Some(Error::Truncated("magic number")));
        assert_eq!(
            parse(b"not an executable at all").err(),
            Some(Error::BadMagic)
        );
        assert!(parse(b"\x7fELF\x02\x01\x01").is_err());
        assert!(parse(b"MZ\x90\x00").is_err());
    }

    /// An instruction set binform does not decode (IA-64, machine 50)
    /// leaves the layout readable and no code to recover.
    #[test]
    fn an_unknown_instruction_set_has_layout_only() {
        let mut header = vec![0_u8; 64];
        header[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        header[16..18].copy_from_slice(&2_u16.to_le_bytes());
        header[18..20].copy_from_slice(&50_u16.to_le_bytes());
        header[24..32].copy_from_slice(&0x1000_u64.to_le_bytes());
        let bin = parse(&header).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            (bin.format, bin.arch, bin.entry),
            (Format::Elf, None, Some(0x1000))
        );
        assert!(bin.segments.is_empty() && bin.seeds.is_empty());
        assert!(
            crate::recover(&bin, &crate::Limits::DEFAULT)
                .functions
                .is_empty()
        );
    }
}
