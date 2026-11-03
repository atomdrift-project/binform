//! Go's function table, `.gopclntab`: the entry and name of every function,
//! kept in stripped binaries because the runtime needs it for tracebacks.
//! Functions reached only through method tables, closures and type
//! descriptors are found nowhere else.
//!
//! The layout, by the magic number that starts it, in the binary's byte
//! order (which the magic number gives, or for a garbled one, the file):
//!
//! - Go 1.2-1.15 (`0xfffffffb`): after the 8-byte header, the function
//!   count, then (entry, offset) pairs of pointers; each offset finds the
//!   function's record, whose name offset counts from the table's start.
//! - Go 1.16-1.17 (`0xfffffffa`): the header holds the count and the
//!   offsets of the name table and of the function table; entries are
//!   pointers.
//! - Go 1.18 and later (`0xfffffff0`, and `0xfffffff1` from 1.20): as
//!   1.16, with the text start in the header, and entries 32-bit offsets
//!   from it.
//!
//! Obfuscators (garble) overwrite the magic number. A table found by its
//! section's name is read with any magic whose header is a Go 1.18 one: its
//! offsets in order and inside the table.

/// The most functions read from one table.
const MOST: usize = 1 << 21;

/// The longest function name read.
const LONGEST: usize = 1 << 12;

/// The magic numbers of the layouts, oldest first.
pub(super) const MAGICS: [u32; 4] = [0xffff_fffb, 0xffff_fffa, 0xffff_fff0, 0xffff_fff1];

/// Every function in `table` as (entry, name), in entry order, up to the
/// first entry out of order. `text` is the start of the code, which entries
/// count from when the header leaves the text start out (a
/// position-independent binary fills it in at load time). `named` says the
/// table's section names it, so a magic number may have been overwritten;
/// `big` is the file's byte order, for a table whose magic number does not
/// say.
pub(super) fn functions(
    table: &[u8],
    text: Option<u64>,
    named: bool,
    big: bool,
) -> Vec<(u64, String)> {
    let big = match (u32_at(table, 0, false), u32_at(table, 0, true)) {
        (Some(magic), _) if MAGICS.contains(&magic) => false,
        (_, Some(magic)) if MAGICS.contains(&magic) => true,
        _ => big,
    };
    functions_of(table, text, named, big).unwrap_or_default()
}

fn functions_of(
    table: &[u8],
    text: Option<u64>,
    named: bool,
    big: bool,
) -> Option<Vec<(u64, String)>> {
    let u32_at = |bytes: &[u8], at: usize| u32_at(bytes, at, big);
    let uint_at = |bytes: &[u8], at: usize, size: usize| uint_at(bytes, at, size, big);
    let magic = u32_at(table, 0)?;
    let (pad, quantum, ptr) = (table.get(4..6)?, *table.get(6)?, *table.get(7)?);
    if pad != [0, 0] || !matches!(quantum, 1 | 2 | 4) || !matches!(ptr, 4 | 8) {
        return None;
    }
    let ptr = usize::from(ptr);
    let word = |i: usize| uint_at(table, 8 + i * ptr, ptr);
    let count = usize::try_from(word(0)?).ok()?.min(MOST);
    // Go 1.18's offsets: function names, compilation units, files, pc
    // tables, functions.
    let ordered = || {
        let offsets: Option<Vec<u64>> = (3..8).map(word).collect();
        offsets.is_some_and(|offsets| {
            offsets.is_sorted()
                && offsets
                    .last()
                    .is_some_and(|&last| last < table.len() as u64)
        })
    };
    let (names, functab, entry_size, base) = match magic {
        0xffff_fffb => (0, u64::try_from(8 + ptr).ok()?, ptr, 0),
        0xffff_fffa => (word(2)?, word(6)?, ptr, 0),
        _ if MAGICS.contains(&magic) || (named && ordered()) => {
            let start = match word(2)? {
                0 => text?,
                start => start,
            };
            (word(3)?, word(7)?, 4, start)
        }
        _ => return None,
    };
    let names = usize::try_from(names).ok()?;
    let functab = usize::try_from(functab).ok()?;
    // The function table's offsets count from its own start, except in the
    // oldest layout, where they count from the table's.
    let records = if magic == 0xffff_fffb { 0 } else { functab };
    // A table cut short yields the functions before the cut.
    let function = |i: usize| {
        let at = functab.checked_add(i.checked_mul(2 * entry_size)?)?;
        let entry = uint_at(table, at, entry_size)?;
        let record = usize::try_from(uint_at(table, at + entry_size, entry_size)?).ok()?;
        let name_at = u32_at(table, records.checked_add(record)?.checked_add(entry_size)?)?;
        let name = table
            .get(names.checked_add(usize::try_from(name_at).ok()?)?..)
            .map(|rest| {
                let rest = rest.get(..LONGEST).unwrap_or(rest);
                let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
                String::from_utf8_lossy(rest.get(..end).unwrap_or_default()).into_owned()
            })
            .unwrap_or_default();
        Some((base.wrapping_add(entry), name))
    };
    let mut last = 0;
    Some(
        (0..count)
            .map_while(function)
            .take_while(|&(entry, _)| std::mem::replace(&mut last, entry) <= entry)
            .collect(),
    )
}

fn u32_at(bytes: &[u8], at: usize, big: bool) -> Option<u32> {
    uint_at(bytes, at, 4, big).and_then(|value| u32::try_from(value).ok())
}

/// The `size`-byte (4 or 8) unsigned integer at `at`, big-endian when
/// `big`.
fn uint_at(bytes: &[u8], at: usize, size: usize, big: bool) -> Option<u64> {
    let bytes = bytes.get(at..at.checked_add(size)?)?;
    if size != 4 && size != 8 {
        return None;
    }
    let word = |value: u64, &byte: &u8| value << 8 | u64::from(byte);
    Some(if big {
        bytes.iter().fold(0, word)
    } else {
        bytes.iter().rev().fold(0, word)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A Go 1.20 (and 1.18) table with two functions, `main.main` and `main.f`, at
    /// 0x10 and 0x40 past a text start the header leaves out.
    #[test]
    fn go_1_20() {
        let mut table = vec![0xf1, 0xff, 0xff, 0xff, 0, 0, 1, 8];
        // nfunc, nfiles, textStart, funcnameOffset, cuOffset, filetabOffset,
        // pctabOffset, pclnOffset.
        for word in [2_u64, 0, 0, 0x48, 0x5a, 0x5c, 0x5e, 0x60] {
            table.extend(word.to_le_bytes());
        }
        table.extend(b"main.main\0main.f\0");
        table.resize(0x60, 0);
        // The function table: (entry, record) pairs and the end sentinel,
        // then the records (entry, name offset).
        for word in [0x10_u32, 0x18, 0x40, 0x20, 0x50, 0] {
            table.extend(word.to_le_bytes());
        }
        for word in [0x10_u32, 0, 0x40, 10] {
            table.extend(word.to_le_bytes());
        }
        let both = [
            (0x40_1010, "main.main".to_owned()),
            (0x40_1040, "main.f".to_owned()),
        ];
        assert_eq!(functions(&table, Some(0x40_1000), false, false), both);
        // Go 1.18 and 1.19 lay it out the same under their own magic.
        let mut go_1_18 = table.clone();
        go_1_18[0] = 0xf0;
        assert_eq!(functions(&go_1_18, Some(0x40_1000), false, false), both);
        assert!(
            functions(&table, None, false, false).is_empty(),
            "no text start"
        );
        let cut = table.get(..0x80).unwrap_or_default();
        assert_eq!(functions(cut, Some(0), false, false).len(), 1, "cut short");

        // garble's: the magic overwritten, the rest intact.
        let mut garbled = table.clone();
        garbled.splice(..4, [0xa6, 0xab, 0x7f, 0xcc]);
        assert!(functions(&garbled, Some(0x40_1000), false, false).is_empty());
        assert_eq!(functions(&garbled, Some(0x40_1000), true, false), both);

        if let Some(pad) = table.get_mut(4) {
            *pad = 1;
        }
        assert!(
            functions(&table, Some(0x40_1000), true, false).is_empty(),
            "not a table"
        );
    }
}
