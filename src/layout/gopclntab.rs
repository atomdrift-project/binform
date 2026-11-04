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

use super::limits;
use super::read::Reader;

const GO_1_2: u32 = 0xffff_fffb;
const GO_1_16: u32 = 0xffff_fffa;
const GO_1_18: u32 = 0xffff_fff0;
const GO_1_20: u32 = 0xffff_fff1;

/// The magic numbers of the layouts, oldest first.
pub(super) const MAGICS: [u32; 4] = [GO_1_2, GO_1_16, GO_1_18, GO_1_20];

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
    Table::new(table, text, named, big)
        .map(|table| table.functions())
        .unwrap_or_default()
}

/// A function table whose header has been read: where its parts are.
pub(super) struct Table<'a> {
    r: Reader<'a>,
    count: u64,
    /// The offset of the function names.
    names: u64,
    /// The offset of the (entry, record) pairs.
    functab: u64,
    /// The offset the records' offsets count from.
    records: u64,
    /// Bytes in an entry and in a record offset.
    entry_size: u8,
    /// What entries count from.
    base: u64,
}

impl<'a> Table<'a> {
    /// The table in `table`, or `None` when its header is no function
    /// table's. The arguments are as [`functions`]'.
    pub(super) fn new(table: &'a [u8], text: Option<u64>, named: bool, big: bool) -> Option<Self> {
        let magic_in = |big| {
            Reader::new(table, big)
                .u32(0)
                .filter(|magic| MAGICS.contains(magic))
        };
        let big = match (magic_in(false), magic_in(true)) {
            (Some(_), _) => false,
            (_, Some(_)) => true,
            _ => big,
        };
        let r = Reader::new(table, big);
        let magic = r.u32(0)?;
        let (pad, quantum, ptr) = (r.u16(4)?, r.u8(6)?, r.u8(7)?);
        if pad != 0 || !matches!(quantum, 1 | 2 | 4) || !matches!(ptr, 4 | 8) {
            return None;
        }
        let word = |i: u64| r.uint(u64::from(ptr).checked_mul(i)?.checked_add(8)?, ptr);
        let count = word(0)?.min(limits::GO_FUNCTIONS as u64);
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
            GO_1_2 => (0, u64::from(ptr).checked_add(8)?, ptr, 0),
            GO_1_16 => (word(2)?, word(6)?, ptr, 0),
            _ if MAGICS.contains(&magic) || (named && ordered()) => {
                let start = match word(2)? {
                    0 => text?,
                    start => start,
                };
                (word(3)?, word(7)?, 4, start)
            }
            _ => return None,
        };
        Some(Self {
            r,
            count,
            names,
            functab,
            // The function table's offsets count from its own start, except
            // in the oldest layout, where they count from the table's.
            records: if magic == GO_1_2 { 0 } else { functab },
            entry_size,
            base,
        })
    }

    /// Function `i`'s entry and name; `None` past the end of the table.
    pub(super) fn function(&self, i: u64) -> Option<(u64, String)> {
        let (r, size) = (&self.r, u64::from(self.entry_size));
        let at = self
            .functab
            .checked_add(i.checked_mul(size)?.checked_mul(2)?)?;
        let entry = r.uint(at, self.entry_size)?;
        let record = r.uint(at.checked_add(size)?, self.entry_size)?;
        let name_at = r.u32(self.records.checked_add(record)?.checked_add(size)?)?;
        let name = r.name(self.names.checked_add(u64::from(name_at))?);
        Some((self.base.wrapping_add(entry), name.into_owned()))
    }

    /// Every function, in entry order, up to the first out of order. A
    /// table cut short yields the functions before the cut.
    pub(super) fn functions(&self) -> Vec<(u64, String)> {
        let mut last = 0;
        (0..self.count)
            .map_while(|i| self.function(i))
            .take_while(|&(entry, _)| std::mem::replace(&mut last, entry) <= entry)
            .collect()
    }
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
