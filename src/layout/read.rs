//! Bounds-checked reads of a file's integers and names. Every read returns
//! `None` past the end of the bytes, and every offset is added with a
//! check, so a header that points nowhere costs the table it names, not the
//! file.

use std::borrow::Cow;

use super::limits;

/// A file's bytes, read in its byte order.
#[derive(Clone, Copy)]
pub(super) struct Reader<'a> {
    pub(super) bytes: &'a [u8],
    /// Big-endian.
    pub(super) big: bool,
}

impl<'a> Reader<'a> {
    pub(super) fn new(bytes: &'a [u8], big: bool) -> Self {
        Self { bytes, big }
    }

    /// The bytes from `at` on, read the same way: a header's fields, at
    /// offsets from its start. Empty past the end.
    pub(super) fn at(&self, at: u64) -> Self {
        let bytes = usize::try_from(at)
            .ok()
            .and_then(|at| self.bytes.get(at..))
            .unwrap_or_default();
        Self {
            bytes,
            big: self.big,
        }
    }

    pub(super) fn array<const N: usize>(&self, at: u64) -> Option<[u8; N]> {
        let at = usize::try_from(at).ok()?;
        self.bytes.get(at..at.checked_add(N)?)?.try_into().ok()
    }

    pub(super) fn u8(&self, at: u64) -> Option<u8> {
        self.bytes.get(usize::try_from(at).ok()?).copied()
    }

    pub(super) fn u16(&self, at: u64) -> Option<u16> {
        let bytes = self.array(at)?;
        Some(if self.big {
            u16::from_be_bytes(bytes)
        } else {
            u16::from_le_bytes(bytes)
        })
    }

    pub(super) fn u32(&self, at: u64) -> Option<u32> {
        let bytes = self.array(at)?;
        Some(if self.big {
            u32::from_be_bytes(bytes)
        } else {
            u32::from_le_bytes(bytes)
        })
    }

    pub(super) fn u64(&self, at: u64) -> Option<u64> {
        let bytes = self.array(at)?;
        Some(if self.big {
            u64::from_be_bytes(bytes)
        } else {
            u64::from_le_bytes(bytes)
        })
    }

    /// The 32-bit fields at `offsets`: a header's, all there or none.
    pub(super) fn u32s<const N: usize>(&self, offsets: [u64; N]) -> Option<[u32; N]> {
        let mut fields = [0; N];
        for (field, at) in fields.iter_mut().zip(offsets) {
            *field = self.u32(at)?;
        }
        Some(fields)
    }

    /// A pointer-sized field: eight bytes when `wide`, four otherwise.
    pub(super) fn word(&self, at: u64, wide: bool) -> Option<u64> {
        if wide {
            self.u64(at)
        } else {
            self.u32(at).map(u64::from)
        }
    }

    /// The unsigned integer of `size` bytes (1, 2, 4 or 8) at `at`.
    pub(super) fn uint(&self, at: u64, size: u8) -> Option<u64> {
        match size {
            1 => self.u8(at).map(u64::from),
            2 => self.u16(at).map(u64::from),
            4 => self.u32(at).map(u64::from),
            8 => self.u64(at),
            _ => None,
        }
    }

    /// The bytes of the NUL-terminated string at `at`, at most
    /// [`limits::NAME_LEN`] of them. Empty past the end.
    pub(super) fn cstr(&self, at: u64) -> &'a [u8] {
        let rest = self.at(at).bytes;
        let rest = rest.get(..limits::NAME_LEN).unwrap_or(rest);
        rest.split(|&b| b == 0).next().unwrap_or_default()
    }

    /// The NUL-terminated name at `at`, with any bytes that are not UTF-8
    /// replaced. Empty past the end.
    pub(super) fn name(&self, at: u64) -> Cow<'a, str> {
        String::from_utf8_lossy(self.cstr(at))
    }
}

/// The offsets of a table's entries: `count` of `size` bytes from
/// `offset`, at most [`limits::TABLE`], ending where an offset overflows.
pub(super) fn table(offset: u64, size: u64, count: u64) -> impl Iterator<Item = u64> {
    (0..count.min(limits::TABLE)).map_while(move |i| offset.checked_add(i.checked_mul(size)?))
}

/// The offsets of the entries of `size` bytes that fit in the `bytes` from
/// `offset`, as [`table`]'s.
pub(super) fn entries(offset: u64, bytes: u64, size: u64) -> impl Iterator<Item = u64> {
    table(offset, size, bytes.checked_div(size).unwrap_or(0))
}

/// The unsigned LEB128 number at `*at`, advancing past it; bits past the
/// 64th are dropped. `None` when it runs past the end.
pub(super) fn uleb128(bytes: &[u8], at: &mut usize) -> Option<u64> {
    leb128(bytes, at).map(|(value, _)| value)
}

/// The signed LEB128 number at `*at`, advancing past it, as two's
/// complement.
pub(super) fn sleb128(bytes: &[u8], at: &mut usize) -> Option<u64> {
    let (value, shift) = leb128(bytes, at)?;
    // The last byte's bit 6 is the sign.
    let sign = shift
        .checked_sub(1)
        .and_then(|bit| value.checked_shr(bit))
        .is_some_and(|top| top & 1 != 0);
    Some(match u64::MAX.checked_shl(shift) {
        Some(high) if sign => value | high,
        _ => value,
    })
}

/// A LEB128 number's bits and how many it has. One longer than
/// [`limits::LEB128`] bytes is none: else every start within a long run of
/// continuation bytes would read to its end.
fn leb128(bytes: &[u8], at: &mut usize) -> Option<(u64, u32)> {
    let (mut value, mut shift) = (0_u64, 0_u32);
    for _ in 0..limits::LEB128 {
        let byte = *bytes.get(*at)?;
        *at = at.checked_add(1)?;
        value |= u64::from(byte & 0x7f).checked_shl(shift).unwrap_or(0);
        shift = shift.saturating_add(7);
        if byte & 0x80 == 0 {
            return Some((value, shift));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_both_orders_and_stops_at_the_end() {
        let bytes = [1, 2, 3, 4, b'a', b'b', 0, b'c'];
        let little = Reader::new(&bytes, false);
        let big = Reader::new(&bytes, true);
        assert_eq!(little.u32(0), Some(0x0403_0201));
        assert_eq!(big.u32(0), Some(0x0102_0304));
        assert_eq!(big.u16(2), Some(0x0304));
        assert_eq!(big.at(2).u16(0), Some(0x0304));
        assert_eq!(little.word(0, false), Some(0x0403_0201));
        assert_eq!(little.uint(0, 2), Some(0x0201));
        assert_eq!(little.uint(0, 3), None);
        assert_eq!(little.u64(1), None);
        assert_eq!(little.u32(u64::MAX), None);
        assert_eq!(little.at(u64::MAX).u8(0), None);
        assert_eq!(little.name(4), "ab");
        assert_eq!(little.name(7), "c");
        assert_eq!(little.name(99), "");
    }

    #[test]
    fn leb128s() {
        let bytes = [0x02, 0xe5, 0x8e, 0x26, 0x7f, 0x80, 0x7f, 0x80];
        let mut at = 0;
        assert_eq!(uleb128(&bytes, &mut at), Some(2));
        assert_eq!(uleb128(&bytes, &mut at), Some(624_485));
        assert_eq!(sleb128(&bytes, &mut at), Some(u64::MAX));
        assert_eq!(sleb128(&bytes, &mut at), Some((-128_i64).cast_unsigned()));
        assert_eq!(uleb128(&bytes, &mut at), None, "runs past the end");
        // Bits past the 64th are dropped, not wrapped.
        let long = [0xff; 20];
        let mut at = 0;
        assert_eq!(
            uleb128(&[long.as_slice(), &[1]].concat(), &mut at),
            Some(u64::MAX)
        );
        // Longer than any encoder pads one.
        let endless = [[0x80; limits::LEB128].as_slice(), &[1]].concat();
        assert_eq!(uleb128(&endless, &mut 0), None);
        // As long as may be: its one bit is past the 64th.
        assert_eq!(uleb128(&endless, &mut 1), Some(0));
    }

    #[test]
    fn tables_end_where_offsets_overflow() {
        assert_eq!(table(u64::MAX - 8, 4, 10).count(), 3);
        assert_eq!(table(0, 1, u64::MAX).count() as u64, limits::TABLE);
    }
}
