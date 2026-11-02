//! Bounds-checked reads of a file's integers and names. Every read returns
//! `None` past the end of the bytes, so a header that points nowhere costs
//! the table it names, not the file.

use std::borrow::Cow;

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

    fn array<const N: usize>(&self, at: u64) -> Option<[u8; N]> {
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

    /// A pointer-sized field: eight bytes when `wide`, four otherwise.
    pub(super) fn word(&self, at: u64, wide: bool) -> Option<u64> {
        if wide {
            self.u64(at)
        } else {
            self.u32(at).map(u64::from)
        }
    }

    /// The NUL-terminated name at `at`, at most 4 KiB, with any bytes that
    /// are not UTF-8 replaced. Empty past the end.
    pub(super) fn name(&self, at: u64) -> Cow<'a, str> {
        let Some(rest) = usize::try_from(at).ok().and_then(|at| self.bytes.get(at..)) else {
            return Cow::Borrowed("");
        };
        let rest = rest.get(..1 << 12).unwrap_or(rest);
        let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
        String::from_utf8_lossy(rest.get(..end).unwrap_or_default())
    }
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
        assert_eq!(little.word(0, false), Some(0x0403_0201));
        assert_eq!(little.u64(1), None);
        assert_eq!(little.u32(u64::MAX), None);
        assert_eq!(little.name(4), "ab");
        assert_eq!(little.name(7), "c");
        assert_eq!(little.name(99), "");
    }
}
