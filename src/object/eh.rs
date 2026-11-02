//! Exception-handling tables: where `.eh_frame` says functions start, and
//! where each function's language-specific data area (LSDA, in
//! `.gcc_except_table`) says its landing pads are.
//!
//! A landing pad is code inside a function that no instruction branches to:
//! the unwinder enters it to run a destructor or a `catch`. Without it, a
//! function's graph misses its cleanup code.

use crate::Handler;
use crate::decode::Memory;

/// The most landing pads read from one LSDA.
const MOST_PADS: usize = 1 << 14;

/// `DW_EH_PE_omit`: the field is absent.
const OMIT: u8 = 0xff;

/// The start of every range the `.eh_frame` at `addr` describes, and the
/// landing pads its LSDAs name.
pub(super) fn eh_frame(
    memory: &Memory<'_>,
    addr: u64,
    size: u64,
    is_64: bool,
) -> (Vec<u64>, Vec<Handler>) {
    use gimli::{BaseAddresses, CieOrFde, EhFrame, LittleEndian, Pointer, UnwindSection};
    let Some((data, _)) = memory.at(addr) else {
        return (Vec::new(), Vec::new());
    };
    let data = data
        .get(..usize::try_from(size).unwrap_or(usize::MAX).min(data.len()))
        .unwrap_or_default();
    let width: u8 = if is_64 { 8 } else { 4 };
    let mut eh_frame = EhFrame::new(data, LittleEndian);
    eh_frame.set_address_size(width);
    let bases = BaseAddresses::default().set_eh_frame(addr);
    let mut entries = eh_frame.entries(&bases);
    let (mut starts, mut handlers) = (Vec::new(), Vec::new());
    while let Ok(Some(entry)) = entries.next() {
        let CieOrFde::Fde(partial) = entry else {
            continue;
        };
        let Ok(fde) = partial.parse(EhFrame::cie_from_offset) else {
            continue;
        };
        let function = fde.initial_address();
        starts.push(function);
        let lsda = match fde.lsda() {
            Some(Pointer::Direct(lsda)) => Some(lsda),
            Some(Pointer::Indirect(slot)) => memory.read(slot, width),
            None => None,
        };
        if let Some(lsda) = lsda {
            handlers.extend(
                landing_pads(memory, lsda, function, width)
                    .into_iter()
                    .map(|addr| Handler { function, addr }),
            );
        }
    }
    (starts, handlers)
}

/// The landing pads the LSDA at `addr` names for the function at
/// `function`, in table order without repeats.
pub(super) fn landing_pads(memory: &Memory<'_>, addr: u64, function: u64, width: u8) -> Vec<u64> {
    let Some((bytes, _)) = memory.at(addr) else {
        return Vec::new();
    };
    let mut reader = Reader {
        bytes,
        at: 0,
        base: addr,
        width,
    };
    let mut pads = Vec::new();
    let _complete = (|| {
        let start_encoding = reader.u8()?;
        let start = if start_encoding == OMIT {
            function
        } else {
            reader.encoded(start_encoding)?
        };
        if reader.u8()? != OMIT {
            reader.uleb()?; // type-table offset
        }
        let site_encoding = reader.u8()?;
        let length = usize::try_from(reader.uleb()?).ok()?;
        let end = reader.at.checked_add(length)?.min(bytes.len());
        while reader.at < end && pads.len() < MOST_PADS {
            reader.encoded(site_encoding)?; // call-site start
            reader.encoded(site_encoding)?; // call-site length
            let pad = reader.encoded(site_encoding)?;
            reader.uleb()?; // action
            let pad = start.wrapping_add(pad);
            if pad != start && !pads.contains(&pad) {
                pads.push(pad);
            }
        }
        Some(())
    })();
    pads
}

/// A cursor over DWARF exception-handling encodings.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
    /// The address of `bytes[0]`, for PC-relative values.
    base: u64,
    /// Bytes in an address.
    width: u8,
}

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Option<&[u8]> {
        let bytes = self.bytes.get(self.at..self.at.checked_add(n)?)?;
        self.at += n;
        Some(bytes)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1)?.first().copied()
    }

    /// A little-endian unsigned integer of `n` bytes.
    fn unsigned(&mut self, n: usize) -> Option<u64> {
        let bytes = self.take(n)?;
        Some(
            bytes
                .iter()
                .rev()
                .fold(0, |value, &byte| value << 8 | u64::from(byte)),
        )
    }

    /// A little-endian two's-complement integer of `n` bytes, widened.
    fn signed(&mut self, n: usize) -> Option<u64> {
        let shift = 64 - 8 * u32::try_from(n).ok()?;
        let value = self.unsigned(n)?;
        Some(((value << shift).cast_signed() >> shift).cast_unsigned())
    }

    fn uleb(&mut self) -> Option<u64> {
        let (mut value, mut shift) = (0_u64, 0_u32);
        loop {
            let byte = self.u8()?;
            if shift < 64 {
                value |= u64::from(byte & 0x7f) << shift;
            }
            shift += 7;
            if byte & 0x80 == 0 {
                return Some(value);
            }
        }
    }

    fn sleb(&mut self) -> Option<u64> {
        let (mut value, mut shift) = (0_u64, 0_u32);
        loop {
            let byte = self.u8()?;
            if shift < 64 {
                value |= u64::from(byte & 0x7f) << shift;
            }
            shift += 7;
            if byte & 0x80 == 0 {
                if shift < 64 && byte & 0x40 != 0 {
                    value |= u64::MAX << shift;
                }
                return Some(value);
            }
        }
    }

    /// A value in `DW_EH_PE` `encoding`: absolute or PC-relative.
    fn encoded(&mut self, encoding: u8) -> Option<u64> {
        let field = self.base.wrapping_add(self.at as u64);
        let value = match encoding & 0x0f {
            0x00 => self.unsigned(usize::from(self.width))?,
            0x01 => self.uleb()?,
            0x02 => self.unsigned(2)?,
            0x03 => self.unsigned(4)?,
            0x04 => self.unsigned(8)?,
            0x09 => self.sleb()?,
            0x0a => self.signed(2)?,
            0x0b => self.signed(4)?,
            0x0c => self.signed(8)?,
            _ => return None,
        };
        match encoding & 0x70 {
            0x00 => Some(value),
            0x10 => Some(field.wrapping_add(value)),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Segment;

    #[test]
    fn landing_pads_from_a_uleb_call_site_table() {
        // LPStart omitted; no type table; ULEB call sites:
        // (0, 4, pad 0x10, action 0), (4, 4, no pad, 0), (8, 4, pad 0x10, 1)
        // (8, 2, pad 0x20, 0)
        let lsda = [
            0xff, 0xff, 0x01, 16, 0, 4, 0x10, 0, 4, 4, 0, 0, 8, 4, 0x10, 1, 8, 2, 0x20, 0,
        ];
        let segments = [Segment {
            addr: 0x5000,
            bytes: (&lsda[..]).into(),
            executable: false,
        }];
        let memory = Memory::new(&segments);
        assert_eq!(landing_pads(&memory, 0x5000, 0x1000, 8), [0x1010, 0x1020]);
    }

    #[test]
    fn truncated_tables_yield_what_was_read() {
        let lsda = [0xff, 0xff, 0x01, 40, 0, 4, 0x10, 0, 4];
        let segments = [Segment {
            addr: 0x5000,
            bytes: (&lsda[..]).into(),
            executable: false,
        }];
        let memory = Memory::new(&segments);
        assert_eq!(landing_pads(&memory, 0x5000, 0x1000, 8), [0x1010]);
        assert!(landing_pads(&memory, 0x9000, 0x1000, 8).is_empty());
    }

    /// A CIE with augmentation "zLR" and one FDE whose LSDA names a pad.
    #[test]
    fn eh_frame_landing_pads() {
        let section = [
            // CIE: version 1, "zLR", code 1, data -8, return in r16, LSDA
            // and addresses PC-relative 4-byte.
            0x14, 0, 0, 0, 0, 0, 0, 0, 0x01, b'z', b'L', b'R', 0, 0x01, 0x78, 0x10, 0x02, 0x1b,
            0x1b, 0x0c, 0x07, 0x08, 0x90, 0x01,
            // FDE: the function at 0x1000, 0x20 bytes, its LSDA at 0x4000.
            0x14, 0, 0, 0, 0x1c, 0, 0, 0, 0xe0, 0xdf, 0xff, 0xff, 0x20, 0, 0, 0, 0x04, 0xd7, 0x0f,
            0, 0, 0, 0, 0, // Terminator.
            0, 0, 0, 0,
        ];
        // One call site, its pad 0x10 bytes in.
        let lsda = [0xff, 0xff, 0x01, 4, 0, 5, 0x10, 0];
        let code = [0xc3_u8; 0x20];
        let segments = [
            Segment {
                addr: 0x1000,
                bytes: (&code[..]).into(),
                executable: true,
            },
            Segment {
                addr: 0x3000,
                bytes: (&section[..]).into(),
                executable: false,
            },
            Segment {
                addr: 0x4000,
                bytes: (&lsda[..]).into(),
                executable: false,
            },
        ];
        let memory = Memory::new(&segments);
        let (starts, handlers) = eh_frame(&memory, 0x3000, section.len() as u64, true);
        assert_eq!(starts, [0x1000]);
        assert_eq!(
            handlers,
            [Handler {
                function: 0x1000,
                addr: 0x1010
            }]
        );
    }

    #[test]
    fn encodings() {
        let bytes = [0xfe, 0xff, 0xff, 0xff, 0x7f, 0x10, 0x00, 0x00, 0x00];
        let mut reader = Reader {
            bytes: &bytes,
            at: 0,
            base: 0x100,
            width: 8,
        };
        assert_eq!(reader.encoded(0x0b), Some((-2_i64).cast_unsigned())); // sdata4
        assert_eq!(reader.encoded(0x09), Some((-1_i64).cast_unsigned())); // sleb 0x7f
        assert_eq!(reader.encoded(0x13), Some(0x105 + 0x10)); // pcrel udata4
    }
}
