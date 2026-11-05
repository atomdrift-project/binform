//! Exception-handling tables: where `.eh_frame` says functions start, and
//! where each function's language-specific data area (LSDA, in
//! `.gcc_except_table`) says its landing pads are.
//!
//! A landing pad is code inside a function that no instruction branches to:
//! the unwinder enters it to run a destructor or a `catch`. Without it, a
//! function's graph misses its cleanup code.

use std::collections::{HashMap, HashSet};
use std::ops::Range;

use gimli::{BaseAddresses, EhFrame, EhFrameOffset, Pointer, RunTimeEndian, UnwindSection};

use super::limits;
use super::read::{self, Reader};
use crate::Handler;
use crate::isa::Memory;

/// `DW_EH_PE_omit`: the field is absent.
const OMIT: u8 = 0xff;
/// The CIE pointer field of a CIE, which an FDE's points back at one.
const CIE_ID: u32 = 0;
/// The 32-bit length that says a 64-bit one follows.
const LENGTH_64: u32 = 0xffff_ffff;

/// Every function's code the `.eh_frame` at `addr` describes; the landing
/// pads its LSDAs name go to `pads`. Each record is read on its own, by its
/// length: a malformed one is skipped, and one that runs past the section
/// ends the walk.
pub(super) fn eh_frame(
    memory: &Memory<'_>,
    addr: u64,
    size: u64,
    pads: &mut Pads,
) -> Vec<Range<u64>> {
    let Some((data, _)) = memory.at(addr) else {
        return Vec::new();
    };
    let data = data
        .get(..usize::try_from(size).unwrap_or(usize::MAX).min(data.len()))
        .unwrap_or_default();
    let big = memory.big_endian();
    let endian = if big {
        RunTimeEndian::Big
    } else {
        RunTimeEndian::Little
    };
    let mut eh_frame = EhFrame::new(data, endian);
    eh_frame.set_address_size(pads.width);
    let bases = BaseAddresses::default().set_eh_frame(addr);
    let r = Reader::new(data, big);
    // A record's end, and whether it is an FDE: its length (a 64-bit one
    // after `LENGTH_64`), then its CIE pointer. A zero length ends the
    // section.
    let record = |at: u64| -> Option<(u64, bool)> {
        let record = r.at(at);
        let (header, length) = match record.u32(0)? {
            0 => return None,
            LENGTH_64 => (12, record.u64(4)?),
            length => (4, u64::from(length)),
        };
        let fde = record.u32(header)? != CIE_ID;
        let end = at.checked_add(header)?.checked_add(length)?;
        (end <= r.bytes.len() as u64).then_some((end, fde))
    };
    let mut extents = Vec::new();
    let mut at = 0;
    while let Some((end, fde)) = record(at) {
        let offset = EhFrameOffset(usize::try_from(at).unwrap_or(usize::MAX));
        if fde && let Ok(fde) = eh_frame.fde_from_offset(&bases, offset, EhFrame::cie_from_offset) {
            let function = fde.initial_address();
            extents.push(function..function.saturating_add(fde.len()));
            let lsda = match fde.lsda() {
                Some(Pointer::Direct(lsda)) => Some(lsda),
                Some(Pointer::Indirect(slot)) => memory.read(slot, pads.width),
                None => None,
            };
            if let Some(lsda) = lsda {
                pads.add(memory, function, lsda);
            }
        }
        at = end;
    }
    extents
}

/// The landing pads of a file's functions. Each LSDA is read once, however
/// many functions name it, and all of them within [`limits::CALL_SITES`]
/// and [`limits::HANDLERS`].
pub(super) struct Pads {
    /// Bytes in an address.
    width: u8,
    lsdas: HashMap<u64, Lsda>,
    /// Call-site records left to read.
    sites: usize,
    pub(super) handlers: Vec<Handler>,
}

/// One LSDA's landing pads, as offsets from its landing-pad base: its
/// own, or (`None`) the start of the function naming it.
struct Lsda {
    start: Option<u64>,
    pads: Vec<u64>,
}

impl Pads {
    pub(super) fn new(width: u8) -> Self {
        Self {
            width,
            lsdas: HashMap::new(),
            sites: limits::CALL_SITES,
            handlers: Vec::new(),
        }
    }

    /// Records the landing pads the LSDA at `lsda` names for the function
    /// at `function`, in table order without repeats.
    pub(super) fn add(&mut self, memory: &Memory<'_>, function: u64, lsda: u64) {
        let (width, sites) = (self.width, &mut self.sites);
        let table = self
            .lsdas
            .entry(lsda)
            .or_insert_with(|| read_lsda(memory, lsda, width, sites));
        let start = table.start.unwrap_or(function);
        let room = limits::HANDLERS.saturating_sub(self.handlers.len());
        self.handlers
            .extend(table.pads.iter().take(room).map(|&pad| Handler {
                function,
                addr: start.wrapping_add(pad),
            }));
    }
}

/// The LSDA at `addr`, as much of it as is there; `sites` is the budget of
/// call-site records it may spend.
fn read_lsda(memory: &Memory<'_>, addr: u64, width: u8, sites: &mut usize) -> Lsda {
    let mut lsda = Lsda {
        start: None,
        pads: Vec::new(),
    };
    let Some((bytes, _)) = memory.at(addr) else {
        return lsda;
    };
    let mut c = Cursor {
        r: Reader::new(bytes, memory.big_endian()),
        at: 0,
        base: addr,
        width,
    };
    // A truncated LSDA, or one past the budget, keeps what was read.
    let _ = read_call_sites(&mut c, &mut lsda, sites);
    lsda
}

/// Read the LSDA header and call-site table at `c` into `lsda`, spending
/// `sites`; `None` where they end early.
fn read_call_sites(c: &mut Cursor<'_>, lsda: &mut Lsda, sites: &mut usize) -> Option<()> {
    let start_encoding = c.u8()?;
    if start_encoding != OMIT {
        lsda.start = Some(c.encoded(start_encoding)?);
    }
    if c.u8()? != OMIT {
        c.uleb()?; // type-table offset
    }
    let site_encoding = c.u8()?;
    let end = c.at.checked_add(c.uleb()?)?.min(c.r.bytes.len() as u64);
    let mut seen = HashSet::new();
    while c.at < end && lsda.pads.len() < limits::PADS {
        *sites = sites.checked_sub(1)?;
        c.encoded(site_encoding)?; // call-site start
        c.encoded(site_encoding)?; // call-site length
        let pad = c.encoded(site_encoding)?;
        c.uleb()?; // action
        if pad != 0 && seen.insert(pad) {
            lsda.pads.push(pad);
        }
    }
    Some(())
}

/// A cursor over DWARF exception-handling encodings.
struct Cursor<'a> {
    r: Reader<'a>,
    at: u64,
    /// The address of the first byte, for PC-relative values.
    base: u64,
    /// Bytes in an address.
    width: u8,
}

impl Cursor<'_> {
    fn u8(&mut self) -> Option<u8> {
        let value = self.r.u8(self.at)?;
        self.at = self.at.checked_add(1)?;
        Some(value)
    }

    /// An unsigned integer of `size` bytes.
    fn unsigned(&mut self, size: u8) -> Option<u64> {
        let value = self.r.uint(self.at, size)?;
        self.at = self.at.checked_add(u64::from(size))?;
        Some(value)
    }

    /// A two's-complement integer of `size` bytes, widened.
    fn signed(&mut self, size: u8) -> Option<u64> {
        let value = self.unsigned(size)?;
        let value = match size {
            2 => i64::from(u16::try_from(value).ok()?.cast_signed()),
            4 => i64::from(u32::try_from(value).ok()?.cast_signed()),
            _ => value.cast_signed(),
        };
        Some(value.cast_unsigned())
    }

    fn leb(&mut self, decode: fn(&[u8], &mut usize) -> Option<u64>) -> Option<u64> {
        let mut at = usize::try_from(self.at).ok()?;
        let value = decode(self.r.bytes, &mut at)?;
        self.at = u64::try_from(at).ok()?;
        Some(value)
    }

    fn uleb(&mut self) -> Option<u64> {
        self.leb(read::uleb128)
    }

    /// A value in `DW_EH_PE` `encoding`: absolute or PC-relative.
    fn encoded(&mut self, encoding: u8) -> Option<u64> {
        let field = self.base.wrapping_add(self.at);
        let value = match encoding & 0x0f {
            0x00 => self.unsigned(self.width)?,
            0x01 => self.uleb()?,
            0x02 => self.unsigned(2)?,
            0x03 => self.unsigned(4)?,
            0x04 => self.unsigned(8)?,
            0x09 => self.leb(read::sleb128)?,
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

    fn pads(segments: &[Segment<'_>], big: bool, lsda: u64, function: u64) -> Vec<u64> {
        let memory = if big {
            Memory::for_arch(segments, crate::Arch::Mips)
        } else {
            Memory::new(segments)
        };
        let mut pads = Pads::new(8);
        pads.add(&memory, function, lsda);
        pads.handlers.iter().map(|handler| handler.addr).collect()
    }

    fn data(addr: u64, bytes: &[u8]) -> Segment<'_> {
        Segment {
            addr,
            bytes: bytes.into(),
            executable: false,
        }
    }

    #[test]
    fn landing_pads_from_a_uleb_call_site_table() {
        // LPStart omitted; no type table; ULEB call sites:
        // (0, 4, pad 0x10, action 0), (4, 4, no pad, 0), (8, 4, pad 0x10, 1)
        // (8, 2, pad 0x20, 0)
        let lsda = [
            0xff, 0xff, 0x01, 16, 0, 4, 0x10, 0, 4, 4, 0, 0, 8, 4, 0x10, 1, 8, 2, 0x20, 0,
        ];
        let segments = [data(0x5000, &lsda)];
        assert_eq!(pads(&segments, false, 0x5000, 0x1000), [0x1010, 0x1020]);
    }

    /// A big-endian target's LSDA holds its fixed-size fields big-endian.
    #[test]
    fn landing_pads_in_big_endian() {
        // udata4 call sites: (0, 4, pad 0x10, action 0).
        let lsda = [
            0xff, 0xff, 0x03, 13, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0x10, 0,
        ];
        let segments = [data(0x5000, &lsda)];
        assert_eq!(pads(&segments, true, 0x5000, 0x1000), [0x1010]);
        assert_eq!(pads(&segments, false, 0x5000, 0x1000), [0x1000_1000]);
    }

    #[test]
    fn truncated_tables_yield_what_was_read() {
        let lsda = [0xff, 0xff, 0x01, 40, 0, 4, 0x10, 0, 4];
        let segments = [data(0x5000, &lsda)];
        assert_eq!(pads(&segments, false, 0x5000, 0x1000), [0x1010]);
        assert!(pads(&segments, false, 0x9000, 0x1000).is_empty());
    }

    /// A million functions naming one LSDA of 2048 pads read it once
    /// and keep at most `limits::HANDLERS` pads between them.
    #[test]
    fn shared_lsdas_are_read_once_and_bounded() {
        // 2048 ULEB call sites of 5 bytes, 10240 in all: (0, 0, pad, 0).
        let mut lsda = vec![0xff, 0xff, 0x01, 0x80, 0x50];
        for pad in 1..=2048_u32 {
            let [low, high, ..] = (pad & 0x7f | 0x80 | (pad >> 7) << 8).to_le_bytes();
            lsda.extend([0, 0, low, high, 0]);
        }
        let segments = [data(0x5000, &lsda)];
        let memory = Memory::new(&segments);
        let mut pads = Pads::new(8);
        let start = std::time::Instant::now();
        for function in 0..1_000_000 {
            pads.add(&memory, function, 0x5000);
        }
        assert_eq!(pads.lsdas.len(), 1);
        assert_eq!(pads.handlers.len(), limits::HANDLERS);
        assert!(start.elapsed().as_secs() < 5);
    }

    /// A CIE with augmentation "zLR" and one FDE whose LSDA names a pad,
    /// after a record that is no CIE: it is skipped, not the end.
    #[test]
    fn eh_frame_landing_pads() {
        let section = [
            // Garbage: a record of 4 bytes whose CIE pointer points nowhere.
            0x04, 0, 0, 0, 0xff, 0xff, 0, 0, //
            // CIE: version 1, "zLR", code 1, data -8, return in r16, LSDA
            // and addresses PC-relative 4-byte.
            0x14, 0, 0, 0, 0, 0, 0, 0, 0x01, b'z', b'L', b'R', 0, 0x01, 0x78, 0x10, 0x02, 0x1b,
            0x1b, 0x0c, 0x07, 0x08, 0x90, 0x01,
            // FDE: the function at 0x1000, 0x20 bytes, its LSDA at 0x4000.
            0x14, 0, 0, 0, 0x1c, 0, 0, 0, 0xd8, 0xdf, 0xff, 0xff, 0x20, 0, 0, 0, 0x04, 0xcf, 0x0f,
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
            data(0x3000, &section),
            data(0x4000, &lsda),
        ];
        let memory = Memory::new(&segments);
        let mut pads = Pads::new(8);
        let extents = eh_frame(&memory, 0x3000, section.len() as u64, &mut pads);
        assert_eq!(extents.first(), Some(&(0x1000..0x1020)));
        assert_eq!(extents.len(), 1);
        assert_eq!(
            pads.handlers,
            [Handler {
                function: 0x1000,
                addr: 0x1010
            }]
        );
    }

    #[test]
    fn encodings() {
        let bytes = [0xfe, 0xff, 0xff, 0xff, 0x7f, 0x10, 0x00, 0x00, 0x00];
        let mut c = Cursor {
            r: Reader::new(&bytes, false),
            at: 0,
            base: 0x100,
            width: 8,
        };
        assert_eq!(c.encoded(0x0b), Some((-2_i64).cast_unsigned())); // sdata4
        assert_eq!(c.encoded(0x09), Some((-1_i64).cast_unsigned())); // sleb 0x7f
        assert_eq!(c.encoded(0x13), Some(0x105 + 0x10)); // pcrel udata4
    }
}
