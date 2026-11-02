//! A64. Only control flow is decoded, plus the `adrp`/`add`/`ldr` sequence
//! that stubs load a slot's address with; every other instruction falls
//! through.

use crate::decode::{Flow, Insn, Note};

/// What the instructions since the last reset left in each general register.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct State {
    /// A known address held in the register.
    value: [Option<u64>; 32],
    /// The register was loaded from this fixed address.
    loaded: [Option<u64>; 32],
}

pub(crate) fn decode(state: &mut State, bytes: &[u8], addr: u64) -> Insn {
    let word = bytes
        .get(..4)
        .and_then(|word| word.try_into().ok())
        .map(u32::from_le_bytes);
    let Some(word) = word else {
        return Insn {
            len: 4,
            flow: Flow::Stop,
            note: Note::None,
            pad: false,
        };
    };
    Insn {
        len: 4,
        flow: flow(state, word, addr),
        note: Note::None,
        // NOP, BTI, PACIASP and the rest of the hint space.
        pad: word & 0xffff_f01f == 0xd503_201f,
    }
}

/// `stp x29, x30, [sp, ...]`, saving the frame record, after at most two of
/// `bti c`, `paciasp` and `sub sp, sp, #n`.
pub(crate) fn starts_frame(bytes: &[u8]) -> bool {
    for word in bytes.chunks_exact(4).take(3) {
        let Ok(word) = <[u8; 4]>::try_from(word) else {
            return false;
        };
        let word = u32::from_le_bytes(word);
        // Pre-indexed or signed-offset, at any offset.
        let pair = word & 0xffc0_7fff;
        if pair == 0xa980_7bfd || pair == 0xa900_7bfd {
            return true;
        }
        let prefix = word == 0xd503_245f // bti c
            || word == 0xd503_233f // paciasp
            || word & 0xff80_03ff == 0xd100_03ff; // sub sp, sp, #n
        if !prefix {
            return false;
        }
    }
    false
}

fn flow(state: &mut State, word: u32, addr: u64) -> Flow {
    let rd = (word & 0x1f) as usize;
    let rn = ((word >> 5) & 0x1f) as usize;
    if word & 0x7c00_0000 == 0x1400_0000 {
        // B, BL
        let target = relative(addr, word & 0x03ff_ffff, 26);
        return if word & 0x8000_0000 == 0 {
            Flow::Jump(target)
        } else {
            Flow::Call(target)
        };
    }
    if word & 0xff00_0010 == 0x5400_0000 || word & 0x7e00_0000 == 0x3400_0000 {
        // B.cond, CBZ, CBNZ
        return Flow::Branch(relative(addr, (word >> 5) & 0x7_ffff, 19));
    }
    if word & 0x7e00_0000 == 0x3600_0000 {
        // TBZ, TBNZ
        return Flow::Branch(relative(addr, (word >> 5) & 0x3fff, 14));
    }
    if word & 0xfe00_0000 == 0xd600_0000 {
        // Branch to register: BR, BLR, RET, ERET, DRPS, and their
        // pointer-authenticating forms.
        let slot = state.loaded.get(rn).copied().flatten();
        return match (word >> 21) & 0xf {
            0 | 8 => slot.map_or(Flow::JumpIndirect, Flow::JumpSlot),
            1 | 9 => slot.map_or(Flow::CallIndirect, Flow::CallSlot),
            2 | 4 | 5 => Flow::Return,
            _ => Flow::Stop,
        };
    }
    if word & 0xffe0_001f == 0xd420_0000 || word & 0xffe0_001f == 0xd440_0000 || word >> 16 == 0 {
        // BRK, HLT, UDF
        return Flow::Stop;
    }
    if word & 0x9f00_0000 == 0x9000_0000 {
        // ADRP
        let imm = (((word >> 5) & 0x7_ffff) << 2) | ((word >> 29) & 0x3);
        let page = (addr & !0xfff).wrapping_add((sign_extend(imm, 21) << 12) as u64);
        set(state, rd, Some(page), None);
    } else if word & 0xff80_0000 == 0x9100_0000 {
        // ADD (immediate, 64-bit)
        let shift = if word & 0x0040_0000 == 0 { 0 } else { 12 };
        let imm = u64::from((word >> 10) & 0xfff) << shift;
        let value = state.value.get(rn).copied().flatten();
        set(state, rd, value.map(|value| value.wrapping_add(imm)), None);
    } else if word & 0xffc0_0000 == 0xf940_0000 {
        // LDR (immediate, unsigned offset, 64-bit)
        let offset = u64::from((word >> 10) & 0xfff) * 8;
        let base = state.value.get(rn).copied().flatten();
        set(state, rd, None, base.map(|base| base.wrapping_add(offset)));
    }
    Flow::Next
}

fn set(state: &mut State, register: usize, value: Option<u64>, loaded: Option<u64>) {
    if let Some(slot) = state.value.get_mut(register) {
        *slot = value;
    }
    if let Some(slot) = state.loaded.get_mut(register) {
        *slot = loaded;
    }
}

/// `addr` plus a signed, `bits`-wide offset counted in instructions.
fn relative(addr: u64, imm: u32, bits: u32) -> u64 {
    addr.wrapping_add((sign_extend(imm, bits) << 2) as u64)
}

fn sign_extend(value: u32, bits: u32) -> i64 {
    let shift = 64 - bits;
    (i64::from(value) << shift) >> shift
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|word| word.to_le_bytes()).collect()
    }

    #[test]
    fn frames() {
        // stp x29, x30, [sp, #-16]!
        assert!(starts_frame(&words(&[0xa9bf_7bfd])));
        // paciasp; sub sp, sp, #0x40; stp x29, x30, [sp, #0x30]
        assert!(starts_frame(&words(&[
            0xd503_233f,
            0xd101_03ff,
            0xa903_7bfd
        ])));
        // ret
        assert!(!starts_frame(&words(&[0xd65f_03c0, 0xa9bf_7bfd])));
        assert!(!starts_frame(&[]));
    }

    fn one(word: u32, addr: u64) -> Flow {
        decode(&mut State::default(), &word.to_le_bytes(), addr).flow
    }

    #[test]
    fn branches() {
        assert_eq!(one(0x1400_0004, 0x1000), Flow::Jump(0x1010)); // b +16
        assert_eq!(one(0x17ff_ffff, 0x1000), Flow::Jump(0xffc)); // b -4
        assert_eq!(one(0x9400_0002, 0x1000), Flow::Call(0x1008)); // bl +8
        assert_eq!(one(0x5400_0040, 0x1000), Flow::Branch(0x1008)); // b.eq +8
        assert_eq!(one(0xb400_0060, 0x1000), Flow::Branch(0x100c)); // cbz x0, +12
        assert_eq!(one(0x3600_0080, 0x1000), Flow::Branch(0x1010)); // tbz w0, #0, +16
        assert_eq!(one(0xd65f_03c0, 0x1000), Flow::Return); // ret
        assert_eq!(one(0xd65f_0bff, 0x1000), Flow::Return); // retaa
        assert_eq!(one(0xd61f_0200, 0x1000), Flow::JumpIndirect); // br x16
        assert_eq!(one(0xd63f_0200, 0x1000), Flow::CallIndirect); // blr x16
        assert_eq!(one(0xd420_0000, 0x1000), Flow::Stop); // brk #0
        assert_eq!(one(0x0000_0000, 0x1000), Flow::Stop); // udf #0
        assert_eq!(one(0xaa01_03e0, 0x1000), Flow::Next); // mov x0, x1
    }

    /// A Mach-O `__stubs` entry: `adrp x16, page; ldr x16, [x16, #off]; br x16`.
    #[test]
    fn stub_jumps_through_its_slot() {
        let mut state = State::default();
        let words = [0xb000_0010_u32, 0xf940_0610, 0xd61f_0200];
        let flows: Vec<Flow> = (0_u64..)
            .zip(words)
            .map(|(i, word)| decode(&mut state, &word.to_le_bytes(), 0x1_0000 + 4 * i).flow)
            .collect();
        // adrp x16, #0x1000 at 0x10000 is page 0x11000; the slot is 8 bytes in.
        assert_eq!(flows, [Flow::Next, Flow::Next, Flow::JumpSlot(0x1_1008)]);
    }

    #[test]
    fn hints_are_padding() {
        let pad = |word: u32| decode(&mut State::default(), &word.to_le_bytes(), 0).pad;
        assert!(pad(0xd503_201f)); // nop
        assert!(pad(0xd503_245f)); // bti c
        assert!(!pad(0xaa01_03e0)); // mov x0, x1
    }
}
