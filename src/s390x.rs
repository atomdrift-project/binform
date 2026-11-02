//! z/Architecture (s390x): control flow only. Instructions are 2, 4 or 6
//! bytes, by the top two bits of their first byte, and big-endian; relative
//! branches count halfwords from the instruction's own address.

use crate::decode::{Flow, Insn};

/// The register a call leaves its return address in by convention.
const R14: u32 = 14;

pub(crate) fn decode(bytes: &[u8], addr: u64) -> Insn {
    let Some(&first) = bytes.first() else {
        return Insn::new(2, Flow::Invalid);
    };
    let len: u32 = match first >> 6 {
        0 => 2,
        1 | 2 => 4,
        _ => 6,
    };
    let Some(insn) = bytes.get(..len as usize) else {
        return Insn::new(2, Flow::Invalid);
    };
    let byte = |i: usize| insn.get(i).copied().unwrap_or(0);
    let (high, low) = (u32::from(byte(1) >> 4), u32::from(byte(1) & 0xf));
    // A signed halfword offset in bytes `at..at + width`.
    let relative = |at: usize, width: usize| {
        let raw = insn
            .get(at..at + width)
            .unwrap_or_default()
            .iter()
            .fold(0_i64, |value, &b| value << 8 | i64::from(b));
        let sign = 1_i64 << (8 * width - 1);
        addr.wrapping_add_signed(((raw ^ sign) - sign) * 2)
    };
    // A branch on condition mask `mask`: never, always, or sometimes.
    let on = |mask: u32, target: u64| match mask {
        0 => Flow::Next,
        15 => Flow::Jump(target),
        _ => Flow::Branch(target),
    };
    let mut falls = false;
    let mut pad = false;
    let flow = match first {
        // An all-zero halfword is no valid instruction.
        0x00 => Flow::Invalid,
        // BCR M1, R2: `br r14` returns.
        0x07 if high == 0 || low == 0 => {
            pad = true;
            Flow::Next
        }
        0x07 => {
            falls = high != 15;
            if low == R14 {
                Flow::Return
            } else {
                Flow::JumpRegister(low)
            }
        }
        // BALR, BASR: a call through R2 (none on R0, which only links).
        0x05 | 0x0d if low != 0 => Flow::CallIndirect,
        // BC M1, D2(X2, B2)
        0x47 if high == 0 => {
            pad = true;
            Flow::Next
        }
        0x47 => {
            falls = high != 15;
            Flow::JumpIndirect
        }
        // BAL, BAS
        0x45 | 0x4d => Flow::CallIndirect,
        // BRC, BRAS, BRCT, BRCTG
        0xa7 => match low {
            4 => on(high, relative(2, 2)),
            5 => Flow::Call(relative(2, 2)),
            6 | 7 => Flow::Branch(relative(2, 2)),
            _ => Flow::Next,
        },
        // BRXH, BRXLE
        0x84 | 0x85 => Flow::Branch(relative(2, 2)),
        // BRCL, BRASL
        0xc0 => match low {
            4 => on(high, relative(2, 4)),
            5 => Flow::Call(relative(2, 4)),
            _ => Flow::Next,
        },
        // BRCTH
        0xcc if low == 6 => Flow::Branch(relative(2, 4)),
        // BRXHG, BRXLG, and the compare-and-branch-relative family.
        0xec => match byte(5) {
            0x44 | 0x45 | 0x64 | 0x65 | 0x76 | 0x77 | 0x7c..=0x7f => Flow::Branch(relative(2, 2)),
            _ => Flow::Next,
        },
        _ => Flow::Next,
    };
    let mut decoded = Insn::new(len, flow);
    decoded.falls = falls
        && matches!(
            flow,
            Flow::Return | Flow::JumpRegister(_) | Flow::JumpIndirect
        );
    decoded.pad = pad;
    decoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calls_jumps_and_returns() {
        // brasl %r14, +0x100
        let call = decode(&[0xc0, 0xe5, 0, 0, 0, 0x80], 0x1000);
        assert_eq!((call.len, call.flow), (6, Flow::Call(0x1100)));
        // br %r14
        assert_eq!(decode(&[0x07, 0xfe], 0x1000).flow, Flow::Return);
        // bner %r14: a conditional return.
        let ret = decode(&[0x07, 0x7e], 0x1000);
        assert!(ret.flow == Flow::Return && ret.falls);
        // br %r1
        assert_eq!(decode(&[0x07, 0xf1], 0x1000).flow, Flow::JumpRegister(1));
        // basr %r14, %r1
        assert_eq!(decode(&[0x0d, 0xe1], 0x1000).flow, Flow::CallIndirect);
        // j -4 (brc 15)
        assert_eq!(
            decode(&[0xa7, 0xf4, 0xff, 0xfe], 0x1000).flow,
            Flow::Jump(0xffc)
        );
        // jne +8
        assert_eq!(
            decode(&[0xa7, 0x74, 0, 4], 0x1000).flow,
            Flow::Branch(0x1008)
        );
        // jg (brcl 15) -2
        assert_eq!(
            decode(&[0xc0, 0xf4, 0xff, 0xff, 0xff, 0xff], 0x1000).flow,
            Flow::Jump(0xffe)
        );
        // cgij %r2, 0, 8, +6
        assert_eq!(
            decode(&[0xec, 0x28, 0, 3, 0, 0x7c], 0x1000).flow,
            Flow::Branch(0x1006)
        );
    }

    #[test]
    fn lengths_and_padding() {
        // lgr %r1, %r2; lg %r1, 8(%r15); nopr
        assert_eq!(decode(&[0xb9, 0x04, 0, 0x12], 0).len, 4);
        assert_eq!(decode(&[0xe3, 0x10, 0xf0, 0x08, 0, 0x04], 0).len, 6);
        assert!(decode(&[0x07, 0x07], 0).pad);
        assert_eq!(decode(&[0, 0], 0).flow, Flow::Invalid);
        assert_eq!(decode(&[0xc0, 0xe5, 0], 0).flow, Flow::Invalid);
    }
}
