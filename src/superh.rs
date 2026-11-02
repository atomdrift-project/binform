//! SuperH (SH-2 to SH-4), little-endian: control flow only. Instructions
//! are 16 bits. A delayed transfer (`bra`, `bsr`, `jmp`, `jsr`, `rts`,
//! `bt/s`, `bf/s`, `braf`, `bsrf`) and its slot decode as one 4-byte
//! instruction; `bt` and `bf` have no slot. Displacements count halfwords
//! from the instruction's address plus 4.

use crate::decode::{Flow, Insn};

pub(crate) fn decode(bytes: &[u8], addr: u64) -> Insn {
    let Some(word) = half(bytes) else {
        return Insn::new(2, Flow::Invalid);
    };
    let n = u32::from((word >> 8) & 0xf);
    let target = |bits: u32| {
        let field = i64::from(word) & ((1 << bits) - 1);
        let sign = 1_i64 << (bits - 1);
        addr.wrapping_add(4)
            .wrapping_add_signed(((field ^ sign) - sign) * 2)
            & 0xffff_ffff
    };
    let (flow, delayed) = match word {
        0x0000 => (Flow::Invalid, false),
        0x000b | 0x002b => (Flow::Return, true),
        _ => match word >> 12 {
            0xa => (Flow::Jump(target(12)), true),
            0xb => (Flow::Call(target(12)), true),
            0x8 => match (word >> 8) & 0xf {
                // BT, BF
                0x9 | 0xb => (Flow::Branch(target(8)), false),
                // BT/S, BF/S
                0xd | 0xf => (Flow::Branch(target(8)), true),
                _ => (Flow::Next, false),
            },
            0x4 => match word & 0xff {
                0x2b => (Flow::JumpRegister(n), true),
                0x0b => (Flow::CallIndirect, true),
                _ => (Flow::Next, false),
            },
            0x0 => match word & 0xff {
                // BRAF
                0x23 => (Flow::JumpIndirect, true),
                // BSRF
                0x03 => (Flow::CallIndirect, true),
                _ => (Flow::Next, false),
            },
            _ => (Flow::Next, false),
        },
    };
    if !delayed {
        let mut insn = Insn::new(2, flow);
        insn.pad = word == 0x0009;
        return insn;
    }
    // A transfer with no slot after it is cut short: the slot is not code.
    match bytes.get(2..).and_then(half) {
        Some(_) => Insn::new(4, flow),
        None => Insn::new(2, Flow::Invalid),
    }
}

fn half(bytes: &[u8]) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(..2)?.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(halves: &[u16], addr: u64) -> Insn {
        let bytes: Vec<u8> = halves.iter().flat_map(|h| h.to_le_bytes()).collect();
        decode(&bytes, addr)
    }

    const NOP: u16 = 0x0009;

    #[test]
    fn transfers() {
        // bsr +0x10 halfwords
        let call = one(&[0xb010, NOP], 0x1000);
        assert_eq!((call.len, call.flow), (4, Flow::Call(0x1024)));
        // bra -2: to itself
        assert_eq!(one(&[0xaffe, NOP], 0x1000).flow, Flow::Jump(0x1000));
        // rts
        assert_eq!(one(&[0x000b, NOP], 0x1000).flow, Flow::Return);
        // bt +2, without a slot; bf/s with one
        let bt = one(&[0x8902], 0x1000);
        assert_eq!((bt.len, bt.flow), (2, Flow::Branch(0x1008)));
        assert_eq!(one(&[0x8f02, NOP], 0x1000).len, 4);
        // jsr @r1; jmp @r2
        assert_eq!(one(&[0x410b, NOP], 0x1000).flow, Flow::CallIndirect);
        assert_eq!(one(&[0x422b, NOP], 0x1000).flow, Flow::JumpRegister(2));
    }

    #[test]
    fn others() {
        assert!(one(&[NOP], 0).pad);
        // mov.l r14, @-r15
        assert_eq!(one(&[0x2fe6], 0).flow, Flow::Next);
        assert_eq!(one(&[0], 0).flow, Flow::Invalid);
        assert_eq!(one(&[0x000b], 0).flow, Flow::Invalid);
    }
}
