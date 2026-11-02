//! SPARC (V8 and V9): control flow only. Words are big-endian. A transfer
//! and the instruction in its delay slot decode as one 8-byte instruction,
//! so a call returns past the slot (to `%o7 + 8`, as `ret` and `retl` go).

use crate::decode::{Flow, Insn};

/// `%o7`, where `call` and `jmpl` leave the caller's address.
const O7: u32 = 15;
/// `%i7`: the caller's `%o7`, after a `save`.
const I7: u32 = 31;

pub(crate) fn decode(wide: bool, bytes: &[u8], addr: u64) -> Insn {
    let Some(word) = read_word(bytes) else {
        return Insn::new(4, Flow::Invalid);
    };
    let wrap = |target: u64| if wide { target } else { target & 0xffff_ffff };
    let Some(flow) = flow(word, addr, wrap) else {
        let mut insn = Insn::new(4, Flow::Next);
        // `nop` is `sethi 0, %g0`.
        insn.pad = word == 0x0100_0000;
        return insn;
    };
    if matches!(flow, Flow::Stop | Flow::Invalid) {
        return Insn::new(4, flow);
    }
    // A transfer with no slot after it is cut short: the slot is not code.
    match bytes.get(4..8).and_then(read_word) {
        Some(_) => Insn::new(8, flow),
        None => Insn::new(4, Flow::Invalid),
    }
}

fn read_word(bytes: &[u8]) -> Option<u32> {
    Some(u32::from_be_bytes(bytes.get(..4)?.try_into().ok()?))
}

/// A signed `bits`-bit word displacement from `addr`.
fn displaced(addr: u64, word: u32, bits: u32) -> u64 {
    let field = i64::from(word & ((1 << bits) - 1));
    let sign = 1_i64 << (bits - 1);
    addr.wrapping_add_signed(((field ^ sign) - sign) * 4)
}

/// Where control goes after the transfer at `addr` and its slot; `None`
/// for an instruction that is no transfer.
fn flow(word: u32, addr: u64, wrap: impl Fn(u64) -> u64) -> Option<Flow> {
    let rd = (word >> 25) & 0x1f;
    let cond = (word >> 25) & 0xf;
    match word >> 30 {
        // CALL disp30
        1 => Some(Flow::Call(wrap(displaced(addr, word, 30)))),
        0 => {
            let target = match (word >> 22) & 7 {
                // UNIMP / ILLTRAP: zeros, or a struct-return size word.
                0 => return Some(Flow::Invalid),
                // BPcc, FBPfcc: 19-bit displacement.
                1 | 5 => displaced(addr, word, 19),
                // Bicc, FBfcc: 22-bit displacement.
                2 | 6 => displaced(addr, word, 22),
                // BPr: 16 bits split in two fields; no "always" condition.
                3 => {
                    let field = (word >> 6) & 0xc000 | word & 0x3fff;
                    return Some(Flow::Branch(wrap(displaced(addr, field, 16))));
                }
                _ => return None,
            };
            Some(match cond {
                // BN: never taken, but a prefetch of its slot.
                0 => Flow::Next,
                // BA: always.
                8 => Flow::Jump(wrap(target)),
                _ => Flow::Branch(wrap(target)),
            })
        }
        2 => {
            let rs1 = (word >> 14) & 0x1f;
            let immediate = word & 0x2000 != 0;
            match (word >> 19) & 0x3f {
                // JMPL: `ret` and `retl` jump past the call's slot.
                0x38 if rd == 0 && immediate && word & 0x1fff == 8 && (rs1 == I7 || rs1 == O7) => {
                    Some(Flow::Return)
                }
                0x38 if rd == O7 => Some(Flow::CallIndirect),
                0x38 if rd == 0 && !immediate => Some(Flow::JumpIndirect),
                0x38 if rd == 0 => Some(Flow::JumpRegister(rs1)),
                // A link into another register: a call by another name.
                0x38 => Some(Flow::CallIndirect),
                // RETURN (V9)
                0x39 => Some(Flow::Return),
                _ => None,
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(words: &[u32], addr: u64) -> Insn {
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_be_bytes()).collect();
        decode(false, &bytes, addr)
    }

    const NOP: u32 = 0x0100_0000;

    #[test]
    fn transfers_take_their_slot() {
        // call +0x40
        let call = one(&[0x4000_0010, NOP], 0x1_0000);
        assert_eq!((call.len, call.flow), (8, Flow::Call(0x1_0040)));
        // call -4
        assert_eq!(one(&[0x7fff_ffff, NOP], 0x1_0000).flow, Flow::Call(0xfffc));
        // ret; restore
        assert_eq!(one(&[0x81c7_e008, 0x81e8_0000], 0x1000).flow, Flow::Return);
        // retl
        assert_eq!(one(&[0x81c3_e008, NOP], 0x1000).flow, Flow::Return);
        // ba +8; bne -8
        assert_eq!(one(&[0x1080_0002, NOP], 0x1000).flow, Flow::Jump(0x1008));
        assert_eq!(one(&[0x12bf_fffe, NOP], 0x1000).flow, Flow::Branch(0xff8));
        // jmpl %g1, %o7: a call through a register
        assert_eq!(one(&[0x9fc0_4000, NOP], 0x1000).flow, Flow::CallIndirect);
        // jmp %g1
        assert_eq!(one(&[0x81c0_6000, NOP], 0x1000).flow, Flow::JumpRegister(1));
        // brz %o0, +8 (BPr)
        assert_eq!(one(&[0x02c2_0002, NOP], 0x1000).flow, Flow::Branch(0x1008));
    }

    #[test]
    fn others() {
        let nop = one(&[NOP], 0x1000);
        assert_eq!((nop.len, nop.flow, nop.pad), (4, Flow::Next, true));
        // save %sp, -96, %sp
        assert_eq!(one(&[0x9de3_bfa0], 0x1000).flow, Flow::Next);
        assert_eq!(one(&[0], 0x1000).flow, Flow::Invalid);
        assert_eq!(one(&[0x4000_0010], 0x1000).flow, Flow::Invalid);
    }
}
