//! MIPS (32- and 64-bit, either byte order): control flow only. A branch,
//! jump, call or return and the instruction in its delay slot, which runs
//! before control moves, decode as one 8-byte instruction, so a call
//! returns past the slot and a block ends after it.

use crate::decode::{Flow, Insn};

/// The return-address register, `$ra`.
const RA: u32 = 31;

pub(crate) fn decode(big: bool, wide: bool, bytes: &[u8], addr: u64) -> Insn {
    let Some(word) = read_word(big, bytes) else {
        return Insn::new(4, Flow::Invalid);
    };
    let Some(flow) = flow(word, addr, wide) else {
        let mut insn = Insn::new(4, Flow::Next);
        // `nop` (`sll $0, $0, 0`) and `ssnop`.
        insn.pad = word == 0 || word == 0x40;
        return insn;
    };
    // A trap has no slot.
    if flow == Flow::Stop {
        return Insn::new(4, flow);
    }
    // A transfer with no slot after it is cut short: the slot is not code.
    match bytes.get(4..8).and_then(|slot| read_word(big, slot)) {
        Some(_) => Insn::new(8, flow),
        None => Insn::new(4, Flow::Invalid),
    }
}

fn read_word(big: bool, bytes: &[u8]) -> Option<u32> {
    let bytes: [u8; 4] = bytes.get(..4)?.try_into().ok()?;
    Some(if big {
        u32::from_be_bytes(bytes)
    } else {
        u32::from_le_bytes(bytes)
    })
}

/// Where control goes after the transfer at `addr` and its slot; `None`
/// for an instruction that is no transfer.
fn flow(word: u32, addr: u64, wide: bool) -> Option<Flow> {
    let opcode = word >> 26;
    let rs = (word >> 21) & 0x1f;
    let rt = (word >> 16) & 0x1f;
    let slot = addr.wrapping_add(4);
    let wrap = |target: u64| if wide { target } else { target & 0xffff_ffff };
    // A 16-bit word offset from the slot.
    let offset = (i64::from(word & 0xffff) ^ 0x8000) - 0x8000;
    let branch = wrap(slot.wrapping_add_signed(offset << 2));
    Some(match opcode {
        0 => match word & 0x3f {
            // JR, JR.HB
            0x08 if rs == RA => Flow::Return,
            0x08 => Flow::JumpRegister(rs),
            // JALR
            0x09 => Flow::CallIndirect,
            // BREAK
            0x0d => Flow::Stop,
            _ => return None,
        },
        // REGIMM: BLTZ, BGEZ and their likely and linking forms.
        1 => match rt {
            0x00..=0x03 => Flow::Branch(branch),
            // BLTZAL, BGEZAL (`bal` on $zero) and their likely forms.
            0x10..=0x13 => Flow::Call(branch),
            _ => return None,
        },
        // J, JAL: the low 28 bits of the slot's region.
        2 | 3 => {
            let target = wrap((slot & !0x0fff_ffff) | u64::from(word & 0x03ff_ffff) << 2);
            if opcode == 2 {
                Flow::Jump(target)
            } else {
                Flow::Call(target)
            }
        }
        // BEQ $x, $x is `b`, always taken.
        4 if rs == rt => Flow::Jump(branch),
        // BEQ, BNE, BLEZ, BGTZ and their likely forms.
        4..=7 | 0x14..=0x17 => Flow::Branch(branch),
        // BC1F, BC1T and their likely forms.
        0x11 if rs == 8 => Flow::Branch(branch),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(words: &[u32], addr: u64) -> Insn {
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_be_bytes()).collect();
        decode(true, false, &bytes, addr)
    }

    #[test]
    fn transfers_take_their_slot() {
        // jal 0x400100; nop
        let call = one(&[0x0c10_0040, 0], 0x40_0000);
        assert_eq!((call.len, call.flow), (8, Flow::Call(0x40_0100)));
        // jr $ra; nop
        assert_eq!(one(&[0x03e0_0008, 0], 0x1000).flow, Flow::Return);
        // jr $t9
        assert_eq!(one(&[0x0320_0008, 0], 0x1000).flow, Flow::JumpRegister(25));
        // beq $a0, $zero, -4 words from the slot
        let back = one(&[0x1080_fffc, 0], 0x1010);
        assert_eq!(back.flow, Flow::Branch(0x1004));
        // b +2 words
        assert_eq!(one(&[0x1000_0002, 0], 0x1000).flow, Flow::Jump(0x100c));
        // bal
        assert_eq!(one(&[0x0411_0001, 0], 0x1000).flow, Flow::Call(0x1008));
        // jalr $t9
        assert_eq!(one(&[0x0320_f809, 0], 0x1000).flow, Flow::CallIndirect);
    }

    #[test]
    fn others_fall_through() {
        let nop = one(&[0], 0x1000);
        assert_eq!((nop.len, nop.flow, nop.pad), (4, Flow::Next, true));
        // addiu $sp, $sp, -32
        assert_eq!(one(&[0x27bd_ffe0], 0x1000).flow, Flow::Next);
        // break
        assert_eq!(one(&[0x0000_000d], 0x1000).flow, Flow::Stop);
        // A jump with no slot.
        assert_eq!(one(&[0x0800_0000], 0x1000).flow, Flow::Invalid);
    }

    #[test]
    fn little_endian_and_64_bit() {
        let bytes: Vec<u8> = [0x0c10_0040_u32, 0]
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect();
        let call = decode(false, true, &bytes, 0x1_2000_0000);
        assert_eq!(call.flow, Flow::Call(0x1_2040_0100));
    }
}
