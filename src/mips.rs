//! MIPS (32- and 64-bit, either byte order): control flow only. A branch,
//! jump, call or return and the instruction in its delay slot, which runs
//! before control moves, decode as one 8-byte instruction, so a call
//! returns past the slot and a block ends after it.
//!
//! Position-independent code calls through `$t9`, loaded from the GOT at an
//! offset from `_gp` (`lw $t9, n($gp); jalr $t9`): the decoder follows the
//! load, so the call reads as one through that GOT slot.

use crate::decode::{Flow, Insn};

/// `$zero`.
const ZERO: u32 = 0;
/// `$t9`, which a position-independent call goes through.
const T9: u32 = 25;
/// The stack and frame pointers, `$sp` and `$fp`.
const SP: u32 = 29;
const FP: u32 = 30;
/// The return-address register, `$ra`.
const RA: u32 = 31;

/// What earlier instructions left that a later one needs.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct State {
    /// The GOT slot `$t9` was loaded from.
    t9: Option<u64>,
}

/// The instruction at `addr`. `gp` is the address `_gp` stands for: GOT
/// slots are at offsets from it.
pub(crate) fn decode(
    state: &mut State,
    gp: Option<u64>,
    (big, wide): (bool, bool),
    bytes: &[u8],
    addr: u64,
) -> Insn {
    let Some(word) = read_word(big, bytes) else {
        return Insn::new(4, Flow::Invalid);
    };
    let Some(flow) = flow(word, addr, wide) else {
        track(state, word, gp, wide);
        let mut insn = Insn::new(4, Flow::Next);
        // `nop` (`sll $0, $0, 0`) and `ssnop`.
        insn.pad = word == 0 || word == 0x40;
        return insn;
    };
    // A trap has no slot.
    if flow == Flow::Stop {
        return Insn::new(4, flow);
    }
    let flow = match (flow, state.t9) {
        (Flow::CallIndirect, Some(slot)) if word >> 26 == 0 && (word >> 21) & 0x1f == T9 => {
            Flow::CallSlot(slot)
        }
        (Flow::JumpRegister(T9), Some(slot)) => Flow::JumpSlot(slot),
        _ => flow,
    };
    // A transfer with no slot after it is cut short: the slot is not code.
    let Some(slot) = bytes.get(4..8).and_then(|slot| read_word(big, slot)) else {
        return Insn::new(4, Flow::Invalid);
    };
    // A callee changes `$t9`.
    if matches!(flow, Flow::Call(_) | Flow::CallSlot(_) | Flow::CallIndirect) {
        state.t9 = None;
    } else {
        track(state, slot, gp, wide);
    }
    Insn::new(8, flow)
}

/// Follow what `word`, which transfers nowhere, does to `$t9`: a load from
/// a fixed offset off a register other than the stack's is a GOT load
/// (whichever register holds `_gp`); anything else that may write `$t9`
/// forgets it.
fn track(state: &mut State, word: u32, gp: Option<u64>, wide: bool) {
    let opcode = word >> 26;
    let (rs, rt, rd) = (
        (word >> 21) & 0x1f,
        (word >> 16) & 0x1f,
        (word >> 11) & 0x1f,
    );
    // LW, LD
    if matches!(opcode, 0x23 | 0x37) && rt == T9 {
        let offset = (i64::from(word & 0xffff) ^ 0x8000) - 0x8000;
        state.t9 = gp
            .filter(|_| !matches!(rs, ZERO | SP | FP))
            .map(|gp| gp.wrapping_add_signed(offset))
            .map(|slot| if wide { slot } else { slot & 0xffff_ffff });
        return;
    }
    let writes = match opcode {
        // SPECIAL, SPECIAL2
        0 | 0x1c => rd == T9,
        // SPECIAL3 writes either.
        0x1f => rd == T9 || rt == T9,
        // Stores, CACHE, PREF.
        0x28..=0x2f | 0x38..=0x3f => false,
        _ => rt == T9,
    };
    if writes {
        state.t9 = None;
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
        decode(&mut State::default(), None, (true, false), &bytes, addr)
    }

    /// Each instruction of `words` at `addr` on, in order, with `_gp` at
    /// `gp`.
    fn run(words: &[u32], addr: u64, gp: u64) -> Vec<Flow> {
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_be_bytes()).collect();
        let mut state = State::default();
        let mut flows = Vec::new();
        let mut at = 0;
        while at < bytes.len() {
            let insn = decode(
                &mut state,
                Some(gp),
                (true, false),
                &bytes[at..],
                addr + at as u64,
            );
            flows.push(insn.flow);
            at += insn.len as usize;
        }
        flows
    }

    #[test]
    fn calls_through_the_got() {
        // lw $t9, -0x7fd8($s0); jalr $t9; nop
        let flows = run(&[0x8e19_8028, 0x0320_f809, 0], 0x1000, 0x2_7ff0);
        assert_eq!(flows, [Flow::Next, Flow::CallSlot(0x2_0018)]);
        // lw $t9, -0x7fd8($gp); addiu $t9, $t9, 8; jalr $t9; nop
        let flows = run(
            &[0x8f99_8028, 0x2739_0008, 0x0320_f809, 0],
            0x1000,
            0x2_7ff0,
        );
        assert_eq!(flows[2], Flow::CallIndirect);
        // lw $t9, 16($sp): a spilled pointer, not a GOT slot.
        let flows = run(&[0x8fb9_0010, 0x0320_f809, 0], 0x1000, 0x2_7ff0);
        assert_eq!(flows[1], Flow::CallIndirect);
        // lw $t9, -0x7fd8($gp); jr $t9; nop: a tail call.
        let flows = run(&[0x8f99_8028, 0x0320_0008, 0], 0x1000, 0x2_7ff0);
        assert_eq!(flows[1], Flow::JumpSlot(0x2_0018));
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
        let call = decode(
            &mut State::default(),
            None,
            (false, true),
            &bytes,
            0x1_2000_0000,
        );
        assert_eq!(call.flow, Flow::Call(0x1_2040_0100));
    }
}
