//! eBPF, little-endian: control flow only. Instructions are 8 bytes (an
//! opcode, a register byte, a 16-bit offset and a 32-bit immediate), except
//! `lddw`, whose 64-bit immediate takes a second 8-byte slot. Jumps count
//! instructions from the one after them.
//!
//! A `call` whose source register is 1 (`BPF_PSEUDO_CALL`) calls a
//! subprogram in the same object, at `imm` instructions on; any other
//! calls a kernel helper or kfunc by number, which is no code in the file.

use crate::isa::{Flow, Insn};

/// The 64-bit immediate load, two slots long.
const LDDW: u8 = 0x18;
const CLASS_JMP: u8 = 0x05;
const CLASS_JMP32: u8 = 0x06;
const PSEUDO_CALL: u8 = 1;

pub(crate) fn decode(bytes: &[u8], addr: u64) -> Insn {
    let Some(&[op, regs, o0, o1, i0, i1, i2, i3]) = bytes.get(..8) else {
        return Insn::new(8, Flow::Invalid);
    };
    let off = i64::from(i16::from_le_bytes([o0, o1]));
    let imm = i64::from(i32::from_le_bytes([i0, i1, i2, i3]));
    let next = addr.wrapping_add(8);
    let to = |count: i64| next.wrapping_add_signed(count.wrapping_mul(8));
    // Registers are r0 to r10.
    if regs & 0xf > 10 || regs >> 4 > 10 {
        return Insn::new(8, Flow::Invalid);
    }
    let flow = match (op & 7, op >> 4) {
        _ if op == 0 => Flow::Invalid,
        _ if op == LDDW => {
            // The second slot carries only the immediate's high half.
            return match bytes.get(8..12) {
                Some([0, 0, 0, 0]) => Insn::new(16, Flow::Next),
                _ => Insn::new(8, Flow::Invalid),
            };
        }
        // ja; gotol (a 32-bit offset in the immediate).
        (CLASS_JMP, 0x0) => Flow::Jump(to(off)),
        (CLASS_JMP32, 0x0) => Flow::Jump(to(imm)),
        (CLASS_JMP, 0x8) if regs >> 4 == PSEUDO_CALL => Flow::Call(to(imm)),
        (CLASS_JMP, 0x8) => Flow::CallIndirect,
        (CLASS_JMP, 0x9) => Flow::Return,
        (CLASS_JMP | CLASS_JMP32, 0x1..=0x7 | 0xa..=0xd) => Flow::Branch(to(off)),
        (CLASS_JMP | CLASS_JMP32, _) => Flow::Invalid,
        _ => Flow::Next,
    };
    Insn::new(8, flow)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(bytes: &[u8], addr: u64) -> Flow {
        decode(bytes, addr).flow
    }

    #[test]
    fn transfers() {
        // r0 = 0; exit
        assert_eq!(at(&[0xb7, 0, 0, 0, 0, 0, 0, 0], 0), Flow::Next);
        assert_eq!(at(&[0x95, 0, 0, 0, 0, 0, 0, 0], 0), Flow::Return);
        // if r1 == 0 goto +2
        assert_eq!(at(&[0x15, 1, 2, 0, 0, 0, 0, 0], 0x10), Flow::Branch(0x28));
        // goto -1: to itself.
        assert_eq!(at(&[0x05, 0, 0xff, 0xff, 0, 0, 0, 0], 0x10), Flow::Jump(0x10));
        // call a subprogram 3 instructions on; call helper 1.
        assert_eq!(at(&[0x85, 0x10, 0, 0, 3, 0, 0, 0], 0x10), Flow::Call(0x30));
        assert_eq!(at(&[0x85, 0, 0, 0, 1, 0, 0, 0], 0), Flow::CallIndirect);
    }

    #[test]
    fn lddw_takes_two_slots() {
        let code = [0x18, 0x11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(decode(&code, 0).len, 16);
        assert_eq!(decode(&code[..8], 0).flow, Flow::Invalid);
    }

    #[test]
    fn zeros_and_bad_registers_are_no_code() {
        assert_eq!(at(&[0; 8], 0), Flow::Invalid);
        assert_eq!(at(&[0xb7, 0x0b, 0, 0, 0, 0, 0, 0], 0), Flow::Invalid);
    }
}
