//! Nios II (R1), little-endian: control flow, and the constants calls and
//! jumps through registers need. Instructions are 32 bits, without delay
//! slots.
//!
//! `call` and `jmpi` take a 26-bit word index within the 256 MiB region of
//! the instruction; branches a signed 16-bit byte offset from the next
//! instruction. `ret` is `jmp ra`, `callr` and `jmp` go through a register.
//! Constants are built with `movhi` (`orhi rB, zero, hi`) and `addi` or
//! `ori` for the low half; a PLT stub loads its GOT slot through one
//! (`movhi r15, %hiadj(slot); ldw r15, %lo(slot)(r15); jmp r15`). The
//! decoder keeps those constants, and forgets a register anything else
//! writes.

use crate::isa::{Flow, Insn, Mem, Note};

/// `ra`, where `call` leaves the return address.
const RA: u32 = 31;
/// The registers a call may change: `r1` to `r15` and `ra`.
const VOLATILE: u32 = 0x8000_fffe;

/// What earlier instructions left in each register: a constant, when known.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct State {
    regs: [Option<u32>; 32],
    /// The fixed address each register was last loaded from: a GOT slot,
    /// which a `jmp` or `callr` through the register goes through.
    slots: [Option<u32>; 32],
}

impl State {
    fn slot(&self, reg: u32) -> Option<u32> {
        self.slots.get(reg as usize).copied().flatten()
    }

    fn get(&self, reg: u32) -> Option<u32> {
        if reg == 0 {
            return Some(0);
        }
        self.regs.get(reg as usize).copied().flatten()
    }

    fn set(&mut self, reg: u32, value: Option<u32>) -> Note {
        if reg == 0 {
            return Note::None;
        }
        if let Some(slot) = self.regs.get_mut(reg as usize) {
            *slot = value;
        }
        if let Some(slot) = self.slots.get_mut(reg as usize) {
            *slot = None;
        }
        match value {
            Some(value) => Note::Address {
                reg,
                addr: u64::from(value),
            },
            None => Note::Write(reg),
        }
    }
}

fn read_word(bytes: &[u8]) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?))
}

pub(crate) fn decode(state: &mut State, bytes: &[u8], addr: u64) -> Insn {
    let Some(w) = read_word(bytes) else {
        return Insn::new(4, Flow::Invalid);
    };
    let op = w & 0x3f;
    let a = w >> 27;
    let b = (w >> 22) & 31;
    let imm = (w >> 6) & 0xffff;
    // The immediate sign-extended, as a 32-bit addend and as an offset.
    let simm32 = if imm & 0x8000 == 0 { imm } else { imm | 0xffff_0000 };
    let simm = i64::from(simm32.cast_signed());
    let next = addr.wrapping_add(4) & 0xffff_ffff;
    let relative = next.wrapping_add_signed(simm) & 0xffff_ffff;
    let absolute = (addr & 0xf000_0000) | u64::from(w >> 6) << 2;
    let mut note = Note::None;
    let flow = match op {
        // Zeros (`call 0`) are literal data, not code.
        _ if w == 0 => Flow::Invalid,
        0x00 => Flow::Call(absolute),
        0x01 => Flow::Jump(absolute),
        0x06 => Flow::Jump(relative),
        // bge, blt, bne, beq, bgeu, bltu
        0x0e | 0x16 | 0x1e | 0x26 | 0x2e | 0x36 => Flow::Branch(relative),
        0x3a => {
            let c = (w >> 17) & 31;
            match (w >> 11) & 0x3f {
                // ret
                0x05 => Flow::Return,
                // eret, bret
                0x01 | 0x09 => Flow::Return,
                // jmp rA
                0x0d if a == RA => Flow::Return,
                0x0d => match (state.get(a), state.slot(a)) {
                    (Some(to), _) => Flow::Jump(u64::from(to)),
                    (None, Some(slot)) => Flow::JumpSlot(u64::from(slot)),
                    (None, None) => Flow::JumpRegister(a),
                },
                // callr rA
                0x1d => match (state.get(a), state.slot(a)) {
                    (Some(to), _) => Flow::Call(u64::from(to)),
                    (None, Some(slot)) => Flow::CallSlot(u64::from(slot)),
                    (None, None) => Flow::CallRegister(a),
                },
                // break
                0x34 => Flow::Stop,
                // nextpc rC: the address of the next instruction.
                0x1c => {
                    let _ = state.set(c, u32::try_from(next).ok());
                    note = Note::Pc { reg: c, addr: next };
                    Flow::Next
                }
                // trap (a syscall), sync, wrctl, flushi, flushp, initi:
                // no register written.
                0x2d | 0x36 | 0x2e | 0x0c | 0x04 | 0x29 => Flow::Next,
                // add rC, rA, rB on constants.
                0x31 => {
                    let sum = state.get(a).zip(state.get(b)).map(|(x, y)| x.wrapping_add(y));
                    note = state.set(c, sum);
                    Flow::Next
                }
                // or rC, rA, rB: `mov` is `or rC, rA, zero`.
                0x16 => {
                    let or = state.get(a).zip(state.get(b)).map(|(x, y)| x | y);
                    note = state.set(c, or);
                    Flow::Next
                }
                _ => {
                    note = state.set(c, None);
                    Flow::Next
                }
            }
        }
        // addi
        0x04 => {
            let value = state.get(a).map(|v| v.wrapping_add(simm32));
            note = state.set(b, value);
            Flow::Next
        }
        // ori, orhi: `movhi` is `orhi rB, zero, imm`.
        0x14 | 0x34 => {
            let imm = if op == 0x34 { imm << 16 } else { imm };
            note = state.set(b, state.get(a).map(|v| v | imm));
            Flow::Next
        }
        // ldw, ldwio: a load from a known address is a slot.
        0x17 | 0x37 => match state.get(a) {
            Some(base) => {
                let _ = state.set(b, None);
                if let Some(slot) = state.slots.get_mut(b as usize).filter(|_| b != 0) {
                    *slot = Some(base.wrapping_add(simm32));
                }
                if b != 0 {
                    note = Note::Fetch {
                        reg: b,
                        mem: Mem {
                            base: None,
                            index: None,
                            scale: 1,
                            disp: u64::from(base.wrapping_add(simm32)),
                        },
                        size: 4,
                        signed: false,
                    };
                }
                Flow::Next
            }
            None => {
                note = state.set(b, None);
                Flow::Next
            }
        },
        // Stores, cache operations and the custom instruction: nothing a
        // jump table needs (a custom instruction may write rC, forgotten).
        0x05 | 0x0d | 0x15 | 0x25 | 0x2d | 0x35 | 0x13 | 0x1b | 0x33 | 0x3b => Flow::Next,
        0x32 => {
            note = state.set((w >> 17) & 31, None);
            Flow::Next
        }
        // Other loads, compares and immediate ALU operations write rB.
        0x03 | 0x07 | 0x0b | 0x0f | 0x23 | 0x27 | 0x2b | 0x2f | 0x08 | 0x10 | 0x18 | 0x20
        | 0x28 | 0x30 | 0x0c | 0x1c | 0x24 | 0x2c | 0x3c | 0x38 => {
            note = state.set(b, None);
            Flow::Next
        }
        // Opcodes R1 leaves unassigned.
        _ => Flow::Invalid,
    };
    let mut insn = Insn::new(4, flow);
    insn.note = note;
    // nop is `add zero, zero, zero`.
    insn.pad = w == 0x0001_883a;
    match flow {
        Flow::Next | Flow::Branch(_) => {}
        Flow::Call(_) | Flow::CallRegister(_) | Flow::CallSlot(_) | Flow::CallIndirect => {
            let both = state.regs.iter_mut().zip(state.slots.iter_mut());
            for (reg, (value, slot)) in both.enumerate() {
                if VOLATILE >> reg & 1 != 0 {
                    (*value, *slot) = (None, None);
                }
            }
        }
        _ => *state = State::default(),
    }
    insn
}

/// Whether `bytes` begin a frame: GCC's first instruction lowers the stack
/// pointer (`addi sp, sp, -n`).
pub(crate) fn starts_frame(bytes: &[u8]) -> bool {
    read_word(bytes).is_some_and(|w| w & 0xffc0_003f == 0xdec0_0004 && (w >> 21) & 1 == 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(words: &[u32], addr: u64) -> Vec<Insn> {
        let code: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        let mut state = State::default();
        (0..words.len())
            .map(|i| decode(&mut state, &code[i * 4..], addr + i as u64 * 4))
            .collect()
    }

    #[test]
    fn transfers() {
        // call 0x1000, jmpi 0x2000
        assert_eq!(run(&[0x1000 >> 2 << 6], 0x100)[0].flow, Flow::Call(0x1000));
        assert_eq!(run(&[0x2000 >> 2 << 6 | 1], 0x100)[0].flow, Flow::Jump(0x2000));
        // br -4: to itself; beq r2, r3, +8
        assert_eq!(run(&[0xfffc << 6 | 0x06], 0x100)[0].flow, Flow::Jump(0x100));
        let beq = 2 << 27 | 3 << 22 | 8 << 6 | 0x26;
        assert_eq!(run(&[beq], 0x100)[0].flow, Flow::Branch(0x10c));
        // ret
        assert_eq!(run(&[0xf800_283a], 0)[0].flow, Flow::Return);
        // callr r2, jmp r3
        assert_eq!(run(&[2 << 27 | 0x1d << 11 | 31 << 17 | 0x3a], 0)[0].flow, Flow::CallRegister(2));
        assert_eq!(run(&[3 << 27 | 0x0d << 11 | 0x3a], 0)[0].flow, Flow::JumpRegister(3));
        assert_eq!(run(&[0], 0)[0].flow, Flow::Invalid);
    }

    /// `movhi r15, 0x1; ldw r15, 0x20(r15); jmp r15`: a PLT stub.
    #[test]
    fn plt_stub() {
        let movhi = 15 << 22 | 1 << 6 | 0x34;
        let ldw = 15 << 27 | 15 << 22 | 0x20 << 6 | 0x17;
        let jmp = 15 << 27 | 0x0d << 11 | 0x3a;
        let insns = run(&[movhi, ldw, jmp], 0x1000);
        assert_eq!(insns[0].note, Note::Address { reg: 15, addr: 0x1_0000 });
        assert!(matches!(insns[1].note, Note::Fetch { reg: 15, mem: Mem { disp: 0x1_0020, .. }, .. }));
        assert_eq!(insns[2].flow, Flow::JumpSlot(0x1_0020));
    }

    /// `movhi r2, 0x2; addi r2, r2, 0x10; callr r2`: a call to a constant.
    #[test]
    fn call_through_a_constant() {
        let movhi = 2 << 22 | 2 << 6 | 0x34;
        let addi = 2 << 27 | 2 << 22 | 0x10 << 6 | 0x04;
        let callr = 2 << 27 | 31 << 17 | 0x1d << 11 | 0x3a;
        assert_eq!(run(&[movhi, addi, callr], 0)[2].flow, Flow::Call(0x2_0010));
    }
}
