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

use crate::isa::{Flow, Insn, Mem, Note, Regs, sext, u32_at};

/// `ra`, where `call` leaves the return address.
const RA: u32 = 31;
/// The registers a call may change: `r1` to `r15` and `ra`.
const VOLATILE: u64 = 0x8000_fffe;
/// Registers and addresses are 32 bits.
const MASK: u64 = 0xffff_ffff;

/// The Nios II decoder: what earlier instructions left in each register.
#[derive(Clone, Debug, Default)]
pub(crate) struct Decoder {
    /// A constant, and whether it is an address (an immediate added to a
    /// register's constant, as `addi` completes a `movhi` pair) rather
    /// than a bare integer.
    regs: Regs<(u64, bool), 32>,
    /// The fixed address each register was last loaded from: a GOT slot,
    /// which a `jmp` or `callr` through the register goes through.
    slots: Regs<u64, 32>,
}

impl Decoder {
    fn get(&self, reg: u32) -> Option<(u64, bool)> {
        if reg == 0 {
            return Some((0, false));
        }
        self.regs.get(reg)
    }

    /// Record what `reg` now holds, forgetting the slot it was loaded
    /// from.
    fn set(&mut self, reg: u32, value: Option<(u64, bool)>) -> Note {
        if reg == 0 {
            return Note::None;
        }
        let value = value.map(|(value, address)| (value & MASK, address));
        self.regs.set(reg, value);
        self.slots.set(reg, None);
        match value {
            Some((addr, true)) => Note::Address { reg, addr },
            Some((value, false)) => Note::Value { reg, value },
            None => Note::Write(reg),
        }
    }

    /// `rB = op(rA)` with an immediate: an address when it completes a
    /// constant in a register, a bare integer when `rA` is `zero` (`movi`,
    /// `movhi`).
    fn immediate(&mut self, b: u32, a: u32, op: impl Fn(u64) -> u64) -> Note {
        let value = self.get(a).map(|(v, _)| (op(v), a != 0));
        self.set(b, value)
    }

    /// Where a `jmp` (or, when `call`, a `callr`) through `reg` goes.
    fn through(&self, reg: u32, call: bool) -> Flow {
        match (self.get(reg), self.slots.get(reg), call) {
            (Some((to, _)), _, false) => Flow::Jump(to),
            (Some((to, _)), _, true) => Flow::Call(to),
            (None, Some(slot), false) => Flow::JumpSlot(slot),
            (None, Some(slot), true) => Flow::CallSlot(slot),
            (None, None, false) => Flow::JumpRegister(reg),
            (None, None, true) => Flow::CallRegister(reg),
        }
    }

    /// The R-type instruction `w` (opcode 0x3a), its operation in `opx`.
    fn r_type(&mut self, w: u32, a: u32, b: u32, next: u64) -> (Flow, Note) {
        let c = (w >> 17) & 31;
        let note = match (w >> 11) & 0x3f {
            // ret, eret, bret
            0x05 | 0x01 | 0x09 => return (Flow::Return, Note::None),
            // jmp rA
            0x0d if a == RA => return (Flow::Return, Note::None),
            0x0d => return (self.through(a, false), Note::None),
            // callr rA
            0x1d => return (self.through(a, true), Note::None),
            // break
            0x34 => return (Flow::Stop, Note::None),
            // nextpc rC: the address of the next instruction, the PC read.
            0x1c => self.set(c, Some((next, false))),
            // trap (a syscall), sync, wrctl, flushi, flushp, initi: no
            // register written.
            0x2d | 0x36 | 0x2e | 0x0c | 0x04 | 0x29 => Note::None,
            // add rC, rA, rB on constants.
            0x31 => {
                let sum = self.get(a).zip(self.get(b));
                let sum = sum.map(|((x, p), (y, q))| (x.wrapping_add(y), p || q));
                self.set(c, sum)
            }
            // or rC, rA, rB: `mov` is `or rC, rA, zero`.
            0x16 => {
                let or = self.get(a).zip(self.get(b));
                let or = or.map(|((x, p), (y, q))| (x | y, p || q));
                self.set(c, or)
            }
            _ => self.set(c, None),
        };
        (Flow::Next, note)
    }

    /// `ldw rB, imm(rA)`: from a known address, a load of a slot.
    fn load_word(&mut self, a: u32, b: u32, simm: i64) -> Note {
        let Some((base, _)) = self.get(a).filter(|_| b != 0) else {
            return self.set(b, None);
        };
        let slot = base.wrapping_add_signed(simm) & MASK;
        let _ = self.set(b, None);
        self.slots.set(b, Some(slot));
        Note::Fetch {
            reg: b,
            mem: Mem {
                base: None,
                index: None,
                scale: 1,
                disp: slot,
            },
            size: 4,
            signed: false,
        }
    }
}

impl crate::isa::Decode for Decoder {
    fn decode(&mut self, bytes: &[u8], addr: u64) -> Insn {
        let Some(w) = u32_at(bytes, 0, false) else {
            return Insn::new(4, Flow::Invalid);
        };
        let op = w & 0x3f;
        let a = w >> 27;
        let b = (w >> 22) & 31;
        let imm = (w >> 6) & 0xffff;
        let simm = sext(imm, 16);
        let next = addr.wrapping_add(4) & MASK;
        let relative = next.wrapping_add_signed(simm) & MASK;
        let absolute = (addr & 0xf000_0000) | u64::from(w >> 6) << 2;
        let (flow, note) = match op {
            // Zeros (`call 0`) are literal data, not code.
            _ if w == 0 => (Flow::Invalid, Note::None),
            0x00 => (Flow::Call(absolute), Note::None),
            0x01 => (Flow::Jump(absolute), Note::None),
            0x06 => (Flow::Jump(relative), Note::None),
            // bge, blt, bne, beq, bgeu, bltu
            0x0e | 0x16 | 0x1e | 0x26 | 0x2e | 0x36 => (Flow::Branch(relative), Note::None),
            0x3a => self.r_type(w, a, b, next),
            // addi
            0x04 => (
                Flow::Next,
                self.immediate(b, a, |v| v.wrapping_add_signed(simm)),
            ),
            // ori, orhi: `movhi` is `orhi rB, zero, imm`.
            0x14 => (Flow::Next, self.immediate(b, a, |v| v | u64::from(imm))),
            0x34 => (
                Flow::Next,
                self.immediate(b, a, |v| v | u64::from(imm) << 16),
            ),
            // ldw, ldwio
            0x17 | 0x37 => (Flow::Next, self.load_word(a, b, simm)),
            // Stores, cache operations and the custom instruction: nothing a
            // jump table needs (a custom instruction may write rC, forgotten).
            0x05 | 0x0d | 0x15 | 0x25 | 0x2d | 0x35 | 0x13 | 0x1b | 0x33 | 0x3b => {
                (Flow::Next, Note::None)
            }
            0x32 => (Flow::Next, self.set((w >> 17) & 31, None)),
            // Other loads, compares and immediate ALU operations write rB.
            0x03 | 0x07 | 0x0b | 0x0f | 0x23 | 0x27 | 0x2b | 0x2f | 0x08 | 0x10 | 0x18 | 0x20
            | 0x28 | 0x30 | 0x0c | 0x1c | 0x24 | 0x2c | 0x3c | 0x38 => {
                (Flow::Next, self.set(b, None))
            }
            // Opcodes R1 leaves unassigned.
            _ => (Flow::Invalid, Note::None),
        };
        Insn {
            note,
            // nop is `add zero, zero, zero`.
            pad: w == 0x0001_883a,
            ..Insn::new(4, flow)
        }
    }

    fn reset(&mut self) {
        *self = Self::default();
    }

    fn call(&mut self) {
        self.regs.forget(VOLATILE);
        self.slots.forget(VOLATILE);
    }

    /// GCC's first instruction lowers the stack pointer (`addi sp, sp,
    /// -n`).
    fn starts_frame(&self, bytes: &[u8]) -> bool {
        u32_at(bytes, 0, false)
            .is_some_and(|w| w & 0xffc0_003f == 0xdec0_0004 && (w >> 21) & 1 == 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isa::Decode;

    fn run(words: &[u32], addr: u64) -> Vec<Insn> {
        let code: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        let mut decoder = Decoder::default();
        (0..words.len())
            .map(|i| decoder.decode(&code[i * 4..], addr + i as u64 * 4))
            .collect()
    }

    #[test]
    fn transfers() {
        // call 0x1000, jmpi 0x2000
        assert_eq!(run(&[0x1000 >> 2 << 6], 0x100)[0].flow, Flow::Call(0x1000));
        assert_eq!(
            run(&[0x2000 >> 2 << 6 | 1], 0x100)[0].flow,
            Flow::Jump(0x2000)
        );
        // br -4: to itself; beq r2, r3, +8
        assert_eq!(run(&[0xfffc << 6 | 0x06], 0x100)[0].flow, Flow::Jump(0x100));
        let beq = 2 << 27 | 3 << 22 | 8 << 6 | 0x26;
        assert_eq!(run(&[beq], 0x100)[0].flow, Flow::Branch(0x10c));
        // ret
        assert_eq!(run(&[0xf800_283a], 0)[0].flow, Flow::Return);
        // callr r2, jmp r3
        assert_eq!(
            run(&[2 << 27 | 0x1d << 11 | 31 << 17 | 0x3a], 0)[0].flow,
            Flow::CallRegister(2)
        );
        assert_eq!(
            run(&[3 << 27 | 0x0d << 11 | 0x3a], 0)[0].flow,
            Flow::JumpRegister(3)
        );
        assert_eq!(run(&[0], 0)[0].flow, Flow::Invalid);
    }

    /// `movhi r15, 0x1; ldw r15, 0x20(r15); jmp r15`: a PLT stub.
    #[test]
    fn plt_stub() {
        let movhi = 15 << 22 | 1 << 6 | 0x34;
        let ldw = 15 << 27 | 15 << 22 | 0x20 << 6 | 0x17;
        let jmp = 15 << 27 | 0x0d << 11 | 0x3a;
        let insns = run(&[movhi, ldw, jmp], 0x1000);
        // The high half alone is no address.
        assert_eq!(
            insns[0].note,
            Note::Value {
                reg: 15,
                value: 0x1_0000
            }
        );
        assert!(matches!(
            insns[1].note,
            Note::Fetch {
                reg: 15,
                mem: Mem { disp: 0x1_0020, .. },
                ..
            }
        ));
        assert_eq!(insns[2].flow, Flow::JumpSlot(0x1_0020));
    }

    /// `movhi r2, 0x2; addi r2, r2, 0x10; callr r2`: a call to a constant.
    #[test]
    fn call_through_a_constant() {
        let movhi = 2 << 22 | 2 << 6 | 0x34;
        let addi = 2 << 27 | 2 << 22 | 0x10 << 6 | 0x04;
        let callr = 2 << 27 | 31 << 17 | 0x1d << 11 | 0x3a;
        let insns = run(&[movhi, addi, callr], 0);
        assert_eq!(
            insns[1].note,
            Note::Address {
                reg: 2,
                addr: 0x2_0010
            }
        );
        assert_eq!(insns[2].flow, Flow::Call(0x2_0010));
        // `movi r2, 5` (`addi r2, zero, 5`): an integer.
        let movi = 2 << 22 | 5 << 6 | 0x04;
        assert_eq!(run(&[movi], 0)[0].note, Note::Value { reg: 2, value: 5 });
    }

    /// `nextpc r3`: the PC it reads, which a call through the register
    /// then reaches.
    #[test]
    fn nextpc_reads_the_pc() {
        let nextpc = 3 << 17 | 0x1c << 11 | 0x3a;
        let jmp = 3 << 27 | 0x0d << 11 | 0x3a;
        let insns = run(&[nextpc, jmp], 0x1000);
        assert_eq!(
            insns[0].note,
            Note::Value {
                reg: 3,
                value: 0x1004
            }
        );
        assert_eq!(insns[1].flow, Flow::Jump(0x1004));
    }

    #[test]
    fn unassigned_opcodes_are_no_code() {
        // Opcode 0x02 is unassigned in R1; so is 0x09.
        assert_eq!(run(&[1 << 6 | 0x02], 0)[0].flow, Flow::Invalid);
        assert_eq!(run(&[1 << 6 | 0x09], 0)[0].flow, Flow::Invalid);
        // Too short for a word.
        assert_eq!(
            Decoder::default().decode(&[0x3a, 0x88], 0),
            Insn::new(4, Flow::Invalid)
        );
    }

    /// A call forgets the registers it may change, and keeps the rest.
    #[test]
    fn calls_forget_volatile_registers() {
        let mut decoder = Decoder::default();
        decoder.set(2, Some((0x10, true)));
        decoder.set(16, Some((0x20, true)));
        decoder.call();
        assert_eq!(
            (decoder.get(2), decoder.get(16)),
            (None, Some((0x20, true)))
        );
    }
}
