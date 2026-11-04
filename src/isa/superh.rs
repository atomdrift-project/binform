//! SuperH (SH-2 to SH-4), little-endian: control flow only. Instructions
//! are 16 bits. A delayed transfer (`bra`, `bsr`, `jmp`, `jsr`, `rts`,
//! `bt/s`, `bf/s`, `braf`, `bsrf`) and its slot decode as one 4-byte
//! instruction; `bt` and `bf` have no slot. Displacements count halfwords
//! from the instruction's address plus 4.
//!
//! Calls go through registers: GCC loads a callee's address from a literal
//! pool after the function (`mov.l @(disp, pc), r1; jsr @r1`), or in
//! position-independent code an offset from the call (`mov.l @(disp, pc),
//! r1; bsrf r1`). The decoder keeps the constants such loads leave in each
//! register, and forgets a register any other instruction may write.

use crate::isa::{Decode, Flow, Insn, Note, Regs, relative, sext, u16_at, u32_at};

/// The SuperH decoder: what earlier instructions left in each register, a
/// constant when known.
#[derive(Clone, Debug, Default)]
pub(crate) struct Decoder {
    regs: Regs<u32, 16>,
}

/// `nop`.
const NOP: u16 = 0x0009;

/// The registers a call may change: `r0`-`r7`.
const VOLATILE: u64 = 0xff;

/// The low 32 bits of `value`.
fn low32(value: i64) -> u32 {
    u32::try_from(value.cast_unsigned() & 0xffff_ffff).unwrap_or(0)
}

/// The halfword at `bytes[at..]`.
fn half(bytes: &[u8], at: usize) -> Option<u16> {
    u16_at(bytes, at, false)
}

impl Decode for Decoder {
    fn decode(&mut self, bytes: &[u8], addr: u64) -> Insn {
        let Some(word) = half(bytes, 0) else {
            return Insn::new(2, Flow::Invalid);
        };
        let (flow, delayed) = transfer(word, addr);
        // A transfer through a register holding a constant.
        let held = self.regs.get(u32::from((word >> 8) & 0xf)).map(u64::from);
        let after = |offset: u64| addr.wrapping_add(4).wrapping_add(offset) & 0xffff_ffff;
        let flow = match (flow, held, word & 0xf0ff) {
            (Flow::CallIndirect, Some(to), 0x400b) => Flow::Call(to),
            (Flow::JumpRegister(_), Some(to), _) => Flow::Jump(to),
            (Flow::CallIndirect, Some(offset), 0x0003) => Flow::Call(after(offset)),
            (Flow::JumpIndirect, Some(offset), 0x0023) => Flow::Jump(after(offset)),
            (flow, ..) => flow,
        };
        if !delayed {
            return Insn {
                note: self.track(word, bytes, addr),
                pad: word == NOP,
                ..Insn::new(2, flow)
            };
        }
        let slot = half(bytes, 2);
        // A jump whose slot sets the return address (`mova 1f, r0; braf r1;
        // lds r0, pr`, as uClibc's `.init` and `.fini` call): a call, which
        // returns past the literal after it.
        let mut back = None;
        let flow = match (flow, slot) {
            (Flow::Jump(_) | Flow::JumpRegister(_) | Flow::JumpIndirect, Some(slot))
                if slot & 0xf0ff == 0x402a =>
            {
                back = self
                    .regs
                    .get(u32::from((slot >> 8) & 0xf))
                    .map(u64::from)
                    .filter(|&back| {
                        back > addr.wrapping_add(4)
                            && back <= addr.wrapping_add(64)
                            && back & 1 == 0
                    });
                match flow {
                    Flow::Jump(to) => Flow::Call(to),
                    _ => Flow::CallIndirect,
                }
            }
            (flow, _) => flow,
        };
        let at = addr.wrapping_add(2);
        let slot = slot.map(|slot| match transfer(slot, at) {
            (Flow::Next, _) => {
                Insn::note(2, self.track(slot, bytes.get(2..).unwrap_or_default(), at))
            }
            _ => Insn::new(2, Flow::Invalid),
        });
        let mut insn = Insn::new(2, flow).with_slot(slot);
        if let Some(back) = back.filter(|_| insn.flow != Flow::Invalid) {
            insn.len = u32::try_from(back.wrapping_sub(addr)).unwrap_or(4);
        }
        insn
    }

    fn reset(&mut self) {
        self.regs = Regs::default();
    }

    fn call(&mut self) {
        self.regs.forget(VOLATILE);
    }

    /// Whether `bytes` begin a GCC frame: saved registers (`mov.l rN,
    /// @-r15`), the return address (`sts.l pr, @-r15`) or the frame pointer
    /// (`mov.l r14, @-r15`) among them, before anything else.
    fn starts_frame(&self, bytes: &[u8]) -> bool {
        let push = |word: u16| word & 0xff0f == 0x2f06;
        let lower = |word: u16| word & 0xff00 == 0x7f00 && word & 0x80 != 0;
        // The first instruction saves a register or lowers the stack; GCC
        // then interleaves the rest of the setup (`mova`, literal loads) with
        // the saves, so the saves that make it a frame may come a few later.
        match half(bytes, 0) {
            Some(word) if push(word) || lower(word) || word == 0x4f22 => {}
            _ => return false,
        }
        let mut saved = 0_u32;
        for at in (0..16).step_by(2) {
            match half(bytes, at) {
                // STS.L PR, @-R15; MOV.L R14, @-R15
                Some(0x4f22 | 0x2fe6) => return true,
                // Other saved registers
                Some(word) if push(word) => saved = saved.saturating_add(1),
                Some(_) => {}
                None => break,
            }
        }
        // A leaf saves two registers or more.
        saved >= 2
    }
}

/// Where control goes after `word` at `addr`, and whether it has a delay
/// slot.
fn transfer(word: u16, addr: u64) -> (Flow, bool) {
    let n = u32::from((word >> 8) & 0xf);
    let target = |bits: u32| relative(addr.wrapping_add(4), word, bits, 2) & 0xffff_ffff;
    match word {
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
    }
}

impl Decoder {
    /// What `word`, at `addr` (the start of `bytes`), leaves in the
    /// registers; a 32-bit literal it loads, as a note: a callback's
    /// address, when it points at code.
    fn track(&mut self, word: u16, bytes: &[u8], addr: u64) -> Note {
        let n = u32::from((word >> 8) & 0xf);
        let m = u32::from((word >> 4) & 0xf);
        let disp = u64::from(word & 0xff);
        let imm = sext(word & 0xff, 8);
        // The literal `size` bytes long at `at`, within `bytes`.
        let literal = |at: u64, size: usize| -> Option<u32> {
            let offset = usize::try_from(at.checked_sub(addr)?).ok()?;
            match size {
                2 => Some(u32::from(u16_at(bytes, offset, false)?)),
                _ => u32_at(bytes, offset, false),
            }
        };
        // The word-aligned literal `disp` words past the PC.
        let pool = (addr & !3)
            .wrapping_add(4)
            .wrapping_add(disp.wrapping_mul(4));
        let value = match word >> 12 {
            // MOV.L @(disp, PC), Rn
            0xd => Some(literal(pool, 4)),
            // MOV.W @(disp, PC), Rn, sign-extended
            0x9 => Some(
                literal(addr.wrapping_add(4).wrapping_add(disp.wrapping_mul(2)), 2)
                    .map(|half| low32(sext(half, 16))),
            ),
            // MOV #imm, Rn
            0xe => Some(Some(low32(imm))),
            // MOV Rm, Rn
            0x6 if word & 0xf == 3 => Some(self.regs.get(m)),
            // MOVA @(disp, PC), R0
            0xc if word & 0x0f00 == 0x0700 => {
                self.regs.set(0, u32::try_from(pool).ok());
                return Note::None;
            }
            // ADD #imm, Rn
            0x7 => Some(self.regs.get(n).map(|value| value.wrapping_add(low32(imm)))),
            _ => None,
        };
        if let Some(value) = value {
            self.regs.set(n, value);
            return match (word >> 12, value) {
                (0xd, Some(literal)) => Note::Address {
                    reg: n,
                    addr: u64::from(literal),
                },
                _ => Note::None,
            };
        }
        // In the 0x8 and 0xc groups the fields are immediates, and only R0
        // is written. Anything else may write Rn and Rm (post-increment and
        // pre-decrement addressing included), and the 0x0 group R0 too.
        if !matches!(word >> 12, 0x8 | 0xc) {
            self.regs.set(n, None);
            self.regs.set(m, None);
        }
        if matches!(word >> 12, 0x0 | 0x8 | 0xc) {
            self.regs.set(0, None);
        }
        Note::None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(halves: &[u16], addr: u64) -> Insn {
        let bytes: Vec<u8> = halves.iter().flat_map(|h| h.to_le_bytes()).collect();
        Decoder::default().decode(&bytes, addr)
    }

    /// The flows of `halves` at `addr` on, in order.
    fn run(halves: &[u16], addr: u64) -> Vec<Flow> {
        let bytes: Vec<u8> = halves.iter().flat_map(|h| h.to_le_bytes()).collect();
        let mut decoder = Decoder::default();
        let mut flows = Vec::new();
        let mut at = 0;
        while at < bytes.len() {
            let insn = decoder.decode(&bytes[at..], addr + at as u64);
            flows.push(insn.flow);
            at += insn.len as usize;
        }
        flows
    }

    #[test]
    fn calls_through_literals() {
        // 0x1000: mov.l @(8, pc), r1 (the literal at 0x100c); jsr @r1; nop;
        // rts; nop; the literal 0x2000.
        let flows = run(&[0xd102, 0x410b, NOP, 0x000b, NOP, NOP, 0x2000, 0], 0x1000);
        assert_eq!(flows[1], Flow::Call(0x2000));
        // mov.l @(4, pc), r1; add #1, r2; jsr @r1: r1 kept.
        let flows = run(&[0xd101, 0x7201, 0x410b, NOP, 0x2000, 0], 0x1000);
        assert_eq!(flows[2], Flow::Call(0x2000));
        // mov.l @(4, pc), r1; mov.l @r1+, r2 (r1 written); jsr @r1.
        let flows = run(&[0xd101, 0x6216, 0x410b, NOP, 0x2000, 0], 0x1000);
        assert_eq!(flows[2], Flow::CallIndirect);
        // mov.l @(4, pc), r1 = 0x100; bsrf r1: to 0x1002 + 4 + 0x100.
        let flows = run(&[0xd101, 0x0103, NOP, NOP, 0x0100, 0], 0x1000);
        assert_eq!(flows[1], Flow::Call(0x1106));
        // 0x1000: mov.l @(4, pc), r1 = 0x100; mova @(8, pc), r0 (0x100c);
        // braf r1; lds r0, pr; the literal; then the return at 0x100c.
        let bytes: Vec<u8> = [0xd101_u16, 0xc702, 0x0123, 0x402a, 0x0100, 0, 0x000b, NOP]
            .iter()
            .flat_map(|h| h.to_le_bytes())
            .collect();
        let mut decoder = Decoder::default();
        let first = decoder.decode(&bytes, 0x1000);
        let second = decoder.decode(&bytes[2..], 0x1002);
        let call = decoder.decode(&bytes[4..], 0x1004);
        assert_eq!((first.len, second.len), (2, 2));
        assert_eq!((call.flow, call.len), (Flow::Call(0x1108), 8));
    }

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
    fn frames() {
        let bytes =
            |halves: &[u16]| -> Vec<u8> { halves.iter().flat_map(|h| h.to_le_bytes()).collect() };
        let starts = |bytes: &[u8]| Decoder::default().starts_frame(bytes);
        // mov.l r8, @-r15; sts.l pr, @-r15
        assert!(starts(&bytes(&[0x2f86, 0x4f22])));
        // mov.l r14, @-r15
        assert!(starts(&bytes(&[0x2fe6, 0x6ef3])));
        // mov r4, r1: no frame
        assert!(!starts(&bytes(&[0x6143, 0x4f22])));
        // mov.l r8, @-r15; mova; mov.l r9, @-r15: GCC interleaves setup.
        assert!(starts(&bytes(&[0x2f86, 0xc71e, 0x2f96])));
        // One save and nothing more is no frame.
        assert!(!starts(&bytes(&[0x2f86, 0xc71e, 0x6143])));
    }

    #[test]
    fn others() {
        assert!(one(&[NOP], 0).pad);
        // mov.l r14, @-r15
        assert_eq!(one(&[0x2fe6], 0).flow, Flow::Next);
        assert_eq!(one(&[0], 0).flow, Flow::Invalid);
        assert_eq!(one(&[0x000b], 0).flow, Flow::Invalid);
    }

    #[test]
    fn delay_slots() {
        // bsr; mov.l @(0, pc), r2: the slot's literal load is the call's
        // note. The literal is at (0x1002 & !3) + 4.
        let call = one(&[0xb010, 0xd200, 0x5678, 0x1234], 0x1000);
        assert_eq!(call.flow, Flow::Call(0x1024));
        assert_eq!(
            call.note,
            Note::Address {
                reg: 2,
                addr: 0x1234_5678
            }
        );
        // A transfer in the slot, or none that decodes: no instruction.
        assert_eq!(one(&[0xb010, 0xa000], 0x1000).flow, Flow::Invalid);
        assert_eq!(one(&[0x000b, 0x8902], 0x1000).flow, Flow::Invalid);
        assert_eq!(one(&[0x000b, 0], 0x1000).flow, Flow::Invalid);
        // A call forgets r0-r7 and keeps r8 on.
        let mut decoder = Decoder::default();
        decoder.regs.set(1, Some(1));
        decoder.regs.set(8, Some(8));
        decoder.call();
        assert_eq!((decoder.regs.get(1), decoder.regs.get(8)), (None, Some(8)));
    }

    #[test]
    fn addresses_wrap() {
        // mov.l @(4, pc), r1; mova @(8, pc), r0; braf r1; lds r0, pr, at
        // the top of the address space: no overflow.
        let halves = [0xd101_u16, 0xc702, 0x0123, 0x402a, 0x0100, 0, 0x000b, NOP];
        let bytes: Vec<u8> = halves.iter().flat_map(|h| h.to_le_bytes()).collect();
        for addr in [u64::MAX - 7, u64::MAX - 1] {
            let mut decoder = Decoder::default();
            let mut at = 0;
            while let Some(rest) = bytes.get(at..).filter(|rest| !rest.is_empty()) {
                let insn = decoder.decode(rest, addr.wrapping_add(at as u64));
                assert!(insn.len > 0);
                at += insn.len as usize;
            }
        }
        // mov #-1, r3; add #2, r3; jmp @r3: to 1.
        assert_eq!(
            run(&[0xe3ff, 0x7302, 0x432b, NOP], 0x1000)[2],
            Flow::Jump(1)
        );
    }
}
