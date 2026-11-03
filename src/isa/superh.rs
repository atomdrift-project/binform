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

use crate::isa::{Flow, Insn, Note};

/// What earlier instructions left in each register: a constant, when known.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct State {
    regs: [Option<u32>; 16],
}

impl State {
    fn get(&self, reg: usize) -> Option<u32> {
        self.regs.get(reg).copied().flatten()
    }

    fn set(&mut self, reg: usize, value: Option<u32>) {
        if let Some(slot) = self.regs.get_mut(reg) {
            *slot = value;
        }
    }
}

pub(crate) fn decode(state: &mut State, bytes: &[u8], addr: u64) -> Insn {
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
    // A transfer through a register holding a constant.
    let held = state.regs.get(n as usize).copied().flatten().map(u64::from);
    let relative = |offset: u64| addr.wrapping_add(4).wrapping_add(offset) & 0xffff_ffff;
    let flow = match (flow, held, word & 0xf0ff) {
        (Flow::CallIndirect, Some(to), 0x400b) => Flow::Call(to),
        (Flow::JumpRegister(_), Some(to), _) => Flow::Jump(to),
        (Flow::CallIndirect, Some(offset), 0x0003) => Flow::Call(relative(offset)),
        (Flow::JumpIndirect, Some(offset), 0x0023) => Flow::Jump(relative(offset)),
        (flow, ..) => flow,
    };
    if !delayed {
        let note = track(state, word, bytes, addr);
        let mut insn = Insn::new(2, flow);
        insn.pad = word == 0x0009;
        insn.note = note;
        return insn;
    }
    // A transfer with no slot after it is cut short: the slot is not code.
    let Some(slot) = bytes.get(2..).and_then(half) else {
        return Insn::new(2, Flow::Invalid);
    };
    // A jump whose slot sets the return address (`mova 1f, r0; braf r1;
    // lds r0, pr`, as uClibc's `.init` and `.fini` call): a call, which
    // returns past the literal after it.
    let mut len = 4;
    let flow = match flow {
        Flow::Jump(_) | Flow::JumpRegister(_) | Flow::JumpIndirect if slot & 0xf0ff == 0x402a => {
            let back = state.get(usize::from((slot >> 8) & 0xf)).map(u64::from);
            if let Some(back) =
                back.filter(|&back| back > addr + 4 && back <= addr + 64 && back & 1 == 0)
            {
                len = u32::try_from(back - addr).unwrap_or(4);
            }
            match flow {
                Flow::Jump(to) => Flow::Call(to),
                _ => Flow::CallIndirect,
            }
        }
        flow => flow,
    };
    let note = track(
        state,
        slot,
        bytes.get(2..).unwrap_or_default(),
        addr.wrapping_add(2),
    );
    match flow {
        // A callee changes r0-r7.
        Flow::Call(_) | Flow::CallIndirect => {
            for reg in &mut state.regs[..8] {
                *reg = None;
            }
        }
        // Past a transfer that does not fall through, code is reached from
        // elsewhere.
        Flow::Branch(_) => {}
        _ => *state = State::default(),
    }
    let mut insn = Insn::new(len, flow);
    insn.note = note;
    insn
}

/// What `word`, at `addr` (the start of `bytes`), leaves in the registers;
/// a 32-bit literal it loads, as a note: a callback's address, when it
/// points at code.
fn track(state: &mut State, word: u16, bytes: &[u8], addr: u64) -> Note {
    let n = usize::from((word >> 8) & 0xf);
    let m = usize::from((word >> 4) & 0xf);
    let disp = u64::from(word & 0xff);
    // The literal `size` bytes long at `at`, within `bytes`.
    let literal = |at: u64, size: usize| -> Option<u32> {
        let offset = usize::try_from(at.checked_sub(addr)?).ok()?;
        let raw = bytes.get(offset..offset.checked_add(size)?)?;
        Some(match size {
            2 => i32::from(i16::from_le_bytes(raw.try_into().ok()?)).cast_unsigned(),
            _ => u32::from_le_bytes(raw.try_into().ok()?),
        })
    };
    let value =
        match word >> 12 {
            // MOV.L @(disp, PC), Rn
            0xd => Some(literal((addr & !3).wrapping_add(4 + disp * 4), 4)),
            // MOV.W @(disp, PC), Rn
            0x9 => Some(literal(addr.wrapping_add(4 + disp * 2), 2)),
            // MOV #imm, Rn
            0xe => Some(Some(i32::from((word & 0xff) as u8 as i8).cast_unsigned())),
            // MOV Rm, Rn
            0x6 if word & 0xf == 3 => Some(state.get(m)),
            // MOVA @(disp, PC), R0
            0xc if word & 0x0f00 == 0x0700 => {
                state.regs[0] = u32::try_from((addr & !3).wrapping_add(4 + disp * 4)).ok();
                return Note::None;
            }
            // ADD #imm, Rn
            0x7 => Some(state.get(n).map(|value| {
                value.wrapping_add(i32::from((word & 0xff) as u8 as i8).cast_unsigned())
            })),
            _ => None,
        };
    if let Some(value) = value {
        state.set(n, value);
        return match (word >> 12, value) {
            (0xd, Some(literal)) => Note::Address {
                reg: u32::try_from(n).unwrap_or(0),
                addr: u64::from(literal),
            },
            _ => Note::None,
        };
    }
    // In the 0x8 and 0xc groups the fields are immediates, and only R0 is
    // written. Anything else may write Rn and Rm (post-increment and
    // pre-decrement addressing included), and the 0x0 group R0 too.
    if !matches!(word >> 12, 0x8 | 0xc) {
        state.set(n, None);
        state.set(m, None);
    }
    if matches!(word >> 12, 0x0 | 0x8 | 0xc) {
        state.regs[0] = None;
    }
    Note::None
}

/// Whether `bytes` begin a GCC frame: saved registers (`mov.l rN,
/// @-r15`), the return address (`sts.l pr, @-r15`) or the frame pointer
/// (`mov.l r14, @-r15`) among them, before anything else.
pub(crate) fn starts_frame(bytes: &[u8]) -> bool {
    let mut saved = 0;
    for at in (0..16).step_by(2) {
        match bytes.get(at..).and_then(half) {
            // STS.L PR, @-R15; MOV.L R14, @-R15
            Some(0x4f22 | 0x2fe6) => return true,
            // Other saved registers
            Some(word) if word & 0xff0f == 0x2f06 => saved += 1,
            // ADD #-n, R15
            Some(word) if word & 0xff00 == 0x7f00 && word & 0x80 != 0 => {}
            // A leaf saves two registers or more before anything else.
            _ => return saved >= 2,
        }
    }
    saved >= 2
}

fn half(bytes: &[u8]) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(..2)?.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(halves: &[u16], addr: u64) -> Insn {
        let bytes: Vec<u8> = halves.iter().flat_map(|h| h.to_le_bytes()).collect();
        decode(&mut State::default(), &bytes, addr)
    }

    /// The flows of `halves` at `addr` on, in order.
    fn run(halves: &[u16], addr: u64) -> Vec<Flow> {
        let bytes: Vec<u8> = halves.iter().flat_map(|h| h.to_le_bytes()).collect();
        let mut state = State::default();
        let mut flows = Vec::new();
        let mut at = 0;
        while at < bytes.len() {
            let insn = decode(&mut state, &bytes[at..], addr + at as u64);
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
        let mut state = State::default();
        let first = decode(&mut state, &bytes, 0x1000);
        let second = decode(&mut state, &bytes[2..], 0x1002);
        let call = decode(&mut state, &bytes[4..], 0x1004);
        assert_eq!((first.len, second.len), (2, 2));
        assert_eq!((call.flow, call.len), (Flow::Call(0x1108), 8));
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
    fn frames() {
        let bytes =
            |halves: &[u16]| -> Vec<u8> { halves.iter().flat_map(|h| h.to_le_bytes()).collect() };
        // mov.l r8, @-r15; sts.l pr, @-r15
        assert!(starts_frame(&bytes(&[0x2f86, 0x4f22])));
        // mov.l r14, @-r15
        assert!(starts_frame(&bytes(&[0x2fe6, 0x6ef3])));
        // mov r4, r1: no frame
        assert!(!starts_frame(&bytes(&[0x6143, 0x4f22])));
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
