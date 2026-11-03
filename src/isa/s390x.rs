//! z/Architecture (s390x): control flow only. Instructions are 2, 4 or 6
//! bytes, by the top two bits of their first byte, and big-endian; relative
//! branches count halfwords from the instruction's own address.
//!
//! For jump tables the decoder notes the few instructions GCC's `switch`
//! uses (`clijh %r2, n, default; risbgn %r2, %r2, ..., 3; larl %r4, table;
//! lg %r2, 0(%r2,%r4); b 0(%r2,%r4)`); every other instruction is taken to
//! write every register.

use crate::isa::{Extend, Flow, Insn, Mem, Note};

/// What earlier instructions left that a later one needs.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct State {
    /// A register shifted left in place, and by how much: the index of the
    /// load that follows, scaled.
    scaled: Option<(u32, u8)>,
}

/// The register a call leaves its return address in by convention.
const R14: u32 = 14;

pub(crate) fn decode(state: &mut State, bytes: &[u8], addr: u64) -> Insn {
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
        // `0x0001`: the breakpoint Linux traps on, which LLVM and V8 emit
        // after a call that never returns (`llvm.trap`).
        0x00 if byte(1) == 0x01 => Flow::Stop,
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
    // B D2(X2, B2), with no displacement: to the sum of two registers.
    let flow = match (
        flow,
        first,
        byte(2) >> 4,
        u16::from(byte(2) & 0xf) << 8 | u16::from(byte(3)),
    ) {
        (Flow::JumpIndirect, 0x47, base, 0) if !falls && low != 0 && base != 0 => Flow::JumpAdd {
            base: u32::from(base),
            index: low,
        },
        (Flow::JumpIndirect, 0x47, 0, 0) if !falls && low != 0 => Flow::JumpRegister(low),
        _ => flow,
    };
    let mut decoded = Insn::new(len, flow);
    decoded.falls = falls
        && matches!(
            flow,
            Flow::Return | Flow::JumpRegister(_) | Flow::JumpIndirect
        );
    decoded.pad = pad;
    if matches!(flow, Flow::Next | Flow::Branch(_)) && !pad {
        decoded.note = note(state, insn, addr);
    }
    decoded
}

/// What `insn`, at `addr`, tells a jump-table tracker.
fn note(state: &mut State, insn: &[u8], addr: u64) -> Note {
    let byte = |i: usize| u32::from(insn.get(i).copied().unwrap_or(0));
    let (r1, r2) = (byte(1) >> 4, byte(1) & 0xf);
    let scaled = state.scaled.take();
    let imm32 = || byte(2) << 24 | byte(3) << 16 | byte(4) << 8 | byte(5);
    match (byte(0), byte(5), r2) {
        // LARL
        (0xc0, _, 0) => {
            let offset = i64::from(imm32().cast_signed()) * 2;
            state.scaled = scaled;
            Note::Address {
                reg: r1,
                addr: addr.wrapping_add_signed(offset),
            }
        }
        // CLFI, CLGFI: `jh` past them takes the cases above `imm`.
        (0xc2, _, 0xe | 0xf) => Note::Compare {
            reg: r1,
            imm: u64::from(imm32()),
        },
        // CLIJ, CLGIJ with mask 2 (high): cases above `imm` go elsewhere.
        (0xec, 0x7d | 0x7f, 2) => Note::Compare {
            reg: r1,
            imm: u64::from(byte(4)),
        },
        // RISBG(N) r, r, start, end | zero, shift; SLLG r, r, shift: a
        // shifted index, which the load after it scales.
        (0xec, 0x55 | 0x59, _) if r1 == r2 && byte(3) & 0x80 != 0 && (1..=3).contains(&byte(4)) => {
            state.scaled = Some((r1, u8::try_from(byte(4)).unwrap_or(0)));
            Note::None
        }
        (0xeb, 0x0d, _)
            if r1 == r2
                && byte(2) >> 4 == 0
                && (1..=3).contains(&byte(3))
                && byte(2) & 0xf == 0
                && byte(4) == 0 =>
        {
            state.scaled = Some((r1, u8::try_from(byte(3)).unwrap_or(0)));
            Note::None
        }
        // LG, LGF, LLGF r1, d(x, b)
        (0xe3, 0x04 | 0x14 | 0x16, index) => {
            let base = byte(2) >> 4;
            let disp = (byte(2) & 0xf) << 8 | byte(3) | byte(4) << 12;
            let disp = (i64::from(disp) ^ 0x8_0000) - 0x8_0000;
            let shift = match scaled {
                Some((reg, shift)) if reg == index => shift,
                _ => 0,
            };
            let (size, signed) = match byte(5) {
                0x04 => (8, false),
                0x14 => (4, true),
                _ => (4, false),
            };
            Note::Load {
                reg: r1,
                mem: Mem {
                    base: (base != 0).then_some(base),
                    index: (index != 0).then_some(index),
                    scale: 1 << shift,
                    disp: disp.cast_unsigned(),
                },
                size,
                signed,
            }
        }
        // AGR r1, r2
        (0xb9, _, _) if byte(1) == 0x08 => Note::Add {
            reg: byte(3) >> 4,
            base: byte(3) >> 4,
            index: byte(3) & 0xf,
            shift: 0,
            extend: Extend::None,
        },
        _ => match writes(insn) {
            0 => Note::None,
            regs => Note::Clobber(regs),
        },
    }
}

/// The general registers `insn` may write, as a mask: mostly its first
/// register field. Stores, compares, tests, branches and memory-to-memory
/// instructions write none; a load multiple writes a range.
fn writes(insn: &[u8]) -> u32 {
    let byte = |i: usize| u32::from(insn.get(i).copied().unwrap_or(0));
    let (r1, r3) = (byte(1) >> 4, byte(1) & 0xf);
    let one = 1 << r1;
    // R1 through R3, wrapping past r15.
    let range = || {
        let count = (r3 + 16 - r1) % 16 + 1;
        (0..count).fold(0, |mask, i| mask | 1 << ((r1 + i) % 16))
    };
    match byte(0) {
        // CLR, CR; BALR, BASR, BCR (branches say what they do).
        0x15 | 0x19 | 0x05 | 0x07 | 0x0d => 0,
        // STH, STC, ST, STD, STE; CH, CL, C, CLI-family compares; BC, BAL, BAS.
        0x40 | 0x42 | 0x50 | 0x60 | 0x70 | 0x49 | 0x55 | 0x59 | 0x45 | 0x47 | 0x4d => 0,
        // STM, LM
        0x90 => 0,
        0x98 => range(),
        // SI and SS forms: memory only.
        0x91..=0x97 | 0xd0..=0xdf | 0xe5 | 0xe8..=0xea | 0xee | 0xef => 0,
        // TM, CHI, CGHI and the relative branches.
        0xa7 => match byte(1) & 0xf {
            0..=7 | 0xe | 0xf => 0,
            _ => one,
        },
        // CGR, CLGR, CGFR, CLGFR
        0xb9 => match byte(1) {
            0x20 | 0x21 | 0x30 | 0x31 => 0,
            _ => 1 << (byte(3) >> 4),
        },
        0xb2 | 0xb3 => 1 << (byte(3) >> 4),
        // LARL and the rest write; BRCL, BRASL branch.
        0xc0 if matches!(byte(1) & 0xf, 4 | 5) => 0,
        // CGFI, CFI, CLGFI, CLFI
        0xc2 if byte(1) & 0xf >= 0xc => 0,
        // STHRL, STGRL, STRL; the compares and EXRL.
        0xc4 if matches!(byte(1) & 0xf, 7 | 0xb | 0xf) => 0,
        0xc6 => 0,
        0xe3 => match byte(5) {
            // STG, STY, STHY, STCY, STRVG, STRV; CG, CLG, CGF, CLGF, CY, CLY, CHY.
            0x24 | 0x50 | 0x70 | 0x72 | 0x2f | 0x3e | 0x20 | 0x21 | 0x30 | 0x31 | 0x59 | 0x55
            | 0x79 => 0,
            _ => one,
        },
        0xeb => match byte(5) {
            // LMG, LMY
            0x04 | 0x98 => range(),
            // STMG, STMY; SIY forms.
            0x24 | 0x90 | 0x51..=0x57 | 0x6a | 0x6e | 0x7a | 0x7e => 0,
            _ => one,
        },
        // Compare and branch, compare and trap.
        0xec if matches!(byte(5), 0x64..=0x7f | 0xe4..=0xff) => 0,
        _ => one,
    }
}

/// Whether `bytes` begin a frame: the registers saved up to `%r15` in the
/// caller's save area (`stmg %r6, %r15, 48(%r15)`, or `stm` in 31-bit code).
pub(crate) fn starts_frame(bytes: &[u8]) -> bool {
    match bytes {
        // STMG R1, R15, D(R15)
        [0xeb, regs, base, _, _, 0x24, ..] => regs & 0xf == 0xf && base >> 4 == 0xf,
        // STM R1, R15, D(R15)
        [0x90, regs, base, ..] => regs & 0xf == 0xf && base >> 4 == 0xf,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames() {
        // stmg %r6, %r15, 0x30(%r15)
        assert!(starts_frame(&[0xeb, 0x6f, 0xf0, 0x30, 0x00, 0x24]));
        // stm %r6, %r15, 0x18(%r15)
        assert!(starts_frame(&[0x90, 0x6f, 0xf0, 0x18]));
        // lgr %r5, %r4
        assert!(!starts_frame(&[0xb9, 0x04, 0x00, 0x54]));
        // stmg %r6, %r14, 0x30(%r15): not up to r15
        assert!(!starts_frame(&[0xeb, 0x6e, 0xf0, 0x30, 0x00, 0x24]));
        assert!(!starts_frame(&[]));
    }

    fn run(code: &[u8], addr: u64) -> Vec<Insn> {
        let mut state = State::default();
        let mut out = Vec::new();
        let mut at = 0;
        while at < code.len() {
            let insn = decode(&mut state, &code[at..], addr + at as u64);
            at += insn.len as usize;
            out.push(insn);
        }
        out
    }

    #[test]
    fn switch_notes() {
        let code = [
            0xec, 0x22, 0x00, 0x10, 0x19, 0x7f, // clijh %r2, 25, +0x20
            0xec, 0x22, 0x1d, 0xbc, 0x03, 0x59, // risbgn %r2, %r2, 29, 188, 3
            0xc0, 0x40, 0x00, 0x00, 0x10, 0x00, // larl %r4, +0x2000
            0xe3, 0x22, 0x40, 0x00, 0x00, 0x04, // lg %r2, 0(%r2,%r4)
            0x47, 0xf2, 0x40, 0x00, // b 0(%r2,%r4)
        ];
        let insns = run(&code, 0x1000);
        assert_eq!(insns[0].note, Note::Compare { reg: 2, imm: 25 });
        assert_eq!(insns[1].note, Note::None);
        assert_eq!(
            insns[2].note,
            Note::Address {
                reg: 4,
                addr: 0x300c
            }
        );
        assert_eq!(
            insns[3].note,
            Note::Load {
                reg: 2,
                mem: Mem {
                    base: Some(4),
                    index: Some(2),
                    scale: 8,
                    disp: 0
                },
                size: 8,
                signed: false
            }
        );
        assert_eq!(insns[4].flow, Flow::JumpAdd { base: 4, index: 2 });
    }

    #[test]
    fn registers_written() {
        // lgr %r1, %r2; stg %r1, 8(%r15); lmg %r14, %r1, 0(%r15); clfi %r3, 7
        assert_eq!(writes(&[0xb9, 0x04, 0, 0x12]), 1 << 1);
        assert_eq!(writes(&[0xe3, 0x10, 0xf0, 0x08, 0, 0x24]), 0);
        assert_eq!(writes(&[0xeb, 0xe1, 0xf0, 0, 0, 0x04]), 0xc003);
        assert_eq!(writes(&[0xc2, 0x3f, 0, 0, 0, 7]), 0);
    }

    #[test]
    fn calls_jumps_and_returns() {
        // brasl %r14, +0x100
        let call = decode(&mut State::default(), &[0xc0, 0xe5, 0, 0, 0, 0x80], 0x1000);
        assert_eq!((call.len, call.flow), (6, Flow::Call(0x1100)));
        // br %r14
        assert_eq!(
            decode(&mut State::default(), &[0x07, 0xfe], 0x1000).flow,
            Flow::Return
        );
        // bner %r14: a conditional return.
        let ret = decode(&mut State::default(), &[0x07, 0x7e], 0x1000);
        assert!(ret.flow == Flow::Return && ret.falls);
        // br %r1
        assert_eq!(
            decode(&mut State::default(), &[0x07, 0xf1], 0x1000).flow,
            Flow::JumpRegister(1)
        );
        // basr %r14, %r1
        assert_eq!(
            decode(&mut State::default(), &[0x0d, 0xe1], 0x1000).flow,
            Flow::CallIndirect
        );
        // j -4 (brc 15)
        assert_eq!(
            decode(&mut State::default(), &[0xa7, 0xf4, 0xff, 0xfe], 0x1000).flow,
            Flow::Jump(0xffc)
        );
        // jne +8
        assert_eq!(
            decode(&mut State::default(), &[0xa7, 0x74, 0, 4], 0x1000).flow,
            Flow::Branch(0x1008)
        );
        // jg (brcl 15) -2
        assert_eq!(
            decode(
                &mut State::default(),
                &[0xc0, 0xf4, 0xff, 0xff, 0xff, 0xff],
                0x1000
            )
            .flow,
            Flow::Jump(0xffe)
        );
        // cgij %r2, 0, 8, +6
        assert_eq!(
            decode(&mut State::default(), &[0xec, 0x28, 0, 3, 0, 0x7c], 0x1000).flow,
            Flow::Branch(0x1006)
        );
    }

    #[test]
    fn lengths_and_padding() {
        // lgr %r1, %r2; lg %r1, 8(%r15); nopr
        assert_eq!(
            decode(&mut State::default(), &[0xb9, 0x04, 0, 0x12], 0).len,
            4
        );
        assert_eq!(
            decode(&mut State::default(), &[0xe3, 0x10, 0xf0, 0x08, 0, 0x04], 0).len,
            6
        );
        assert!(decode(&mut State::default(), &[0x07, 0x07], 0).pad);
        assert_eq!(
            decode(&mut State::default(), &[0, 0], 0).flow,
            Flow::Invalid
        );
        assert_eq!(decode(&mut State::default(), &[0, 1], 0).flow, Flow::Stop);
        assert_eq!(
            decode(&mut State::default(), &[0xc0, 0xe5, 0], 0).flow,
            Flow::Invalid
        );
    }
}
