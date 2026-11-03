//! Tensilica Xtensa (little-endian, windowed ABI): control flow, and the
//! constants calls and jumps through registers need. Instructions are two
//! or three bytes, byte-aligned. A density option adds the `.n` narrow
//! forms (`l32i.n`, `movi.n`, `ret.n`).
//!
//! Constants come from a literal pool of 4-byte words placed *before* the
//! code that reads them: `l32r at, label` loads the word at a negative,
//! word-aligned offset. The pool holds callees' addresses, jump tables and
//! data pointers, so an `l32r` of a function's address followed by `callx`
//! is a call there. Direct calls are PC-relative `call0`/`call4`/`call8`/
//! `call12`; `j` jumps, `jx` jumps through a register, and functions in the
//! windowed ABI open with `entry` and end with `retw`/`retw.n`.

use crate::isa::{Flow, Insn, Mem, Note};

/// What earlier instructions left in each of the sixteen address
/// registers: a fixed value (an immediate, or a literal-pool word a later
/// pass reads). Cleared at a block's end and across a call's window.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct State {
    known: [bool; 16],
}

/// The stack pointer.
const SP: u32 = 1;

/// Bytes of the instruction at the start of `bytes`: three, or two for the
/// narrow forms (`op0` 8 and up, except `op0` 11's wide `addmi`).
fn length(op0: u32) -> u32 {
    if op0 >= 0x8 { 2 } else { 3 }
}

/// The 24-bit (or 16-bit) instruction word, little-endian.
fn word(bytes: &[u8]) -> Option<(u32, u32)> {
    let b0 = u32::from(*bytes.first()?);
    let b1 = u32::from(*bytes.get(1)?);
    let op0 = b0 & 0xf;
    let len = length(op0);
    if len == 3 {
        let b2 = u32::from(*bytes.get(2)?);
        Some((b0 | b1 << 8 | b2 << 16, len))
    } else {
        Some((b0 | b1 << 8, len))
    }
}

/// The word-aligned address an `l32r` at `addr` loads from: a negative
/// offset (the 16-bit field is the high half of a negative word count).
fn literal(instr: u32, addr: u64) -> u64 {
    let imm16 = (instr >> 8) & 0xffff;
    let offset = ((0xffff_0000 | imm16) as i32) as i64 * 4;
    ((addr.wrapping_add(3) & !3).wrapping_add_signed(offset)) & 0xffff_ffff
}

/// A word load `at = [as + disp]`, as a note a jump table or a GOT read
/// resolves once the base register holds a fixed address.
fn load(dest: u32, base: u32, disp: u32) -> Note {
    Note::Fetch {
        reg: dest,
        mem: Mem {
            base: Some(base),
            index: None,
            scale: 1,
            disp: u64::from(disp),
        },
        size: 4,
        signed: false,
    }
}

/// The signed eight-bit branch offset in bits 16..24.
fn imm8(instr: u32) -> i64 {
    i64::from(((instr >> 16) & 0xff) as u8 as i8)
}

/// A branch, jump or call target: `addr + 4 + offset`, the offset from the
/// instruction's immediate field.
fn relative(addr: u64, offset: i64) -> u64 {
    addr.wrapping_add(4).wrapping_add_signed(offset) & 0xffff_ffff
}

impl State {
    fn set(&mut self, reg: u32, known: bool) {
        if let Some(slot) = self.known.get_mut(reg as usize) {
            *slot = known;
        }
    }
}

/// The literal-pool word an `l32r` at `addr` reads, for a sweep to step
/// over as data; `None` for any other instruction.
pub(crate) fn literal_word(bytes: &[u8], addr: u64) -> Option<u64> {
    let (instr, _) = word(bytes)?;
    (instr & 0xf == 0x1).then(|| literal(instr, addr))
}

pub(crate) fn decode(state: &mut State, bytes: &[u8], addr: u64) -> Insn {
    let Some((instr, len)) = word(bytes) else {
        return Insn::new(2, Flow::Invalid);
    };
    let op0 = instr & 0xf;
    let t = (instr >> 4) & 0xf;
    let s = (instr >> 8) & 0xf;
    let r = (instr >> 12) & 0xf;
    let mut note = Note::None;
    let mut known: Option<u32> = None;
    let flow = match op0 {
        // QRST: the register-to-register group. Jumps, calls and returns
        // through a register live here (op1 and op2 zero, r zero).
        // ill: GCC's trap after a call that never returns (`_start`'s
        // `callx4 __libc_start_main`).
        0x0 if instr == 0 => Flow::Stop,
        0x0 if (instr >> 16) == 0 && r == 0 => match t {
            0x8 | 0x9 => Flow::Return,
            0xa => Flow::JumpRegister(s),
            0xc..=0xf => Flow::CallRegister(s),
            _ => Flow::Next,
        },
        // Other QRST: writes the r register (ALU), or nothing.
        0x0 => {
            known = Some(r);
            Flow::Next
        }
        // L32R: load a word from the literal pool before it.
        0x1 => {
            note = Note::Fetch {
                reg: t,
                mem: Mem {
                    base: None,
                    index: None,
                    scale: 1,
                    disp: literal(instr, addr),
                },
                size: 4,
                signed: false,
            };
            state.set(t, true);
            Flow::Next
        }
        // LSAI: loads, stores and the immediate arithmetic, by the r field.
        0x2 => {
            match r {
                // movi at, imm12
                0xa => {
                    let imm = ((s << 8 | (instr >> 16) & 0xff) ^ 0x800).wrapping_sub(0x800);
                    note = Note::Address {
                        reg: t,
                        addr: u64::from(imm) & 0xffff_ffff,
                    };
                    state.set(t, true);
                }
                // addi / addmi at, as, imm8: tracked only off a known base.
                0xc | 0xd => {
                    let imm = if r == 0xd {
                        imm8(instr) << 8
                    } else {
                        imm8(instr)
                    };
                    if state.known.get(s as usize).copied().unwrap_or(false) && s != SP {
                        note = Note::Offset {
                            reg: t,
                            src: s,
                            imm: imm as u64 & 0xffff_ffff,
                        };
                        state.set(t, true);
                    } else {
                        known = Some(t);
                    }
                }
                // l32i at, as, imm8 * 4: a word load, which a jump table
                // or a GOT read goes through.
                0x2 => {
                    note = load(t, s, ((instr >> 16) & 0xff) * 4);
                    state.set(t, false);
                }
                // The byte and half-word loads write t.
                0x0 | 0x1 | 0x9 | 0xb => known = Some(t),
                _ => {}
            }
            Flow::Next
        }
        // CALLN: call0/call4/call8/call12 (the n field is the window), to
        // a word-aligned target.
        0x5 => {
            let offset = ((instr >> 6) ^ 0x2_0000).wrapping_sub(0x2_0000) as i32 as i64;
            Flow::Call(((addr & !3).wrapping_add(4).wrapping_add_signed(offset << 2)) & 0xffff_ffff)
        }
        // SI: j (again, with n==0), and the twelve- and eight-bit branches.
        0x6 => match (instr >> 4) & 3 {
            // j
            0 => {
                let offset = ((instr >> 6) ^ 0x2_0000).wrapping_sub(0x2_0000) as i32 as i64;
                Flow::Jump(relative(addr, offset))
            }
            // BRI12: beqz / bnez / bltz / bgez.
            1 => {
                let imm12 = ((instr >> 12) ^ 0x800).wrapping_sub(0x800) as i32 as i64;
                Flow::Branch(relative(addr, imm12))
            }
            // BRI8: the immediate branches (beqi, bnei, blti, bgei).
            2 => Flow::Branch(relative(addr, imm8(instr))),
            // n == 3, m == 0: entry (a frame).
            _ if (instr >> 6) & 3 == 0 => Flow::Next,
            // m == 1: bf/bt (signed offset), and loop/loopnez/loopgtz,
            // whose unsigned offset names the loop's end: loopnez and
            // loopgtz skip there, loop falls into its body.
            _ if (instr >> 6) & 3 == 1 => match r {
                0 | 1 => Flow::Branch(relative(addr, imm8(instr))),
                0x8 => Flow::Next,
                0x9 | 0xa => Flow::Branch(relative(addr, i64::from((instr >> 16) & 0xff))),
                _ => Flow::Invalid,
            },
            // m == 2, 3: bltui / bgeui.
            _ => Flow::Branch(relative(addr, imm8(instr))),
        },
        // B: the register-register branches (beq, bne, blt, ...).
        0x7 => Flow::Branch(relative(addr, imm8(instr))),
        // L32I.N: narrow word load (base s, displacement r * 4).
        0x8 => {
            note = load(t, s, r * 4);
            state.set(t, false);
            Flow::Next
        }
        0x9 => Flow::Next,
        // ADD.N / ADDI.N: narrow, write the r register.
        0xa | 0xb => {
            known = Some(r);
            Flow::Next
        }
        // ST2: movi.n as, imm7 (t below 8), or beqz.n / bnez.n as, imm6
        // (t 8 and up; the offset is unsigned, t's low bits over r).
        0xc => {
            if t & 8 != 0 {
                let imm = (t & 3) << 4 | r;
                Flow::Branch(relative(addr, i64::from(imm)))
            } else {
                // imm7 runs from -32 to 95.
                let imm = ((t & 7) << 4 | r) as i32;
                let imm = if imm >= 96 { imm - 128 } else { imm };
                note = Note::Address {
                    reg: s,
                    addr: imm as u32 as u64,
                };
                state.set(s, true);
                Flow::Next
            }
        }
        // ST3: mov.n (writes t), ret.n / retw.n, or nop.n / break.n.
        0xd => {
            if r == 0xf {
                match t {
                    0 | 1 => Flow::Return,
                    // ill.n
                    6 => Flow::Stop,
                    _ => Flow::Next,
                }
            } else {
                known = Some(t);
                Flow::Next
            }
        }
        // Reserved (or FLIX bundles, which no configuration seen uses).
        _ => Flow::Invalid,
    };
    if let Some(reg) = known {
        state.set(reg, false);
        if !matches!(
            note,
            Note::Address { .. } | Note::Offset { .. } | Note::Fetch { .. }
        ) {
            note = Note::Write(reg);
        }
    }
    let mut insn = Insn::new(len, flow);
    insn.note = note;
    // nop.n and the wide nop.
    insn.pad = instr == 0xf03d || instr == 0x20_00_00;
    match flow {
        Flow::Next | Flow::Branch(_) => {}
        Flow::Call(_) | Flow::CallRegister(_) | Flow::CallIndirect => {
            // A windowed call rotates the register file: the callee's
            // writes land above the caller's live registers, but nothing
            // the decoder tracked survives a call it cannot see through.
            *state = State::default();
        }
        _ => *state = State::default(),
    }
    insn
}

/// Whether `bytes` open a frame: the windowed ABI's `entry` (which lowers
/// the stack pointer and saves the window), or a call0-ABI prologue that
/// subtracts from the stack pointer.
pub(crate) fn starts_frame(bytes: &[u8]) -> bool {
    let Some((instr, _)) = word(bytes) else {
        return false;
    };
    // entry: op0 6, n 3, m 0, s == sp.
    instr & 0xf == 0x6 && (instr >> 4) & 0xf == 0x3 && (instr >> 8) & 0xf == SP
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(bytes: &[u8], addr: u64) -> Vec<Insn> {
        let mut state = State::default();
        let mut out = Vec::new();
        let mut at = 0;
        while at < bytes.len() {
            let insn = decode(&mut state, &bytes[at..], addr + at as u64);
            at += insn.len as usize;
            out.push(insn);
        }
        out
    }

    #[test]
    fn calls_and_returns() {
        // call8 .-0x94 ; callx8 a8 ; retw.n
        let insns = run(&[0xa5, 0xf6, 0xff, 0xe0, 0x08, 0x00, 0x1d, 0xf0], 0x401006);
        assert_eq!(insns[0].flow, Flow::Call(0x400f70));
        assert_eq!(insns[1].flow, Flow::CallRegister(8));
        assert_eq!(insns[2].flow, Flow::Return);
    }

    #[test]
    fn jumps_and_branches() {
        // j .+0x1f
        assert_eq!(
            run(&[0xc6, 0x06, 0x00], 0x400fdf)[0].flow,
            Flow::Jump(0x400ffe)
        );
        // bnez a2, .+0x50
        assert_eq!(
            run(&[0x56, 0xc2, 0x04], 0x400fc9)[0].flow,
            Flow::Branch(0x401019)
        );
        // beq a8, a10, .+0xb
        assert_eq!(
            run(&[0xa7, 0x18, 0x07], 0x400f79)[0].flow,
            Flow::Branch(0x400f84)
        );
        // jx a8
        assert_eq!(
            run(&[0xa0, 0x08, 0x00], 0x400c60)[0].flow,
            Flow::JumpRegister(8)
        );
    }

    #[test]
    fn signed_and_narrow_branches() {
        // bnei a2, 1, .-0x10 (imm8 0xf0: a backward branch)
        assert_eq!(
            run(&[0x66, 0x12, 0xf0], 0x401000)[0].flow,
            Flow::Branch(0x400ff4)
        );
        // bne a2, a3, .-0x4
        assert_eq!(
            run(&[0x37, 0x92, 0xfc], 0x401000)[0].flow,
            Flow::Branch(0x401000)
        );
        // beqz.n a2, .+0x24 (imm6 0x20: t 0b1010, r 0)
        assert_eq!(run(&[0xac, 0x02], 0x401000)[0].flow, Flow::Branch(0x401024));
        // movi.n a2, -1 (imm7 0x7f: t 0b0111, r 0xf) is no branch.
        let insns = run(&[0x7c, 0xf2], 0x401000);
        assert_eq!(insns[0].flow, Flow::Next);
        assert_eq!(
            insns[0].note,
            Note::Address {
                reg: 2,
                addr: 0xffff_ffff
            }
        );
        // call0 .+0x8
        assert_eq!(
            run(&[0x45, 0x00, 0x00], 0x401000)[0].flow,
            Flow::Call(0x401008)
        );
    }

    #[test]
    fn literal_load() {
        // l32r a6, . 0x400f38 at 0x400f4a
        let insns = run(&[0x61, 0xfb, 0xff], 0x400f4a);
        assert_eq!(
            insns[0].note,
            Note::Fetch {
                reg: 6,
                mem: Mem {
                    base: None,
                    index: None,
                    scale: 1,
                    disp: 0x400f38
                },
                size: 4,
                signed: false
            }
        );
        assert_eq!(literal_word(&[0x61, 0xfb, 0xff], 0x400f4a), Some(0x400f38));
    }

    #[test]
    fn frame() {
        // entry a1, 0x20
        assert!(starts_frame(&[0x36, 0x41, 0x00]));
        // retw.n is no frame.
        assert!(!starts_frame(&[0x1d, 0xf0]));
    }
}
