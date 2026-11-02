//! SPARC (V8 and V9): control flow only. Words are big-endian. A transfer
//! and the instruction in its delay slot decode as one 8-byte instruction,
//! so a call returns past the slot (to `%o7 + 8`, as `ret` and `retl` go).
//! A call whose slot restores the caller's register window or return
//! address (`call f; restore`, `mov %o7, %g1; call f; mov %g1, %o7`) makes
//! the callee return to this function's caller: a tail call.
//!
//! For jump tables the decoder notes what GCC's `switch` computes: the
//! bound (`cmp %g1, n; bgu default`), the table's address (from the GOT
//! pointer, `sethi; call thunk; add %l7`, less a `sethi; or` offset), the
//! scaled index (`sllx %g1, 2, %g1`) and the load of an entry relative to
//! the table (`ldsw [%l7+%g1], %g1; jmp %l7+%g1`). A transfer's delay slot
//! runs before its target, so its note is the transfer's, except an
//! annulled branch's, which runs on one path only.

use crate::decode::{Extend, Flow, Insn, Mem, Note};

/// `%o7`, where `call` and `jmpl` leave the caller's address.
const O7: u32 = 15;
/// `%i7`: the caller's `%o7`, after a `save`.
const I7: u32 = 31;

/// What earlier instructions left that a later one needs.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct State {
    /// A register holding another shifted left, and by how much: the index
    /// of the load after it, scaled.
    scaled: Option<(u32, u8)>,
}

/// The registers a call leaves as they were: the locals and ins, which
/// live in the caller's own register window.
pub(crate) const CALL_PRESERVED: u32 = 0xffff_0000;

pub(crate) fn decode(state: &mut State, wide: bool, bytes: &[u8], addr: u64) -> Insn {
    let Some(word) = read_word(bytes) else {
        return Insn::new(4, Flow::Invalid);
    };
    let wrap = |target: u64| if wide { target } else { target & 0xffff_ffff };
    let Some(flow) = flow(word, addr, wrap) else {
        let mut insn = Insn::new(4, Flow::Next);
        // `nop` is `sethi 0, %g0`.
        insn.pad = word == 0x0100_0000;
        if !insn.pad {
            insn.note = note(state, word, wide, addr);
        }
        return insn;
    };
    if matches!(flow, Flow::Stop | Flow::Invalid) {
        return Insn::new(4, flow);
    }
    // A transfer with no slot after it is cut short: the slot is not code.
    let Some(slot) = bytes.get(4..8).and_then(read_word) else {
        return Insn::new(4, Flow::Invalid);
    };
    let flow = match flow {
        Flow::Call(target) if returns_elsewhere(slot) => Flow::Jump(target),
        Flow::CallIndirect if returns_elsewhere(slot) => Flow::JumpIndirect,
        flow => flow,
    };
    let mut insn = Insn::new(8, flow);
    // An annulled branch (bit 29) runs its slot only when taken.
    let annulled = word >> 30 == 0 && word & 0x2000_0000 != 0;
    if !annulled {
        insn.note = note(state, slot, wide, addr.wrapping_add(4));
    }
    if matches!(flow, Flow::Call(_) | Flow::CallIndirect) {
        *state = State::default();
    }
    insn
}

/// The register a PC thunk at the start of `bytes` adds `%o7` to: GCC's
/// `__sparc_get_pc_thunk.l7` is `retl; add %o7, %l7, %l7`.
pub(crate) fn pc_thunk(bytes: &[u8]) -> Option<u32> {
    let (ret, add) = (read_word(bytes)?, read_word(bytes.get(4..)?)?);
    let rd = (add >> 25) & 0x1f;
    let (rs1, rs2) = ((add >> 14) & 0x1f, add & 0x1f);
    let sources = (rs1 == O7 && rs2 == rd) || (rs2 == O7 && rs1 == rd);
    (ret == 0x81c3_e008 && add & 0xc1f8_3fe0 == 0x8000_0000 && sources && rd != 0).then_some(rd)
}

/// What `word`, which transfers nowhere, tells a jump-table tracker.
fn note(state: &mut State, word: u32, wide: bool, addr: u64) -> Note {
    let rd = (word >> 25) & 0x1f;
    let op3 = (word >> 19) & 0x3f;
    let (rs1, rs2) = ((word >> 14) & 0x1f, word & 0x1f);
    let immediate = word & 0x2000 != 0;
    let simm = (i64::from(word & 0x1fff) ^ 0x1000) - 0x1000;
    let wrap = |value: u64| if wide { value } else { value & 0xffff_ffff };
    let clobber = |reg: u32| {
        if reg == 0 {
            Note::None
        } else {
            Note::Clobber(1 << reg)
        }
    };
    let scaled = state.scaled;
    let note = match word >> 30 {
        // SETHI
        0 if (word >> 22) & 7 == 4 && rd != 0 => Note::Address {
            reg: rd,
            addr: u64::from(word & 0x3f_ffff) << 10,
        },
        0 => Note::None,
        // CMP (SUBcc into %g0) with a positive constant.
        2 if rd == 0 && op3 == 0x14 && immediate && simm > 0 => Note::Compare {
            reg: rs1,
            imm: simm.cast_unsigned(),
        },
        // Others into %g0 write only the condition codes.
        2 if rd == 0 => Note::None,
        // RD %pc: Sun Studio's position-independent code finding itself.
        2 if op3 == 0x28 && rs1 == 5 => Note::Address {
            reg: rd,
            addr: wrap(addr),
        },
        2 => match op3 {
            // ADD, OR with a constant (OR fills in the bits SETHI left
            // clear, so it adds).
            0x00 | 0x02 if immediate && rs1 == 0 => Note::Address {
                reg: rd,
                addr: wrap(simm.cast_unsigned()),
            },
            0x00 | 0x02 if immediate => Note::Offset {
                reg: rd,
                src: rs1,
                imm: simm.cast_unsigned(),
            },
            0x04 if immediate => Note::Offset {
                reg: rd,
                src: rs1,
                imm: simm.wrapping_neg().cast_unsigned(),
            },
            0x00 | 0x02 if rs2 == 0 => Note::Copy { reg: rd, src: rs1 },
            0x00 | 0x02 if rs1 == 0 => Note::Copy { reg: rd, src: rs2 },
            0x00 => Note::Add {
                reg: rd,
                base: rs1,
                index: rs2,
                shift: 0,
                extend: Extend::None,
            },
            0x04 => Note::Sub {
                reg: rd,
                base: rs1,
                index: rs2,
            },
            // AND with a byte mask: a case value narrowed, still below
            // any bound it had.
            0x01 if immediate && word & 0x1fff == 0xff => Note::Copy { reg: rd, src: rs1 },
            // SLL, SLLX by 1-3: a scaled copy.
            0x25 if immediate && (1..=3).contains(&(word & 0x3f)) => {
                state.scaled = Some((rd, u8::try_from(word & 3).unwrap_or(0)));
                return Note::Copy { reg: rd, src: rs1 };
            }
            // SAVE, RESTORE: a new register window.
            0x3c | 0x3d => Note::Clobber(u32::MAX),
            // WR, floating-point operations, Tcc, FLUSH, DONE/RETRY.
            0x30 | 0x34..=0x37 | 0x3a | 0x3b | 0x3e => Note::None,
            _ => clobber(rd),
        },
        // Loads and stores.
        3 => match op3 {
            0x00..=0x02 | 0x08..=0x0b => {
                let (size, signed) = match op3 {
                    0x00 => (4, false),
                    0x01 => (1, false),
                    0x02 => (2, false),
                    0x08 => (4, true),
                    0x09 => (1, true),
                    0x0a => (2, true),
                    _ => (8, false),
                };
                let reg = |r: u32| (r != 0).then_some(r);
                let mem = if immediate {
                    Mem {
                        base: reg(rs1),
                        index: None,
                        scale: 1,
                        disp: simm.cast_unsigned(),
                    }
                } else {
                    // The scaled register is the index.
                    let (base, index, shift) = match scaled {
                        Some((r, shift)) if r == rs2 => (rs1, rs2, shift),
                        Some((r, shift)) if r == rs1 => (rs2, rs1, shift),
                        _ => (rs1, rs2, 0),
                    };
                    Mem {
                        base: reg(base),
                        index: reg(index),
                        scale: 1 << shift,
                        disp: 0,
                    }
                };
                if rd == 0 {
                    Note::None
                } else {
                    Note::Load {
                        reg: rd,
                        mem,
                        size,
                        signed: signed && (wide || size < 4),
                    }
                }
            }
            // LDD: a pair.
            0x03 | 0x13 => Note::Clobber((3 << rd) & !1),
            // Stores.
            0x04..=0x07 | 0x0e | 0x14..=0x17 | 0x1e => Note::None,
            // LDSTUB, SWAP and the alternate-space loads; CASA, CASXA.
            0x00..=0x1f | 0x3c | 0x3e => clobber(rd),
            // Floating-point loads and stores, prefetches.
            _ => Note::None,
        },
        _ => Note::None,
    };
    if let Some((reg, _)) = state.scaled
        && writes(note) >> reg & 1 != 0
    {
        state.scaled = None;
    }
    note
}

/// The registers a note says are written, as a mask.
fn writes(note: Note) -> u32 {
    match note {
        Note::None | Note::Push(_) | Note::PushRegister(_) => 0,
        Note::Clobber(regs) => regs,
        Note::Compare { reg, .. }
        | Note::Address { reg, .. }
        | Note::Load { reg, .. }
        | Note::Copy { reg, .. }
        | Note::Offset { reg, .. }
        | Note::Add { reg, .. }
        | Note::Sub { reg, .. }
        | Note::Pop(reg)
        | Note::Write(reg) => 1 << (reg & 31),
    }
}

/// Whether a call's delay slot `word` makes the callee return past the
/// caller: a `restore`, or arithmetic that writes `%o7`.
fn returns_elsewhere(word: u32) -> bool {
    let op3 = (word >> 19) & 0x3f;
    word >> 30 == 2 && (op3 == 0x3d || ((word >> 25) & 0x1f == O7 && op3 < 0x30))
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
        // CALL disp30; a call past its own delay slot only reads the PC
        // (position-independent code finding its GOT).
        1 => {
            let target = wrap(displaced(addr, word, 30));
            Some(if target == wrap(addr.wrapping_add(8)) {
                Flow::Next
            } else {
                Flow::Call(target)
            })
        }
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
                // JMP %rA+%rB: a table's base and its entry.
                0x38 if rd == 0 && !immediate && word & 0x1f != 0 => Some(Flow::JumpAdd {
                    base: rs1,
                    index: word & 0x1f,
                }),
                0x38 if rd == 0 && !immediate => Some(Flow::JumpRegister(rs1)),
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
        decode(&mut State::default(), false, &bytes, addr)
    }

    /// Each instruction of `words` at `addr` on, in order.
    fn run(words: &[u32], addr: u64) -> Vec<Insn> {
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_be_bytes()).collect();
        let mut state = State::default();
        let mut out = Vec::new();
        let mut at = 0;
        while at < bytes.len() {
            let insn = decode(&mut state, true, &bytes[at..], addr + at as u64);
            out.push(insn);
            at += insn.len as usize;
        }
        out
    }

    #[test]
    fn switch_notes() {
        let insns = run(
            &[
                0x80a6_a00a, // cmp %i2, 10
                0x0ac8_0058, // bgu,pn %icc, default
                0x0300_0ac5, // sethi 0xac5, %g1 (in the slot)
                0x8210_6004, // or %g1, 4, %g1
                0xb52e_b002, // sllx %i2, 2, %i2
                0xae25_c001, // sub %l7, %g1, %l7
                0xc245_c01a, // ldsw [%l7+%i2], %g1
                0x81c5_c001, // jmp %l7+%g1
                NOP,
            ],
            0x1000,
        );
        let notes: Vec<Note> = insns.iter().map(|insn| insn.note).collect();
        assert_eq!(notes[0], Note::Compare { reg: 26, imm: 10 });
        assert_eq!(
            notes[1],
            Note::Address {
                reg: 1,
                addr: 0x2b_1400
            }
        );
        assert_eq!(
            notes[2],
            Note::Offset {
                reg: 1,
                src: 1,
                imm: 4
            }
        );
        assert_eq!(notes[3], Note::Copy { reg: 26, src: 26 });
        assert_eq!(
            notes[4],
            Note::Sub {
                reg: 23,
                base: 23,
                index: 1
            }
        );
        assert_eq!(
            notes[5],
            Note::Load {
                reg: 1,
                mem: Mem {
                    base: Some(23),
                    index: Some(26),
                    scale: 4,
                    disp: 0
                },
                size: 4,
                signed: true
            }
        );
        assert_eq!(insns[6].flow, Flow::JumpAdd { base: 23, index: 1 });
        // rd %pc, %o7
        assert_eq!(
            run(&[0x9f41_4000], 0x1000)[0].note,
            Note::Address {
                reg: 15,
                addr: 0x1000
            }
        );
        // An annulled branch's slot: no note.
        assert_eq!(run(&[0x3280_0004, 0x8608_e0ff], 0x1000)[0].note, Note::None);
        // retl; add %o7, %l7, %l7
        let thunk: Vec<u8> = [0x81c3_e008_u32, 0xae03_c017]
            .iter()
            .flat_map(|w| w.to_be_bytes())
            .collect();
        assert_eq!(pc_thunk(&thunk), Some(23));
    }

    const NOP: u32 = 0x0100_0000;

    #[test]
    fn transfers_take_their_slot() {
        // call +0x40
        let call = one(&[0x4000_0010, NOP], 0x1_0000);
        assert_eq!((call.len, call.flow), (8, Flow::Call(0x1_0040)));
        // call -4
        assert_eq!(one(&[0x7fff_ffff, NOP], 0x1_0000).flow, Flow::Call(0xfffc));
        // call .+8: reads the PC.
        assert_eq!(one(&[0x4000_0002, NOP], 0x1_0000).flow, Flow::Next);
        // call +0x40; restore: a tail call.
        let tail = one(&[0x4000_0010, 0x81e8_0000], 0x1_0000);
        assert_eq!(tail.flow, Flow::Jump(0x1_0040));
        // call +0x40; mov %g1, %o7: a tail call from a leaf.
        let tail = one(&[0x4000_0010, 0x9e10_0001], 0x1_0000);
        assert_eq!(tail.flow, Flow::Jump(0x1_0040));
        // jmpl %g1, %o7; restore
        let tail = one(&[0x9fc0_4000, 0x81e8_0000], 0x1000);
        assert_eq!(tail.flow, Flow::JumpIndirect);
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
