//! 32-bit Arm: A32 and Thumb (T16 and T32), control flow only. A Thumb
//! address carries its mode in bit 0, as Arm symbol tables write it, so
//! the decoder reads an odd address as Thumb and gives Thumb targets bit 0;
//! `blx` switches mode. A32 reads the PC as the instruction plus 8, Thumb
//! as plus 4.
//!
//! Most A32 instructions, and Thumb ones inside an `it` block, run only
//! when a condition holds: a conditional return or jump may also fall
//! through. The decoder also follows the address arithmetic of a PLT stub
//! (`add ip, pc, #n; add ip, ip, #n; ldr pc, [ip, #n]!`) to its slot.

use crate::decode::{Flow, Insn, Mem, Note};

/// The link register.
const LR: u32 = 14;
/// The stack pointer.
const SP: u32 = 13;
/// The PC.
const PC: u32 = 15;

/// What earlier instructions left that a later one needs.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct State {
    /// Thumb instructions left in the current `it` block, which run only
    /// when its condition holds.
    it: u8,
    /// The address in `ip` (r12), from the arithmetic a PLT stub does.
    ip: Option<u64>,
}

pub(crate) fn decode(state: &mut State, bytes: &[u8], addr: u64) -> Insn {
    if addr & 1 != 0 {
        thumb(state, bytes, addr & !1)
    } else {
        a32(state, bytes, addr)
    }
}

/// Whether `bytes` begin by pushing the link register, as only a
/// function's first instructions do.
pub(crate) fn starts_frame(thumb: bool, bytes: &[u8]) -> bool {
    if thumb {
        // push {..., lr}; push.w {..., lr}
        let half = |i: usize| {
            bytes
                .get(i..i + 2)
                .and_then(|h| h.try_into().ok())
                .map(u16::from_le_bytes)
        };
        match half(0) {
            Some(first) if first & 0xff00 == 0xb500 => true,
            Some(0xe92d) => half(2).is_some_and(|second| second & 0x4000 != 0),
            _ => false,
        }
    } else {
        // stmdb sp!, {..., lr}
        word(bytes).is_some_and(|word| word & 0xffff_4000 == 0xe92d_4000)
    }
}

fn word(bytes: &[u8]) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?))
}

/// Sign-extend the low `bits` bits of `value`.
fn signed(value: u32, bits: u32) -> i64 {
    let field = i64::from(value) & ((1 << bits) - 1);
    let sign = 1_i64 << (bits - 1);
    (field ^ sign) - sign
}

/// Keep an address to 32 bits.
fn wrap(addr: u64) -> u64 {
    addr & 0xffff_ffff
}

/// An instruction that does `flow`, and when `conditional` and `flow`
/// leaves, may also fall through.
fn insn(len: u32, flow: Flow, conditional: bool) -> Insn {
    let mut insn = Insn::new(len, flow);
    insn.falls = conditional
        && matches!(
            flow,
            Flow::Return
                | Flow::Stop
                | Flow::JumpSlot(_)
                | Flow::JumpMemory(_)
                | Flow::JumpRegister(_)
                | Flow::JumpTable { .. }
                | Flow::JumpIndirect
        );
    insn
}

/// What an instruction that continues to the next one tells a jump-table
/// tracker: `cmp rN, #imm` bounds a case value; anything else is taken to
/// write every register, so a bound holds only up to the table jump right
/// after it (or after the branch to the default case between them).
fn note(compare: Option<(u32, u32)>) -> Note {
    match compare {
        Some((reg, imm)) => Note::Compare {
            reg,
            imm: u64::from(imm),
        },
        None => Note::Clobber(0xffff),
    }
}

/// A Thumb-2 modified immediate, from `i:imm3:imm8`.
fn thumb_immediate(imm12: u32) -> u32 {
    let imm8 = imm12 & 0xff;
    match imm12 >> 8 {
        0 => imm8,
        1 => imm8 << 16 | imm8,
        2 => imm8 << 24 | imm8 << 8,
        3 => imm8.wrapping_mul(0x0101_0101),
        _ => (0x80 | imm12 & 0x7f).rotate_right(imm12 >> 7),
    }
}

fn a32(state: &mut State, bytes: &[u8], addr: u64) -> Insn {
    let Some(word) = word(bytes) else {
        return Insn::new(4, Flow::Invalid);
    };
    let pc = addr.wrapping_add(8);
    let cond = word >> 28;
    let conditional = cond != 0xe;
    let rd = (word >> 12) & 0xf;
    let rn = (word >> 16) & 0xf;
    let load = word & 0x0010_0000 != 0;
    let branch = || wrap(pc.wrapping_add_signed(signed(word, 24) * 4));
    let rotated = || (word & 0xff).rotate_right(((word >> 8) & 0xf) * 2);
    let flow = if cond == 0xf {
        // BLX (immediate): to Thumb, at a halfword the H bit picks.
        if (word >> 25) & 7 == 5 {
            let half = u64::from((word >> 24) & 1) * 2;
            Flow::Call(wrap(branch().wrapping_add(half)) | 1)
        } else {
            Flow::Next
        }
    } else if (word >> 25) & 7 == 5 {
        // B, BL
        if word & 0x0100_0000 != 0 {
            Flow::Call(branch())
        } else if conditional {
            Flow::Branch(branch())
        } else {
            Flow::Jump(branch())
        }
    } else if word & 0x0fff_fff0 == 0x012f_ff10 {
        // BX
        match word & 0xf {
            LR => Flow::Return,
            rm => Flow::JumpRegister(rm),
        }
    } else if word & 0x0fff_fff0 == 0x012f_ff30 {
        // BLX (register)
        Flow::CallIndirect
    } else if word & 0xfff0_00f0 == 0xe7f0_00f0 || word & 0x0ff0_00f0 == 0x0120_0070 {
        // UDF, BKPT
        Flow::Stop
    } else if (word >> 25) & 7 == 4 && load && word & 0x8000 != 0 {
        // LDM with the PC in its list: `pop {..., pc}` returns.
        if rn == SP {
            Flow::Return
        } else {
            Flow::JumpIndirect
        }
    } else if word & 0x0fff_fff0 == 0x079f_f100 {
        // LDR pc, [pc, rm, lsl #2]: a table of addresses after the next
        // instruction (the branch to the default case).
        Flow::JumpMemory(Mem {
            base: None,
            index: Some(word & 0xf),
            scale: 4,
            disp: wrap(pc),
        })
    } else if word & 0x0fff_fff0 == 0x008f_f100 {
        // ADD pc, pc, rm, lsl #2: a run of branches there.
        Flow::JumpTable {
            mem: Mem {
                base: None,
                index: Some(word & 0xf),
                scale: 1,
                disp: wrap(pc),
            },
            size: 0,
            base: wrap(pc),
            shift: 2,
        }
    } else if (word >> 26) & 3 == 1 && load && word & 0x0040_0000 == 0 && rd == PC {
        // LDR pc, [...]
        let immediate = word & 0x0200_0000 == 0;
        let pre = word & 0x0100_0000 != 0;
        let offset = u64::from(word & 0xfff);
        let at = |base: u64| {
            if word & 0x0080_0000 != 0 {
                wrap(base.wrapping_add(offset))
            } else {
                wrap(base.wrapping_sub(offset))
            }
        };
        match rn {
            SP if !pre => Flow::Return,
            PC if immediate => Flow::JumpSlot(at(pc)),
            12 if immediate && pre => state
                .ip
                .map_or(Flow::JumpIndirect, |ip| Flow::JumpSlot(at(ip))),
            _ => Flow::JumpIndirect,
        }
    } else if (word >> 26) & 3 == 0
        && rd == PC
        && word & 0x0190_0000 != 0x0100_0000
        && !(word & 0x0200_0000 == 0 && word & 0x90 == 0x90)
    {
        // A data-processing instruction that writes the PC: `mov pc, lr`
        // and `add pc, lr, #0` (Go's return) return, `mov pc, rm` jumps to
        // a register, and `add pc, pc, ...` indexes a table of branches.
        let opcode = (word >> 21) & 0xf;
        let plain = word & 0x0200_0ff0 == 0;
        let add_zero = word & 0x0200_0fff == 0x0200_0000;
        match (opcode, plain, word & 0xf) {
            (0xd, true, LR) => Flow::Return,
            (0xd, true, rm) => Flow::JumpRegister(rm),
            (0x4, _, _) if add_zero && rn == LR => Flow::Return,
            (0x4, _, _) if add_zero && rn != PC => Flow::JumpRegister(rn),
            _ => Flow::JumpIndirect,
        }
    } else {
        // The arithmetic a PLT stub finds its slot with.
        if rd == 12 {
            state.ip = if word & 0x0fff_f000 == 0x028f_c000 {
                Some(wrap(pc.wrapping_add(u64::from(rotated()))))
            } else if word & 0x0fff_f000 == 0x028c_c000 {
                state
                    .ip
                    .map(|ip| wrap(ip.wrapping_add(u64::from(rotated()))))
            } else {
                None
            };
        }
        Flow::Next
    };
    let mut decoded = insn(4, flow, conditional);
    // NOP, `mov r0, r0`, and zeros (`andeq r0, r0, r0`), which Go places
    // after calls that never return.
    decoded.pad = word == 0xe320_f000 || word == 0xe1a0_0000 || word == 0;
    if flow == Flow::Next && !decoded.pad {
        // CMP rn, #imm
        let compare = word & 0xfff0_f000 == 0xe350_0000;
        decoded.note = note(compare.then(|| (rn, rotated())));
    }
    decoded
}

/// The Thumb instruction at `addr` (even; Thumb addresses out are odd).
fn thumb(state: &mut State, bytes: &[u8], addr: u64) -> Insn {
    let half = |i: usize| {
        bytes
            .get(i..i + 2)
            .and_then(|h| h.try_into().ok())
            .map(u16::from_le_bytes)
    };
    let Some(first) = half(0) else {
        return Insn::new(2, Flow::Invalid);
    };
    let conditional = state.it > 0;
    state.it = state.it.saturating_sub(1);
    let pc = addr.wrapping_add(4);
    let to = |offset: i64| wrap(pc.wrapping_add_signed(offset)) | 1;
    if first >> 11 >= 0x1d {
        let Some(second) = half(2) else {
            return Insn::new(2, Flow::Invalid);
        };
        let (first, second) = (u32::from(first), u32::from(second));
        let flow = t32(first, second, pc, conditional);
        let mut decoded = insn(4, flow, conditional);
        if flow == Flow::Next {
            // CMP.W rn, #imm
            let compare = first & 0xfbf0 == 0xf1b0 && second & 0x8f00 == 0x0f00;
            let imm12 = (first >> 10 & 1) << 11 | (second >> 12 & 7) << 8 | second & 0xff;
            decoded.note = note(compare.then(|| (first & 0xf, thumb_immediate(imm12))));
        }
        return decoded;
    }
    let word = u32::from(first);
    let flow = if word & 0xf000 == 0xd000 {
        match (word >> 8) & 0xf {
            // UDF
            0xe => Flow::Stop,
            // SVC
            0xf => Flow::Next,
            _ => Flow::Branch(to(signed(word, 8) * 2)),
        }
    } else if word & 0xf800 == 0xe000 {
        // B: conditional when last in an `it` block.
        let target = to(signed(word, 11) * 2);
        if conditional {
            Flow::Branch(target)
        } else {
            Flow::Jump(target)
        }
    } else if word == 0x4778 {
        // BX pc: to the A32 code at the word-aligned PC.
        Flow::Jump(wrap(pc & !3))
    } else if word & 0xff87 == 0x4700 || word & 0xff87 == 0x4687 {
        // BX rm, MOV pc, rm
        match (word >> 3) & 0xf {
            LR => Flow::Return,
            rm => Flow::JumpRegister(rm),
        }
    } else if word & 0xff87 == 0x4780 {
        // BLX rm
        Flow::CallIndirect
    } else if word & 0xff87 == 0x4487 {
        // ADD pc, rm: a table of branches.
        Flow::JumpIndirect
    } else if word & 0xff00 == 0xbd00 {
        // POP {..., pc}
        Flow::Return
    } else if word & 0xf500 == 0xb100 {
        // CBZ, CBNZ
        let offset = (word >> 3) & 0x1f | (word >> 4) & 0x20;
        Flow::Branch(to(i64::from(offset) * 2))
    } else if word & 0xff00 == 0xbe00 {
        // BKPT
        Flow::Stop
    } else if word & 0xff00 == 0xbf00 && word & 0xf != 0 {
        // IT: the next instructions, up to four, by the mask's lowest set
        // bit. Under the "always" condition they run unconditionally.
        let mask = word & 0xf;
        let count = 4 - mask.trailing_zeros();
        state.it = if (word >> 4) & 0xf == 0xe {
            0
        } else {
            u8::try_from(count).unwrap_or(0)
        };
        Flow::Next
    } else {
        Flow::Next
    };
    let mut decoded = insn(2, flow, conditional);
    // NOP and the other hints, `mov r8, r8`
    decoded.pad = word == 0xbf00 || word == 0x46c0;
    let it = word & 0xff00 == 0xbf00;
    if flow == Flow::Next && !decoded.pad && !it {
        // CMP rn, #imm8
        let compare = word & 0xf800 == 0x2800;
        decoded.note = note(compare.then_some(((word >> 8) & 7, word & 0xff)));
    }
    decoded
}

/// A 32-bit Thumb instruction's flow, from its halfwords.
fn t32(first: u32, second: u32, pc: u64, conditional: bool) -> Flow {
    if first & 0xf800 == 0xf000 && second & 0x8000 != 0 {
        let s = (first >> 10) & 1;
        let (j1, j2) = ((second >> 13) & 1, (second >> 11) & 1);
        let imm11 = second & 0x7ff;
        // T4, BL, BLX: S:I1:I2:imm10:imm11:0, I = not (J xor S).
        let long = || {
            let (i1, i2) = (!(j1 ^ s) & 1, !(j2 ^ s) & 1);
            signed(
                s << 24 | i1 << 23 | i2 << 22 | (first & 0x3ff) << 12 | imm11 << 1,
                25,
            )
        };
        return match (second >> 12) & 5 {
            // BL
            5 => Flow::Call(wrap(pc.wrapping_add_signed(long())) | 1),
            // BLX: to A32, from the word-aligned PC.
            4 => Flow::Call(wrap((pc & !3).wrapping_add_signed(long()))),
            // B.W
            1 if conditional => Flow::Branch(wrap(pc.wrapping_add_signed(long())) | 1),
            1 => Flow::Jump(wrap(pc.wrapping_add_signed(long())) | 1),
            _ => {
                let cond = (first >> 6) & 0xf;
                if cond < 0xe {
                    // B<c>.W: S:J2:J1:imm6:imm11:0
                    let offset = signed(
                        s << 20 | j2 << 19 | j1 << 18 | (first & 0x3f) << 12 | imm11 << 1,
                        21,
                    );
                    Flow::Branch(wrap(pc.wrapping_add_signed(offset)) | 1)
                } else if first & 0xfff0 == 0xf7f0 && second & 0xf000 == 0xa000 {
                    // UDF.W
                    Flow::Stop
                } else {
                    Flow::Next
                }
            }
        };
    }
    let rn = first & 0xf;
    // TBB, TBH: a table of halfword counts forward from the PC, at the
    // PC's own address when `rn` is the PC.
    if first & 0xfff0 == 0xe8d0 && second & 0xffe0 == 0xf000 {
        let size = if second & 0x10 == 0 { 1 } else { 2 };
        let pcrel = rn == PC;
        return Flow::JumpTable {
            mem: Mem {
                base: (!pcrel).then_some(rn),
                index: Some(second & 0xf),
                scale: size,
                disp: if pcrel { wrap(pc) } else { 0 },
            },
            size,
            base: wrap(pc) | 1,
            shift: 1,
        };
    }
    // LDM.W / POP.W with the PC in its list.
    if (first & 0xffd0 == 0xe890 || first & 0xffd0 == 0xe910) && second & 0x8000 != 0 {
        return if rn == SP {
            Flow::Return
        } else {
            Flow::JumpIndirect
        };
    }
    // LDR.W pc, [...]
    if (first & 0xff70 == 0xf850 || first & 0xfff0 == 0xf8d0) && second >> 12 == PC {
        return match rn {
            // A literal: the word-aligned PC, plus or minus 12 bits.
            PC => {
                let offset = u64::from(second & 0xfff);
                let base = pc & !3;
                Flow::JumpSlot(wrap(if first & 0x80 != 0 {
                    base.wrapping_add(offset)
                } else {
                    base.wrapping_sub(offset)
                }))
            }
            // `pop.w {pc}`: post-indexed from the stack.
            SP if first & 0xfff0 == 0xf850 && second & 0x0f00 == 0x0b00 => Flow::Return,
            _ => Flow::JumpIndirect,
        };
    }
    Flow::Next
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(words: &[u32], addr: u64) -> Vec<Insn> {
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        let mut state = State::default();
        (0..words.len())
            .map(|i| decode(&mut state, &bytes[i * 4..], addr + i as u64 * 4))
            .collect()
    }

    fn t(halves: &[u16], addr: u64) -> Vec<Insn> {
        let bytes: Vec<u8> = halves.iter().flat_map(|h| h.to_le_bytes()).collect();
        let mut state = State::default();
        let mut out = Vec::new();
        let mut offset = 0;
        while offset < bytes.len() {
            let insn = decode(&mut state, &bytes[offset..], (addr + offset as u64) | 1);
            offset += insn.len as usize;
            out.push(insn);
        }
        out
    }

    fn flow(insns: &[Insn]) -> Vec<Flow> {
        insns.iter().map(|insn| insn.flow).collect()
    }

    #[test]
    fn a32_transfers() {
        let insns = a(
            &[
                0xeb00_0010, // bl +0x40 (from pc + 8)
                0xea00_0000, // b +0
                0x1a00_0000, // bne +0
                0xe12f_ff1e, // bx lr
                0x012f_ff1e, // bxeq lr
                0xe12f_ff33, // blx r3
                0xe8bd_8010, // pop {r4, pc}
                0xe28e_f000, // add pc, lr, #0
                0xfa00_0000, // blx +0 (to Thumb)
                0x979f_f100, // ldrls pc, [pc, r0, lsl #2]
            ],
            0x1_0000,
        );
        assert_eq!(
            flow(&insns),
            [
                Flow::Call(0x1_0048),
                Flow::Jump(0x1_000c),
                Flow::Branch(0x1_0010),
                Flow::Return,
                Flow::Return,
                Flow::CallIndirect,
                Flow::Return,
                Flow::Return,
                Flow::Call(0x1_0029),
                Flow::JumpMemory(Mem {
                    base: None,
                    index: Some(0),
                    scale: 4,
                    disp: 0x1_002c,
                }),
            ]
        );
        assert!(!insns[3].falls && insns[4].falls && insns[9].falls);
    }

    #[test]
    fn a32_plt_stub() {
        // add ip, pc, #0; add ip, ip, #0x1000; ldr pc, [ip, #0x10]!
        let insns = a(&[0xe28f_c600, 0xe28c_ca01, 0xe5bc_f010], 0x1_0000);
        // ip = 0x10008 + 0 (0x600 rotates 0 by 12: 0); then + 0x1000.
        assert_eq!(insns[2].flow, Flow::JumpSlot(0x1_1018));
    }

    #[test]
    fn thumb_transfers() {
        let insns = t(
            &[
                0xf000, 0xf810, // bl +0x20
                0xe7fe, // b . (to itself)
                0xd0fd, // beq -6 from pc
                0x4770, // bx lr
                0xbd10, // pop {r4, pc}
                0xb11b, // cbz r3, +6
                0x4798, // blx r3
                0xf000, 0xe810, // blx +0x20 (to A32)
            ],
            0x2000,
        );
        assert_eq!(
            flow(&insns),
            [
                Flow::Call(0x2025),
                Flow::Jump(0x2005),
                Flow::Branch(0x2005),
                Flow::Return,
                Flow::Return,
                Flow::Branch(0x2017),
                Flow::CallIndirect,
                Flow::Call(0x2034),
            ]
        );
    }

    #[test]
    fn thumb_it_blocks_make_returns_conditional() {
        // it eq; bxeq lr; bx lr
        let insns = t(&[0xbf08, 0x4770, 0x4770], 0x2000);
        assert_eq!(flow(&insns)[1..], [Flow::Return, Flow::Return]);
        assert!(insns[1].falls && !insns[2].falls);
        // ite ne: two conditional instructions.
        let insns = t(&[0xbf14, 0x4770, 0x4770, 0x4770], 0x2000);
        assert!(insns[1].falls && insns[2].falls && !insns[3].falls);
    }

    #[test]
    fn thumb_wide_branches_and_loads() {
        let insns = t(
            &[
                0xf000, 0xb800, // b.w +0
                0xf040, 0x8000, // bne.w +0
                0xe8d0, 0xf001, // tbb [r0, r1]
                0xf85d, 0xfb04, // ldr.w pc, [sp], #4
                0xf8df, 0xf004, // ldr.w pc, [pc, #4]
            ],
            0x2000,
        );
        assert_eq!(
            flow(&insns),
            [
                Flow::Jump(0x2005),
                Flow::Branch(0x2009),
                Flow::JumpTable {
                    mem: Mem {
                        base: Some(0),
                        index: Some(1),
                        scale: 1,
                        disp: 0,
                    },
                    size: 1,
                    base: 0x200d,
                    shift: 1,
                },
                Flow::Return,
                Flow::JumpSlot(0x2018),
            ]
        );
    }

    #[test]
    fn compares_bound_tables() {
        let compare = |reg, imm| Note::Compare { reg, imm };
        // cmp r3, #200; add r0, r0, #1
        let insns = a(&[0xe353_00c8, 0xe280_0001], 0);
        assert_eq!(insns[0].note, compare(3, 200));
        assert_eq!(insns[1].note, Note::Clobber(0xffff));
        // cmp r3, #9; cmp.w r4, #300; it hi; nop
        let insns = t(&[0x2b09, 0xf5b4, 0x7f96, 0xbf88, 0xbf00], 0);
        assert_eq!(insns[0].note, compare(3, 9));
        assert_eq!(insns[1].note, compare(4, 300));
        assert_eq!((insns[2].note, insns[3].note), (Note::None, Note::None));
        // addls pc, pc, r3, lsl #2: the branches after the default's.
        let insns = a(&[0x908f_f103], 0x1000);
        assert!(insns[0].falls);
        assert!(matches!(
            insns[0].flow,
            Flow::JumpTable {
                size: 0,
                base: 0x1008,
                shift: 2,
                ..
            }
        ));
    }

    #[test]
    fn frames_and_padding() {
        assert!(starts_frame(false, &0xe92d_4010_u32.to_le_bytes()));
        assert!(starts_frame(true, &0xb510_u16.to_le_bytes()));
        assert!(!starts_frame(true, &0x4770_u16.to_le_bytes()));
        assert!(a(&[0], 0)[0].pad);
        assert!(a(&[0xe320_f000], 0)[0].pad);
    }
}
