//! PowerPC (32- and 64-bit, either byte order): control flow only.
//! Instructions are 32 bits and have no delay slots. Branches are `b`
//! (`bl` calls), the conditional `bc`, and `bclr`/`bcctr` through the link
//! and count registers: `blr` returns, `bctr` jumps through `ctr` (a jump
//! table, or a tail call through a pointer), and their linking forms call.
//! A branch whose `BO` field says "always" is unconditional; one that tests
//! a condition may fall through.
//!
//! Position-independent 32-bit code finds its own address with `bcl 20, 31,
//! $+4`, a call to the next instruction that only sets `lr`.
//!
//! 32-bit code builds addresses in two halves (`lis r9, f@ha; addi r9, r9,
//! f@l`); the decoder keeps the constants such instructions leave, and
//! notes each address one completes: a function whose address is taken,
//! when it points at code.

use crate::isa::{Extend, Flow, Insn, Mem, Note};

/// What earlier instructions left that a later one needs.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct State {
    /// The slot `ctr`'s value was loaded from: a PLT stub's (`ld r12,
    /// n(r2); mtctr r12; bctr`).
    ctr_slot: Option<u64>,
    /// The last register loaded from a fixed address, and that address.
    loaded: Option<(u32, u64)>,
    /// The address in `lr`, after `bcl 20, 31, $+4`.
    lr: Option<u64>,
    /// A register holding a base plus a scaled case value (`slwi r6, r6,
    /// 2; add r6, r27, r6`), the address a table entry is then loaded from
    /// at an offset (`lwz r10, 0x280(r6)`): the sum, base, index and shift.
    indexed: Option<(u32, u32, u32, u8)>,
    /// The constant in each register.
    regs: [Option<u64>; 32],
    /// A register holding another shifted left, and by how much: a scaled
    /// case value.
    scaled: Option<(u32, u8)>,
}

/// The registers a call may change: r0 and r3-r12.
const VOLATILE: u32 = 0x1ff9;

/// The number `lr` goes by in notes, past the general registers: the
/// tracker carries the PC a `bcl` or `bl` over data leaves there to the
/// `mflr` in the block it jumps to.
const LR: u32 = 40;

/// The number `ctr` goes by in notes: `mtctr` copies a register there, and
/// `bctr` jumps to (`bctrl` calls) what it holds, even when the register
/// changed in between (`mtctr r4; mr r4, r5; bctrl`) or in another block.
const CTR: u32 = 41;

/// `nop` (`ori 0, 0, 0`).
const NOP: u32 = 0x6000_0000;

pub(crate) fn decode(
    state: &mut State,
    (big, wide, toc): (bool, bool, Option<u64>),
    bytes: &[u8],
    addr: u64,
) -> Insn {
    let Some(word) = read_word(big, bytes) else {
        return Insn::new(4, Flow::Invalid);
    };
    // Power10's prefixed instructions: a prefix word, then the instruction
    // it extends. None transfers control.
    if word >> 26 == 1 {
        let Some(suffix) = bytes.get(4..).and_then(|rest| read_word(big, rest)) else {
            return Insn::new(4, Flow::Invalid);
        };
        let mut insn = Insn::new(8, Flow::Next);
        insn.note = prefixed(state, word, suffix, addr);
        return insn;
    }
    let wrap = |target: u64| if wide { target } else { target & 0xffff_ffff };
    let link = word & 1 != 0;
    let absolute = word & 2 != 0;
    let next = wrap(addr.wrapping_add(4));
    // BO: bits 0x14 set branch whatever the condition and count.
    let always = (word >> 21) & 0x14 == 0x14;
    let to = |field: u32, bits: u32| {
        let sign = 1_i64 << (bits - 1);
        let offset = (i64::from(field) ^ sign) - sign;
        wrap(if absolute {
            offset.cast_unsigned()
        } else {
            addr.wrapping_add_signed(offset)
        })
    };
    let (flow, falls) = match word >> 26 {
        // Zero, an illegal instruction: the traceback table GCC puts after
        // each 64-bit function starts with it, so a path reaches it past a
        // call that never returns.
        0 if word == 0 => (Flow::Stop, false),
        0 => (Flow::Invalid, false),
        // B, BA, BL, BLA. A `bl` just past one word of data reads the PC
        // and jumps over it (musl's `bl 1f; .long _DYNAMIC - .; 1:`); one
        // farther may call the next function's local entry.
        18 => {
            let target = to(word & 0x03ff_fffc, 26);
            let over = target == next.wrapping_add(4);
            (
                if link && !over {
                    Flow::Call(target)
                } else {
                    Flow::Jump(target)
                },
                false,
            )
        }
        // BC: `bcl 20, 31, $+4` only reads the PC, and `bcl 20, 31, 1f`
        // just past a word of data (`.long _GLOBAL_OFFSET_TABLE_ - .`)
        // reads the PC and jumps over it.
        16 => {
            let target = to(word & 0xfffc, 16);
            match (link, always) {
                (true, true) if target == next => (Flow::Next, false),
                (true, true) if target > next && target <= next.wrapping_add(16) => {
                    (Flow::Jump(target), false)
                }
                (true, _) => (Flow::Call(target), false),
                (false, true) => (Flow::Jump(target), false),
                (false, false) => (Flow::Branch(target), false),
            }
        }
        19 => match (word >> 1) & 0x3ff {
            // BCLR: `blr` returns; `blrl` calls.
            16 if link => (Flow::CallIndirect, false),
            16 => (Flow::Return, !always),
            // BCCTR: `bctr` jumps through ctr; `bctrl` calls.
            528 if link => (
                state
                    .ctr_slot
                    .map_or(Flow::CallRegister(CTR), Flow::CallSlot),
                false,
            ),
            528 => (
                state
                    .ctr_slot
                    .map_or(Flow::JumpRegister(CTR), Flow::JumpSlot),
                !always,
            ),
            _ => (Flow::Next, false),
        },
        // TW 31, 0, 0 (`trap`): an unconditional trap. TD 31, too.
        31 if word & 0xffe0_07fe == 0x7fe0_0008 || word & 0xffe0_07fe == 0x7fe0_0088 => {
            (Flow::Stop, false)
        }
        _ => (Flow::Next, false),
    };
    let mut note = Note::None;
    match flow {
        // `bcl 20, 31, $+4` leaves its own address in `lr`.
        Flow::Next if word >> 26 == 16 => {
            state.lr = Some(next);
            note = Note::Pc {
                reg: LR,
                addr: next,
            };
        }
        // So does a `bl` or `bcl` over data, for the block past it.
        Flow::Jump(_) if link => {
            *state = State::default();
            note = Note::Pc {
                reg: LR,
                addr: next,
            };
        }
        Flow::Next => note = track(state, word, (wide, toc)),
        // A callee may change ctr and the volatile registers.
        Flow::Call(_) | Flow::CallIndirect | Flow::CallRegister(_) | Flow::CallSlot(_) => {
            state.ctr_slot = None;
            state.loaded = None;
            state.lr = None;
            for (reg, value) in state.regs.iter_mut().enumerate() {
                if VOLATILE >> reg & 1 != 0 {
                    *value = None;
                }
            }
        }
        Flow::Branch(_) => {}
        _ if falls => {}
        // Past a transfer that does not fall through, code is reached from
        // elsewhere.
        _ => *state = State::default(),
    }
    let mut insn = Insn::new(4, flow);
    insn.falls = falls;
    insn.pad = word == NOP;
    insn.note = note;
    insn
}

/// What `word`, which transfers nowhere, leaves in `ctr` and the other
/// registers, as a note: an address it completes (`lis; addi`, or an offset
/// from the TOC pointer, `addis r10, r2, ...; addi r10, r10, ...`), or a
/// step of GCC's jump-table read (`cmplwi; sldi; lwax; add; mtctr; bctr`).
fn track(state: &mut State, word: u32, (wide, toc): (bool, Option<u64>)) -> Note {
    let (rt, ra, rb) = (
        (word >> 21) & 0x1f,
        (word >> 16) & 0x1f,
        (word >> 11) & 0x1f,
    );
    let wrap = |value: u64| if wide { value } else { value & 0xffff_ffff };
    let xo = (word >> 1) & 0x3ff;
    // MTSPR ctr, rS (`mtctr rS`): SPR 9, its halves swapped in the field.
    if word & 0xfc1f_fffe == 0x7c09_03a6 {
        state.ctr_slot = state
            .loaded
            .filter(|&(reg, _)| reg == rt)
            .map(|(_, slot)| slot);
        return Note::Copy { reg: CTR, src: rt };
    }
    // MFSPR rT, lr (`mflr rT`): the PC, after `bcl`. MTSPR lr, rS.
    if word & 0xfc1f_fffe == 0x7c08_02a6 {
        let value = state.lr;
        if let Some(slot) = state.regs.get_mut(rt as usize) {
            *slot = value;
        }
        state.loaded = state.loaded.filter(|&(reg, _)| reg != rt);
        return value.map_or(Note::Copy { reg: rt, src: LR }, |addr| Note::Pc {
            reg: rt,
            addr,
        });
    }
    if word & 0xfc1f_fffe == 0x7c08_03a6 {
        state.lr = None;
        return Note::Copy { reg: LR, src: rt };
    }
    let get = |state: &State, reg: u32| match (reg, toc) {
        (2, Some(toc)) if wide => Some(toc),
        _ => state.regs.get(reg as usize).copied().flatten(),
    };
    let imm = u64::from(word & 0xffff);
    let simm = ((i64::from(word & 0xffff) ^ 0x8000) - 0x8000).cast_unsigned();
    let scaled = state.scaled.take();
    let loaded = state.loaded.take();
    let indexed = state.indexed.take();
    let set = |state: &mut State, reg: u32, value: Option<u64>| {
        if let Some(slot) = state.regs.get_mut(reg as usize) {
            *slot = value;
        }
    };
    let note = match word >> 26 {
        // ADDI, ADDIS (`li`, `lis` with rA zero). A high half (`lis`) is
        // no address yet in 32-bit code, where only completed ones are
        // noted (as pointers).
        14 | 15 => {
            let high = word >> 26 == 15;
            let add = if high { simm << 16 } else { simm };
            let base = if ra == 0 { Some(0) } else { get(state, ra) };
            let value = base.map(|base| wrap(base.wrapping_add(add)));
            set(state, rt, value);
            match value {
                Some(addr) if !(high && !wide) => Note::Address { reg: rt, addr },
                // The tracker may know the base the decoder lost: the PIC
                // register, set at the function's start.
                _ if ra != 0 => Note::Offset {
                    reg: rt,
                    src: ra,
                    imm: wrap(add),
                },
                _ => Note::Clobber(1 << rt),
            }
        }
        // ORI, ORIS rA, rS, imm
        24 | 25 => {
            let or = if word >> 26 == 25 { imm << 16 } else { imm };
            let value = get(state, rt).map(|value| value | or);
            set(state, ra, value);
            match value {
                Some(addr) if word >> 26 == 24 => Note::Address { reg: ra, addr },
                _ => Note::Clobber(1 << ra),
            }
        }
        // CMPLI crN, L, rA, imm (`cmplwi`, `cmpldi`): the bound on a case
        // value. CMPI and CMP, CMPL write only a condition register.
        10 => Note::Compare { reg: ra, imm },
        11 => Note::None,
        31 if matches!(xo, 0 | 32) => Note::None,
        // OR rA, rS, rS (`mr`)
        31 if xo == 444 && rt == rb => {
            let value = get(state, rt);
            set(state, ra, value);
            Note::Copy { reg: ra, src: rt }
        }
        // ADD rT, rA, rB: a base plus a scaled case value, which a load
        // reads through, or a table's entry plus its base.
        31 if xo & 0x1ff == 266 => {
            set(state, rt, None);
            if let Some((reg, shift)) = scaled
                && (reg == ra || reg == rb)
            {
                let base = if reg == rb { ra } else { rb };
                state.indexed = Some((rt, base, reg, shift));
                Note::None
            } else {
                Note::Add {
                    reg: rt,
                    base: ra,
                    index: rb,
                    shift: 0,
                    extend: Extend::None,
                }
            }
        }
        // LBZX, LHZX rT, rA, rB: a byte map's (or a halfword table's) entry.
        31 if matches!(xo, 87 | 279) => {
            set(state, rt, None);
            Note::Load {
                reg: rt,
                mem: Mem {
                    base: Some(ra).filter(|&ra| ra != 0),
                    index: Some(rb),
                    scale: 1,
                    disp: 0,
                },
                size: if xo == 87 { 1 } else { 2 },
                signed: false,
            }
        }
        // LWAX, LWZX, LDX rT, rA, rB, with rB the scaled case value.
        31 if matches!(xo, 341 | 23 | 21) => {
            set(state, rt, None);
            match scaled {
                Some((reg, shift)) if reg == rb => Note::Load {
                    reg: rt,
                    mem: Mem {
                        base: Some(ra),
                        index: Some(rb),
                        scale: 1 << shift,
                        disp: 0,
                    },
                    size: if xo == 21 { 8 } else { 4 },
                    signed: xo == 341,
                },
                _ => Note::Clobber(1 << rt),
            }
        }
        // RLWINM rA, rS, sh, mb, me: `slwi` (a scaled copy) and `clrlwi`.
        21 => {
            let (sh, mb, me) = (rb, (word >> 6) & 0x1f, (word >> 1) & 0x1f);
            set(state, ra, None);
            if (1..=3).contains(&sh) && mb == 0 && me == 31 - sh {
                state.scaled = Some((ra, u8::try_from(sh).unwrap_or(0)));
                Note::Copy { reg: ra, src: rt }
            } else if sh == 0 && me == 31 {
                Note::Copy { reg: ra, src: rt }
            } else {
                Note::Clobber(1 << ra)
            }
        }
        // RLDICL, RLDICR, RLDIC rA, rS, sh, m: `clrldi` (a copy), `sldi`
        // and `rldic` (scaled copies).
        30 if (word >> 2) & 7 <= 2 => {
            let sh = rb | (word >> 1 & 1) << 5;
            let m = ((word >> 6) & 0x1f) | (word >> 5 & 1) << 5;
            set(state, ra, None);
            match (word >> 2) & 7 {
                0 if sh == 0 => Note::Copy { reg: ra, src: rt },
                1 | 2 if (1..=3).contains(&sh) && (m == 63 - sh || (word >> 2) & 7 == 2) => {
                    state.scaled = Some((ra, u8::try_from(sh).unwrap_or(0)));
                    Note::Copy { reg: ra, src: rt }
                }
                _ => Note::Clobber(1 << ra),
            }
        }
        // LD rT, ds(rA), LWA rT, ds(rA) and LWZ rT, d(rA): from a slot,
        // when rA holds a fixed address (here, or as far as the tracker
        // knows). musl's start code reads an offset with `lwa`.
        58 | 32 if (word >> 26 == 32 || word & 3 != 1) && ra != 0 => {
            let ld = word >> 26 == 58 && word & 3 == 0;
            let lwa = word >> 26 == 58 && word & 3 == 2;
            let disp = if word >> 26 == 58 { simm & !3 } else { simm };
            if let Some((sum, base, index, shift)) = indexed
                && sum == ra
            {
                clobber(state, 1 << rt);
                return Note::Load {
                    reg: rt,
                    mem: Mem {
                        base: Some(base),
                        index: Some(index),
                        scale: 1 << shift,
                        disp,
                    },
                    size: if ld { 8 } else { 4 },
                    signed: lwa,
                };
            }
            let slot = get(state, ra).map(|base| wrap(base.wrapping_add(disp)));
            clobber(state, 1 << rt);
            state.loaded = slot.map(|slot| (rt, slot));
            let (base, disp) = slot.map_or((Some(ra), disp), |slot| (None, slot));
            Note::Fetch {
                reg: rt,
                mem: Mem {
                    base,
                    index: None,
                    scale: 1,
                    disp,
                },
                size: if ld { 8 } else { 4 },
                signed: lwa,
            }
        }
        // Stores, and their update forms, which write rA.
        36 | 38 | 44 | 47 | 52 | 54 => Note::None,
        37 | 39 | 45 | 53 | 55 => clobber(state, 1 << ra),
        62 if word & 3 == 1 => clobber(state, 1 << ra),
        62 => Note::None,
        // Arithmetic writes rT; logical and rotate instructions rA; the
        // X forms either.
        _ => clobber(state, 1 << rt | 1 << ra),
    };
    // A compare writes only a condition register.
    let written = if matches!(note, Note::Compare { .. }) {
        0
    } else {
        note.writes()
    } | state.indexed.map_or(0, |(sum, ..)| 1 << sum);
    if state.indexed.is_none()
        && let Some((sum, base, index, _)) = indexed
        && written & (1 << sum | 1 << base | 1 << index) == 0
    {
        state.indexed = indexed;
    }
    if state.scaled.is_none()
        && let Some((reg, shift)) = scaled
        && written >> reg & 1 == 0
    {
        state.scaled = Some((reg, shift));
    }
    if state.loaded.is_none()
        && let Some((reg, _)) = loaded
        && written >> reg & 1 == 0
    {
        state.loaded = loaded;
    }
    note
}

/// What the prefixed instruction `prefix`, `suffix` at `addr` leaves in a
/// register: a PC-relative address (`pla rT, f@pcrel`, the `paddi` form
/// with R set), or a load from one (`pld rT, f@got@pcrel`: a GOT slot, as
/// a Power10 PLT stub's `pld r12; mtctr r12; bctr` reads).
fn prefixed(state: &mut State, prefix: u32, suffix: u32, addr: u64) -> Note {
    let (kind, relative) = ((prefix >> 24) & 3, prefix >> 20 & 1 != 0);
    let (opcode, rt, ra) = (suffix >> 26, (suffix >> 21) & 0x1f, (suffix >> 16) & 0x1f);
    // The 34-bit immediate: 18 bits in the prefix, 16 in the suffix.
    let imm = (i64::from(prefix & 0x3_ffff) << 16 | i64::from(suffix & 0xffff)) << 30 >> 30;
    let target = (relative && ra == 0).then(|| addr.wrapping_add_signed(imm));
    state.loaded = None;
    match (kind, opcode, target) {
        // PADDI (MLS:D-form): `pla`, `pli`.
        (2, 14, Some(addr)) => {
            if let Some(slot) = state.regs.get_mut(rt as usize) {
                *slot = Some(addr);
            }
            Note::Address { reg: rt, addr }
        }
        // PLD (8LS:D-form), PLWZ (MLS:D-form).
        (0, 57, Some(slot)) | (2, 32, Some(slot)) => {
            let note = Note::Fetch {
                reg: rt,
                mem: Mem {
                    base: None,
                    index: None,
                    scale: 1,
                    disp: slot,
                },
                size: if opcode == 57 { 8 } else { 4 },
                signed: false,
            };
            clobber(state, 1 << rt);
            state.loaded = Some((rt, slot));
            note
        }
        // Prefixed stores write no register.
        (0, 61 | 62 | 54 | 60, _) | (2, 36 | 38 | 44 | 52 | 54, _) => Note::None,
        _ => clobber(state, 1 << rt),
    }
}

/// Forget the registers in `mask`.
fn clobber(state: &mut State, mask: u32) -> Note {
    for (reg, value) in state.regs.iter_mut().enumerate() {
        if mask >> reg & 1 != 0 {
            *value = None;
        }
    }
    Note::Clobber(mask)
}

/// Whether `bytes` begin a frame: `mflr r0`, which saves the return
/// address, or the stack update (`stwu r1, -n(r1)`, `stdu r1, -n(r1)`),
/// among the first three instructions.
pub(crate) fn starts_frame(big: bool, bytes: &[u8]) -> bool {
    (0..3).any(|i| {
        bytes
            .get(i * 4..)
            .and_then(|rest| read_word(big, rest))
            .is_some_and(|word| {
                word == 0x7c08_02a6
                    || (word & 0xffff_8000 == 0x9421_8000)
                    || (word & 0xffff_8003 == 0xf821_8001)
            })
    })
}

/// Whether `bytes`, eight bytes before a function's local entry, are the
/// global entry of 64-bit ELFv2 code: `addis r2, r12, ...; addi r2, r2,
/// ...`, which sets the TOC pointer from the entry's own address, as
/// callers from another module enter. Calls from within skip it.
pub(crate) fn global_entry(big: bool, bytes: &[u8]) -> bool {
    let (Some(first), Some(second)) = (
        read_word(big, bytes),
        bytes.get(4..).and_then(|rest| read_word(big, rest)),
    ) else {
        return false;
    };
    first & 0xffff_0000 == 0x3c4c_0000 && second & 0xffff_0000 == 0x3842_0000
}

fn read_word(big: bool, bytes: &[u8]) -> Option<u32> {
    let bytes: [u8; 4] = bytes.get(..4)?.try_into().ok()?;
    Some(if big {
        u32::from_be_bytes(bytes)
    } else {
        u32::from_le_bytes(bytes)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The flows of `words` at `addr` on, big-endian and 64-bit.
    fn run(words: &[u32], addr: u64) -> Vec<Insn> {
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_be_bytes()).collect();
        let mut state = State::default();
        (0..words.len())
            .map(|i| {
                decode(
                    &mut state,
                    (true, true, None),
                    &bytes[i * 4..],
                    addr + i as u64 * 4,
                )
            })
            .collect()
    }

    #[test]
    fn transfers() {
        let insns = run(
            &[
                0x4800_0010, // b +0x10
                0x4bff_fff1, // bl -0x10
                0x4182_0008, // beq +8
                0x4e80_0020, // blr
                0x4d82_0020, // beqlr
                0x4e80_0021, // blrl
                0x4e80_0421, // bctrl
                0x7fe0_0008, // trap
                0x429f_0005, // bcl 20, 31, $+4 (at 0x1020)
                0x4200_fff0, // bdnz -0x10
                0x6000_0000, // nop
                0,
            ],
            0x1000,
        );
        let flows: Vec<Flow> = insns.iter().map(|insn| insn.flow).collect();
        assert_eq!(
            flows,
            [
                Flow::Jump(0x1010),
                Flow::Call(0x0ff4),
                Flow::Branch(0x1010),
                Flow::Return,
                Flow::Return,
                Flow::CallIndirect,
                Flow::CallRegister(CTR),
                Flow::Stop,
                Flow::Next,
                Flow::Branch(0x1014),
                Flow::Next,
                Flow::Stop,
            ]
        );
        assert!(!insns[3].falls && insns[4].falls && insns[10].pad);
    }

    #[test]
    fn jumps_through_ctr() {
        // mtctr r9; bctr
        let insns = run(&[0x7d29_03a6, 0x4e80_0420], 0x1000);
        assert_eq!(insns[0].note, Note::Copy { reg: CTR, src: 9 });
        assert_eq!(insns[1].flow, Flow::JumpRegister(CTR));
        // bctrl
        assert_eq!(run(&[0x4e80_0421], 0x1000)[0].flow, Flow::CallRegister(CTR));
        // bcl 20, 31, $+8 over a word of data: a jump past it; bl, too.
        assert_eq!(run(&[0x429f_0009], 0x1000)[0].flow, Flow::Jump(0x1008));
        assert_eq!(run(&[0x4800_0009], 0x1000)[0].flow, Flow::Jump(0x1008));
    }

    #[test]
    fn plt_stubs() {
        // ELFv1: std r2, 40(r1); ld r12, -0x7df8(r2); mtctr r12;
        // ld r2, -0x7df0(r2); cmpldi r2, 0; bnectr
        let words = [
            0xf841_0028_u32,
            0xe982_8208,
            0x7d89_03a6,
            0xe842_8210,
            0x2822_0000,
            0x4c82_0420,
        ];
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_be_bytes()).collect();
        let mut state = State::default();
        let insns: Vec<Insn> = (0..words.len())
            .map(|i| {
                decode(
                    &mut state,
                    (true, true, Some(0x1002_7f00)),
                    &bytes[i * 4..],
                    0x1000_0e60 + i as u64 * 4,
                )
            })
            .collect();
        assert_eq!(insns[5].flow, Flow::JumpSlot(0x1002_0108));
        assert!(insns[5].falls);
        // 32-bit: lis r11, 0x1002; lwz r11, 0x108(r11); mtctr r11; bctr
        let insns = run(
            &[0x3d60_1002, 0x816b_0108, 0x7d69_03a6, 0x4e80_0420],
            0x1000,
        );
        assert_eq!(insns[3].flow, Flow::JumpSlot(0x1002_0108));
        // A load whose register is then overwritten is no slot: lwz r11,
        // 0x108(r11); addi r11, r11, 4; mtctr r11; bctrl
        let insns = run(
            &[
                0x3d60_1002,
                0x816b_0108,
                0x396b_0004,
                0x7d69_03a6,
                0x4e80_0421,
            ],
            0x1000,
        );
        assert_eq!(insns[4].flow, Flow::CallRegister(CTR));
    }

    #[test]
    fn prefixed() {
        // pld r12, 0x2000(0), 1 (`f@got@pcrel`); mtctr r12; bctr: a Power10
        // PLT stub.
        let words = [0x0410_0000_u32, 0xe580_2000, 0x7d89_03a6, 0x4e80_0420];
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_be_bytes()).collect();
        let mut state = State::default();
        let mut at = 0;
        let mut insns = Vec::new();
        while at < bytes.len() {
            let insn = decode(
                &mut state,
                (true, true, None),
                &bytes[at..],
                0x1000 + at as u64,
            );
            at += insn.len as usize;
            insns.push(insn);
        }
        assert_eq!(insns[0].len, 8);
        assert_eq!(insns.len(), 3);
        assert_eq!(insns[2].flow, Flow::JumpSlot(0x3000));
        // pla r3, -0x10 (prefix 0x0613ffff, suffix 0x3860fff0): an address
        // behind the instruction.
        let insns = run(&[0x0613_ffff, 0x3860_fff0], 0x1000);
        assert_eq!(
            insns[0].note,
            Note::Address {
                reg: 3,
                addr: 0xff0
            }
        );
        // A prefix cut short does not decode.
        assert_eq!(run(&[0x0410_0000], 0x1000)[0].flow, Flow::Invalid);
    }

    #[test]
    fn addresses() {
        // lis r9, 0x1000; addi r9, r9, 0xe3c: 32-bit code's address of f.
        let bytes: Vec<u8> = [0x3d20_1000_u32, 0x3929_0e3c, 0x3929_8000]
            .iter()
            .flat_map(|w| w.to_be_bytes())
            .collect();
        let mut state = State::default();
        let notes: Vec<Note> = (0..3)
            .map(|i| {
                decode(
                    &mut state,
                    (true, false, None),
                    &bytes[i * 4..],
                    0x1000 + i as u64 * 4,
                )
                .note
            })
            .collect();
        assert_eq!(notes[0], Note::Clobber(1 << 9));
        assert_eq!(
            notes[1],
            Note::Address {
                reg: 9,
                addr: 0x1000_0e3c
            }
        );
        // addi with a negative immediate: 0x10000e3c - 0x8000.
        assert_eq!(
            notes[2],
            Note::Address {
                reg: 9,
                addr: 0x0fff_8e3c
            }
        );
    }

    #[test]
    fn switch_notes() {
        // GCC's 64-bit table read, the TOC pointer at 0x1001_8000.
        let code = [
            0x2b89_0009_u32, // cmplwi cr7, r9, 9
            0x3d42_ffff,     // addis r10, r2, -1
            0x7929_1764,     // sldi r9, r9, 2 (rldicr r9, r9, 2, 61)
            0x394a_0100,     // addi r10, r10, 0x100
            0x7d2a_4aaa,     // lwax r9, r10, r9
            0x7d29_5214,     // add r9, r9, r10
            0x7d29_03a6,     // mtctr r9
            0x4e80_0420,     // bctr
        ];
        let bytes: Vec<u8> = code.iter().flat_map(|w| w.to_le_bytes()).collect();
        let mut state = State::default();
        let insns: Vec<Insn> = (0..code.len())
            .map(|i| {
                decode(
                    &mut state,
                    (false, true, Some(0x1001_8000)),
                    &bytes[i * 4..],
                    0x1000 + i as u64 * 4,
                )
            })
            .collect();
        assert_eq!(insns[0].note, Note::Compare { reg: 9, imm: 9 });
        assert_eq!(insns[2].note, Note::Copy { reg: 9, src: 9 });
        assert_eq!(
            insns[3].note,
            Note::Address {
                reg: 10,
                addr: 0x1000_8100
            }
        );
        assert_eq!(
            insns[4].note,
            Note::Load {
                reg: 9,
                mem: Mem {
                    base: Some(10),
                    index: Some(9),
                    scale: 4,
                    disp: 0
                },
                size: 4,
                signed: true
            }
        );
        assert_eq!(
            insns[5].note,
            Note::Add {
                reg: 9,
                base: 9,
                index: 10,
                shift: 0,
                extend: Extend::None
            }
        );
        assert_eq!(insns[6].note, Note::Copy { reg: CTR, src: 9 });
        assert_eq!(insns[7].flow, Flow::JumpRegister(CTR));
    }

    #[test]
    fn global_entries() {
        let bytes: Vec<u8> = [0x3c4c_0002_u32, 0x3842_8000]
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect();
        assert!(global_entry(false, &bytes));
        assert!(!global_entry(true, &bytes));
    }

    #[test]
    fn frames() {
        // mflr r0; stwu r1, -32(r1)
        assert!(starts_frame(true, &[0x7c, 0x08, 0x02, 0xa6]));
        assert!(starts_frame(true, &[0x60, 0, 0, 0, 0x94, 0x21, 0xff, 0xe0]));
        // stdu r1, -112(r1)
        assert!(starts_frame(true, &[0xf8, 0x21, 0xff, 0x91]));
        // blr
        assert!(!starts_frame(true, &[0x4e, 0x80, 0x00, 0x20]));
    }
}
