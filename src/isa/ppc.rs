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

use crate::isa::{Extend, Flow, Indexed, Insn, Mem, Memory, Note, Pending, Regs, sext, u32_at};

/// The PowerPC decoder: its byte order, word size, and the TOC pointer
/// 64-bit code keeps in `r2`, and what earlier instructions left.
#[derive(Clone, Debug)]
pub(crate) struct Decoder {
    big: bool,
    wide: bool,
    toc: Option<u64>,
    state: State,
}

/// What earlier instructions left that a later one needs.
#[derive(Clone, Copy, Debug, Default)]
struct State {
    /// The slot `ctr`'s value was loaded from: a PLT stub's (`ld r12,
    /// n(r2); mtctr r12; bctr`).
    ctr_slot: Option<u64>,
    /// The address in `lr`, after `bcl 20, 31, $+4`.
    lr: Option<u64>,
    /// The constant in each register.
    regs: Regs<u64, 32>,
    /// What only the next few instructions use: a scaled case value
    /// (`slwi r6, r6, 2`), a base plus one (`add r6, r27, r6`), the
    /// address a table entry is then loaded from at an offset (`lwz r10,
    /// 0x280(r6)`).
    pending: Pending,
}

/// The registers a call may change: r0 and r3-r12.
const VOLATILE: u64 = 0x1ff9;

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

impl Decoder {
    pub(crate) fn new(big: bool, wide: bool, toc: Option<u64>) -> Self {
        Self {
            big,
            wide,
            toc,
            state: State::default(),
        }
    }

    /// `value` cut to the word size.
    const fn wrap(&self, value: u64) -> u64 {
        if self.wide {
            value
        } else {
            value & 0xffff_ffff
        }
    }

    /// The word at `bytes[at..]`.
    fn word(&self, bytes: &[u8], at: usize) -> Option<u32> {
        u32_at(bytes, at, self.big)
    }

    /// The constant in `reg`: in 64-bit code, `r2` holds the TOC pointer.
    fn get(&self, reg: u32) -> Option<u64> {
        match (reg, self.toc) {
            (2, Some(toc)) if self.wide => Some(toc),
            _ => self.state.regs.get(reg),
        }
    }

    /// Forget the registers in `mask`.
    fn clobber(&mut self, mask: u32) -> Note {
        self.state.regs.forget(u64::from(mask));
        Note::Clobber(mask)
    }

    /// What `word`, which transfers nowhere, leaves in `ctr` and the other
    /// registers, as a note: an address it completes (`lis; addi`, or an
    /// offset from the TOC pointer, `addis r10, r2, ...; addi r10, r10,
    /// ...`), or a step of GCC's jump-table read (`cmplwi; sldi; lwax; add;
    /// mtctr; bctr`).
    fn track(&mut self, word: u32) -> Note {
        let (rt, ra, rb) = (
            (word >> 21) & 0x1f,
            (word >> 16) & 0x1f,
            (word >> 11) & 0x1f,
        );
        let xo = (word >> 1) & 0x3ff;
        // MTSPR ctr, rS (`mtctr rS`): SPR 9, its halves swapped in the field.
        if word & 0xfc1f_fffe == 0x7c09_03a6 {
            self.state.ctr_slot = self
                .state
                .pending
                .loaded
                .filter(|&(reg, _)| reg == rt)
                .map(|(_, slot)| slot);
            return Note::Copy { reg: CTR, src: rt };
        }
        // MFSPR rT, lr (`mflr rT`): the PC, after `bcl`. MTSPR lr, rS.
        if word & 0xfc1f_fffe == 0x7c08_02a6 {
            let value = self.state.lr;
            self.state.regs.set(rt, value);
            self.state.pending.loaded = self.state.pending.loaded.filter(|&(reg, _)| reg != rt);
            return value.map_or(Note::Copy { reg: rt, src: LR }, |value| Note::Value {
                reg: rt,
                value,
            });
        }
        if word & 0xfc1f_fffe == 0x7c08_03a6 {
            self.state.lr = None;
            return Note::Copy { reg: LR, src: rt };
        }
        let imm = u64::from(word & 0xffff);
        let simm = sext(word & 0xffff, 16).cast_unsigned();
        let before = std::mem::take(&mut self.state.pending);
        let Pending {
            scaled, indexed, ..
        } = before;
        let note = match word >> 26 {
            // ADDI, ADDIS: an address when they complete a constant in rA;
            // `li`, `lis` (rA zero) and any high half alone are integers.
            14 | 15 => {
                let high = word >> 26 == 15;
                let add = if high { simm << 16 } else { simm };
                let base = if ra == 0 { Some(0) } else { self.get(ra) };
                let value = base.map(|base| self.wrap(base.wrapping_add(add)));
                self.state.regs.set(rt, value);
                match value {
                    Some(addr) if !high && ra != 0 => Note::Address { reg: rt, addr },
                    Some(value) => Note::Value { reg: rt, value },
                    // The tracker may know the base the decoder lost: the PIC
                    // register, set at the function's start.
                    None => Note::Offset {
                        reg: rt,
                        src: ra,
                        imm: self.wrap(add),
                    },
                }
            }
            // ORI, ORIS rA, rS, imm: the low half completes an address.
            24 | 25 => {
                let or = if word >> 26 == 25 { imm << 16 } else { imm };
                let value = self.get(rt).map(|value| value | or);
                self.state.regs.set(ra, value);
                match value {
                    Some(addr) if word >> 26 == 24 => Note::Address { reg: ra, addr },
                    Some(value) => Note::Value { reg: ra, value },
                    None => Note::Clobber(1 << ra),
                }
            }
            // CMPLI crN, L, rA, imm (`cmplwi`, `cmpldi`): the bound on a case
            // value. CMPI and CMP, CMPL write only a condition register.
            10 => Note::Compare { reg: ra, imm },
            11 => Note::None,
            31 if matches!(xo, 0 | 32) => Note::None,
            // OR rA, rS, rS (`mr`)
            31 if xo == 444 && rt == rb => {
                self.state.regs.set(ra, self.get(rt));
                Note::Copy { reg: ra, src: rt }
            }
            // ADD rT, rA, rB: a base plus a scaled case value, which a load
            // reads through, or a table's entry plus its base.
            31 if xo & 0x1ff == 266 => {
                self.state.regs.set(rt, None);
                if let Some((reg, shift)) = scaled
                    && (reg == ra || reg == rb)
                {
                    let base = if reg == rb { ra } else { rb };
                    self.state.pending.indexed = Some(Indexed {
                        sum: rt,
                        base,
                        index: reg,
                        shift,
                    });
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
                self.state.regs.set(rt, None);
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
                self.state.regs.set(rt, None);
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
                self.state.regs.set(ra, None);
                if (1..=3).contains(&sh) && mb == 0 && me == 31_u32.wrapping_sub(sh) {
                    self.state.pending.scaled = Some((ra, u8::try_from(sh).unwrap_or(0)));
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
                self.state.regs.set(ra, None);
                match (word >> 2) & 7 {
                    0 if sh == 0 => Note::Copy { reg: ra, src: rt },
                    1 | 2
                        if (1..=3).contains(&sh)
                            && (m == 63_u32.wrapping_sub(sh) || (word >> 2) & 7 == 2) =>
                    {
                        self.state.pending.scaled = Some((ra, u8::try_from(sh).unwrap_or(0)));
                        Note::Copy { reg: ra, src: rt }
                    }
                    _ => Note::Clobber(1 << ra),
                }
            }
            // LD rT, ds(rA), LWA rT, ds(rA) and LWZ rT, d(rA): from a slot,
            // when rA holds a fixed address (here, or as far as the tracker
            // knows). Start code may read an offset with `lwa`.
            58 | 32 if (word >> 26 == 32 || word & 3 != 1) && ra != 0 => {
                let ld = word >> 26 == 58 && word & 3 == 0;
                let lwa = word >> 26 == 58 && word & 3 == 2;
                let disp = if word >> 26 == 58 { simm & !3 } else { simm };
                let size = if ld { 8 } else { 4 };
                if let Some(Indexed {
                    sum,
                    base,
                    index,
                    shift,
                }) = indexed
                    && sum == ra
                {
                    self.clobber(1 << rt);
                    return Note::Load {
                        reg: rt,
                        mem: Mem {
                            base: Some(base),
                            index: Some(index),
                            scale: 1 << shift,
                            disp,
                        },
                        size,
                        signed: lwa,
                    };
                }
                let slot = self.get(ra).map(|base| self.wrap(base.wrapping_add(disp)));
                self.clobber(1 << rt);
                self.state.pending.loaded = slot.map(|slot| (rt, slot));
                let (base, disp) = slot.map_or((Some(ra), disp), |slot| (None, slot));
                Note::Fetch {
                    reg: rt,
                    mem: Mem {
                        base,
                        index: None,
                        scale: 1,
                        disp,
                    },
                    size,
                    signed: lwa,
                }
            }
            // Stores, and their update forms, which write rA.
            36 | 38 | 44 | 47 | 52 | 54 => Note::None,
            37 | 39 | 45 | 53 | 55 => self.clobber(1 << ra),
            62 if word & 3 == 1 => self.clobber(1 << ra),
            62 => Note::None,
            // Arithmetic writes rT; logical and rotate instructions rA; the
            // X forms either.
            _ => self.clobber(1 << rt | 1 << ra),
        };
        // What the instruction left before it is kept, unless it wrote a
        // register that holds it. A compare writes only a condition
        // register.
        let written = self.state.pending.written(note);
        self.state.pending.keep(before, written);
        note
    }

    /// What the prefixed instruction `prefix`, `suffix` at `addr` leaves in
    /// a register: a PC-relative address (`pla rT, f@pcrel`, the `paddi`
    /// form with R set), or a load from one (`pld rT, f@got@pcrel`: a GOT
    /// slot, as a Power10 PLT stub's `pld r12; mtctr r12; bctr` reads).
    fn prefixed(&mut self, prefix: u32, suffix: u32, addr: u64) -> Note {
        let (kind, relative) = ((prefix >> 24) & 3, prefix >> 20 & 1 != 0);
        let (opcode, rt, ra) = (suffix >> 26, (suffix >> 21) & 0x1f, (suffix >> 16) & 0x1f);
        // The 34-bit immediate: 18 bits in the prefix, 16 in the suffix.
        let imm = sext(
            u64::from(prefix & 0x3_ffff) << 16 | u64::from(suffix & 0xffff),
            34,
        );
        let target = (relative && ra == 0).then(|| addr.wrapping_add_signed(imm));
        self.state.pending.loaded = None;
        match (kind, opcode, target) {
            // PADDI (MLS:D-form): `pla`, `pli`.
            (2, 14, Some(addr)) => {
                self.state.regs.set(rt, Some(addr));
                Note::Address { reg: rt, addr }
            }
            // PLD (8LS:D-form), PLWZ (MLS:D-form).
            (0, 57, Some(slot)) | (2, 32, Some(slot)) => {
                self.clobber(1 << rt);
                self.state.pending.loaded = Some((rt, slot));
                Note::Fetch {
                    reg: rt,
                    mem: Mem {
                        base: None,
                        index: None,
                        scale: 1,
                        disp: slot,
                    },
                    size: if opcode == 57 { 8 } else { 4 },
                    signed: false,
                }
            }
            // Prefixed stores write no register.
            (0, 61 | 62 | 54 | 60, _) | (2, 36 | 38 | 44 | 52 | 54, _) => Note::None,
            _ => self.clobber(1 << rt),
        }
    }
}

impl crate::isa::Decode for Decoder {
    fn decode(&mut self, bytes: &[u8], addr: u64) -> Insn {
        let Some(word) = self.word(bytes, 0) else {
            return Insn::new(4, Flow::Invalid);
        };
        // Power10's prefixed instructions: a prefix word, then the
        // instruction it extends. None transfers control.
        if word >> 26 == 1 {
            let Some(suffix) = self.word(bytes, 4) else {
                return Insn::new(4, Flow::Invalid);
            };
            return Insn::note(8, self.prefixed(word, suffix, addr));
        }
        let link = word & 1 != 0;
        let absolute = word & 2 != 0;
        let next = self.wrap(addr.wrapping_add(4));
        // BO: bits 0x14 set branch whatever the condition and count.
        let always = (word >> 21) & 0x14 == 0x14;
        let to = |field: u32, bits: u32| {
            let offset = sext(field, bits);
            self.wrap(if absolute {
                offset.cast_unsigned()
            } else {
                addr.wrapping_add_signed(offset)
            })
        };
        let (flow, falls) = match word >> 26 {
            // Zero, an illegal instruction: the traceback table GCC puts
            // after each 64-bit function starts with it, so a path reaches it
            // past a call that never returns.
            0 if word == 0 => (Flow::Stop, false),
            0 => (Flow::Invalid, false),
            // B, BA, BL, BLA. A `bl` just past one word of data reads the PC
            // and jumps over it (`bl 1f; .long _DYNAMIC - .; 1:`); one
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
                    self.state
                        .ctr_slot
                        .map_or(Flow::CallRegister(CTR), Flow::CallSlot),
                    false,
                ),
                528 => (
                    self.state
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
        let note = match flow {
            // `bcl 20, 31, $+4` leaves its own address in `lr`.
            Flow::Next if word >> 26 == 16 => {
                self.state.lr = Some(next);
                Note::Value {
                    reg: LR,
                    value: next,
                }
            }
            // So does a `bl` or `bcl` over data, for the block past it.
            Flow::Jump(_) if link => Note::Value {
                reg: LR,
                value: next,
            },
            Flow::Next => self.track(word),
            _ => Note::None,
        };
        Insn {
            note,
            pad: word == NOP,
            falls,
            ..Insn::new(4, flow)
        }
    }

    fn reset(&mut self) {
        self.state = State::default();
    }

    /// A callee may change ctr, lr and the volatile registers.
    fn call(&mut self) {
        let state = &mut self.state;
        state.ctr_slot = None;
        state.pending = Pending::default();
        state.lr = None;
        state.regs.forget(VOLATILE);
    }

    /// `mflr r0`, which saves the return address, or the stack update
    /// (`stwu r1, -n(r1)`, `stdu r1, -n(r1)`), among the first three
    /// instructions.
    fn starts_frame(&self, bytes: &[u8]) -> bool {
        [0, 4, 8].into_iter().any(|at| {
            self.word(bytes, at).is_some_and(|word| {
                word == 0x7c08_02a6
                    || (word & 0xffff_8000 == 0x9421_8000)
                    || (word & 0xffff_8003 == 0xf821_8001)
            })
        })
    }

    fn entry_of(&self, bytes: &[u8], addr: u64) -> Option<u64> {
        (self.wide && global_entry(self.big, bytes)).then_some(addr)
    }

    fn global_entry(&self, addr: u64, memory: &Memory<'_>) -> u64 {
        let start = addr.checked_sub(GLOBAL_ENTRY).filter(|_| self.wide);
        match start.and_then(|start| Some((start, memory.code(start)?))) {
            Some((start, before)) if global_entry(self.big, before) => start,
            _ => addr,
        }
    }
}

/// How far before a 64-bit ELFv2 function's local entry its global entry
/// sits: the two instructions that set up the TOC pointer.
const GLOBAL_ENTRY: u64 = 8;

/// Whether `bytes`, eight bytes before a function's local entry, are the
/// global entry of 64-bit ELFv2 code: `addis r2, r12, ...; addi r2, r2,
/// ...`, which sets the TOC pointer from the entry's own address, as
/// callers from another module enter. Calls from within skip it.
fn global_entry(big: bool, bytes: &[u8]) -> bool {
    let (Some(first), Some(second)) = (u32_at(bytes, 0, big), u32_at(bytes, 4, big)) else {
        return false;
    };
    first & 0xffff_0000 == 0x3c4c_0000 && second & 0xffff_0000 == 0x3842_0000
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isa::Decode;

    /// The instructions `words`, stored in `big` order, decoded from `addr`
    /// on, all of them, prefixed or not.
    fn decode_all(decoder: &mut Decoder, words: &[u32], addr: u64) -> Vec<Insn> {
        let bytes: Vec<u8> = words
            .iter()
            .flat_map(|&w| {
                if decoder.big {
                    w.to_be_bytes()
                } else {
                    w.to_le_bytes()
                }
            })
            .collect();
        let mut at = 0;
        let mut insns = Vec::new();
        while at < bytes.len() {
            let insn = decoder.decode(&bytes[at..], addr + at as u64);
            at += insn.len as usize;
            insns.push(insn);
        }
        insns
    }

    /// The instructions of `words` at `addr` on, big-endian and 64-bit.
    fn run(words: &[u32], addr: u64) -> Vec<Insn> {
        decode_all(&mut Decoder::new(true, true, None), words, addr)
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
        assert_eq!(
            insns[8].note,
            Note::Value {
                reg: LR,
                value: 0x1024
            }
        );
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
        let mut decoder = Decoder::new(true, true, Some(0x1002_7f00));
        let insns = decode_all(&mut decoder, &words, 0x1000_0e60);
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
        let insns = run(
            &[0x0410_0000_u32, 0xe580_2000, 0x7d89_03a6, 0x4e80_0420],
            0x1000,
        );
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
        // Then addi with a negative immediate: 0x10000e3c - 0x8000.
        let mut decoder = Decoder::new(true, false, None);
        let words = [0x3d20_1000_u32, 0x3929_0e3c, 0x3929_8000];
        let notes: Vec<Note> = decode_all(&mut decoder, &words, 0x1000)
            .iter()
            .map(|insn| insn.note)
            .collect();
        assert_eq!(
            notes,
            [
                // The high half is no address by itself.
                Note::Value {
                    reg: 9,
                    value: 0x1000_0000
                },
                Note::Address {
                    reg: 9,
                    addr: 0x1000_0e3c
                },
                Note::Address {
                    reg: 9,
                    addr: 0x0fff_8e3c
                },
            ]
        );
        // li r3, 5: an integer.
        assert_eq!(
            run(&[0x3860_0005], 0)[0].note,
            Note::Value { reg: 3, value: 5 }
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
        let mut decoder = Decoder::new(false, true, Some(0x1001_8000));
        let insns = decode_all(&mut decoder, &code, 0x1000);
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

    /// A call forgets ctr's slot and the volatile registers, and keeps the
    /// rest.
    #[test]
    fn calls_forget_volatile_registers() {
        // lis r3, 0x10; lis r30, 0x20
        let mut decoder = Decoder::new(true, false, None);
        decode_all(&mut decoder, &[0x3c60_0010, 0x3fc0_0020], 0);
        decoder.call();
        assert_eq!((decoder.get(3), decoder.get(30)), (None, Some(0x20_0000)));
    }

    #[test]
    fn global_entries() {
        let bytes: Vec<u8> = [0x3c4c_0002_u32, 0x3842_8000]
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect();
        assert!(global_entry(false, &bytes));
        assert!(!global_entry(true, &bytes));
        let decoder = Decoder::new(false, true, None);
        assert_eq!(decoder.entry_of(&bytes, 0x100), Some(0x100));
        let segments = [crate::Segment {
            addr: 0x100,
            bytes: bytes.as_slice().into(),
            executable: true,
        }];
        let memory = Memory::for_arch(&segments, crate::Arch::PowerPc64El);
        assert_eq!(Decode::global_entry(&decoder, 0x108, &memory), 0x100);
        assert_eq!(Decode::global_entry(&decoder, 0x104, &memory), 0x104);
    }

    #[test]
    fn frames() {
        let decoder = Decoder::new(true, true, None);
        // mflr r0; stwu r1, -32(r1)
        assert!(decoder.starts_frame(&[0x7c, 0x08, 0x02, 0xa6]));
        assert!(decoder.starts_frame(&[0x60, 0, 0, 0, 0x94, 0x21, 0xff, 0xe0]));
        // stdu r1, -112(r1)
        assert!(decoder.starts_frame(&[0xf8, 0x21, 0xff, 0x91]));
        // blr
        assert!(!decoder.starts_frame(&[0x4e, 0x80, 0x00, 0x20]));
    }
}
