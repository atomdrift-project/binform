//! LoongArch (LA64): control flow only. Instructions are 32 bits,
//! little-endian, with no delay slots.
//!
//! Transfers are `b`, `bl` (which links `ra`), the conditional branches,
//! and `jirl rd, rj, offs` through a register: `jr ra` returns, and `jirl`
//! linking `ra` calls. A call beyond `bl`'s 128 MB is `pcaddu18i ra, hi;
//! jirl ra, ra, lo` (and a far tail call `pcaddu18i t8, hi; jr lo(t8)`):
//! the decoder keeps the constants `pcaddi`, `pcalau12i`, `pcaddu12i`,
//! `pcaddu18i`, `lu12i.w`, `lu32i.d`, `lu52i.d`, `ori` and `addi` leave in
//! registers, so such pairs read as direct calls and jumps. An import stub
//! loads its slot PC-relative and jumps through it (`pcaddu12i t3, hi;
//! ld.d t3, t3, lo; jirl t1, t3, 0`), as does a call through the GOT
//! (`pcalau12i t0, hi; ld.d t0, t0, lo; jirl ra, t0, 0`).
//!
//! Jump tables bound the case value with an unsigned compare against a
//! constant (`ori a2, zero, 19; bltu a2, a0, default`), scale it (`slli.d`,
//! or `alsl.d` to scale and add at once), and load the entry, absolute
//! (GCC: `alsl.d t1, t0, s2, 3; ldptr.d t1, t1, 0; jr t1`) or relative to
//! the table (LLVM: `ldx.w a0, a2, a0; add.d a0, a2, a0; jr a0`).

use crate::isa::{Decode, Extend, Flow, Insn, Mem, Note, Regs, relative, sext, u32_at};

/// What earlier instructions left that a later one needs.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct State {
    /// The constant in each register.
    regs: Regs<u64, 32>,
    /// What only the next few instructions use.
    pending: Pending,
}

/// What an instruction leaves for the ones right after it, until one
/// overwrites a register it names.
#[derive(Clone, Copy, Debug, Default)]
struct Pending {
    /// A register holding another shifted left, and by how much.
    scaled: Option<(u32, u8)>,
    /// A register holding a base plus a scaled register, which a load then
    /// reads through.
    indexed: Option<Indexed>,
    /// The last register loaded from a fixed address, and that address.
    loaded: Option<(u32, u64)>,
}

/// `sum = base + (index << shift)`.
#[derive(Clone, Copy, Debug)]
struct Indexed {
    sum: u32,
    base: u32,
    index: u32,
    shift: u8,
}

/// `ra`, the return address register.
const RA: u32 = 1;

/// The registers a call may change: `ra`, `a0`-`a7`, `t0`-`t8`.
const VOLATILE: u32 = 0x001f_fff2;

/// `nop` (`andi zero, zero, 0`).
const NOP: u32 = 0x0340_0000;

fn word_at(bytes: &[u8], at: usize) -> Option<u32> {
    u32_at(bytes, at, false)
}

pub(crate) fn decode(state: &mut State, bytes: &[u8], addr: u64) -> Insn {
    let Some(word) = word_at(bytes, 0) else {
        return Insn::new(4, Flow::Invalid);
    };
    let (flow, note) = Cx { state, addr }.decode(word);
    Insn {
        note,
        pad: word == NOP,
        ..Insn::new(4, flow)
    }
}

/// The LA64 decoder.
#[derive(Clone, Debug, Default)]
pub(crate) struct Decoder {
    state: State,
}

impl Decode for Decoder {
    fn decode(&mut self, bytes: &[u8], addr: u64) -> Insn {
        decode(&mut self.state, bytes, addr)
    }

    fn reset(&mut self) {
        self.state = State::default();
    }

    fn call(&mut self) {
        self.state.pending = Pending::default();
        self.state.regs.forget(u64::from(VOLATILE));
    }

    /// The stack pointer lowered (`addi.d sp, sp, -n`) among the first
    /// three instructions.
    fn starts_frame(&self, bytes: &[u8]) -> bool {
        (0..12).step_by(4).any(|at| {
            word_at(bytes, at)
                .is_some_and(|word| word & 0xffc0_03ff == 0x02c0_0063 && word >> 21 & 1 == 1)
        })
    }
}

struct Cx<'a> {
    state: &'a mut State,
    addr: u64,
}

/// The low 32 bits of `value`, sign-extended: what a `.w` operation leaves.
fn word_result(value: u64) -> u64 {
    sext(value, 32).cast_unsigned()
}

impl Cx<'_> {
    /// The constant in `reg`: zero in `zero`.
    fn get(&self, reg: u32) -> Option<u64> {
        if reg == 0 {
            return Some(0);
        }
        self.state.regs.get(reg)
    }

    fn set(&mut self, reg: u32, value: Option<u64>) {
        if reg != 0 {
            self.state.regs.set(reg, value);
        }
    }

    /// `reg` changes some other way.
    fn clobber(&mut self, reg: u32) -> Note {
        if reg == 0 {
            return Note::None;
        }
        self.set(reg, None);
        Note::Clobber(1 << reg)
    }

    /// `rd = value`, a constant.
    fn constant(&mut self, rd: u32, value: u64) -> Note {
        if rd == 0 {
            return Note::None;
        }
        self.set(rd, Some(value));
        Note::Address {
            reg: rd,
            addr: value,
        }
    }

    /// `rd = value`, an integer that is no pointer by itself: an
    /// immediate, the high part of an address a later instruction
    /// completes, or the PC.
    fn value(&mut self, rd: u32, value: u64) -> Note {
        match self.constant(rd, value) {
            Note::Address { reg, addr } => Note::Value { reg, value: addr },
            note => note,
        }
    }

    /// `rd = f(rj)`, a constant when `rj` holds one.
    fn derive(&mut self, rd: u32, rj: u32, f: impl Fn(u64) -> u64) -> Note {
        match self.get(rj) {
            Some(value) if rj == 0 => self.value(rd, f(value)),
            Some(value) => self.constant(rd, f(value)),
            None => self.clobber(rd),
        }
    }

    /// `rd = rj + imm` (`addi.d`, `addi.w` when `word`, `addu16i.d`).
    fn add_imm(&mut self, rd: u32, rj: u32, imm: i64, word: bool) -> Note {
        if rd == 0 {
            return Note::None;
        }
        if imm == 0 && !word {
            let value = self.get(rj);
            self.set(rd, value);
            if rj == 0 {
                return self.value(rd, 0);
            }
            return Note::Copy { reg: rd, src: rj };
        }
        match self.get(rj) {
            Some(base) => {
                let sum = base.wrapping_add_signed(imm);
                let sum = if word { word_result(sum) } else { sum };
                if rj == 0 {
                    self.value(rd, sum)
                } else {
                    self.constant(rd, sum)
                }
            }
            None if word => self.clobber(rd),
            None => {
                self.set(rd, None);
                Note::Offset {
                    reg: rd,
                    src: rj,
                    imm: imm.cast_unsigned(),
                }
            }
        }
    }

    /// `rd = rj << shift`: a scaled copy, when small.
    fn shift(&mut self, rd: u32, rj: u32, shift: u32) -> Note {
        if rd == 0 {
            return Note::None;
        }
        self.set(rd, None);
        if (1..=3).contains(&shift) {
            self.state.pending.scaled = Some((rd, u8::try_from(shift).unwrap_or(0)));
            Note::Copy { reg: rd, src: rj }
        } else {
            Note::Clobber(1 << rd)
        }
    }

    /// `rd = (index << shift) + base` (`alsl.d`), the address a table entry
    /// is loaded from.
    fn indexed(&mut self, rd: u32, base: u32, index: u32, shift: u8) -> Note {
        if rd == 0 {
            return Note::None;
        }
        self.set(rd, None);
        self.state.pending.indexed = Some(Indexed {
            sum: rd,
            base,
            index,
            shift,
        });
        Note::None
    }

    /// `rd = rj + rk`: a base plus a scaled case value, which a load then
    /// reads through, or a table's entry plus its base.
    fn add(&mut self, rd: u32, rj: u32, rk: u32, scaled: Option<(u32, u8)>) -> Note {
        if rd == 0 {
            return Note::None;
        }
        if let Some((reg, shift)) = scaled
            && (reg == rj || reg == rk)
        {
            let base = if reg == rj { rk } else { rj };
            return self.indexed(rd, base, reg, shift);
        }
        let value = self
            .get(rj)
            .zip(self.get(rk))
            .map(|(a, b)| a.wrapping_add(b));
        if let Some(value) = value {
            return self.constant(rd, value);
        }
        self.set(rd, None);
        if rj == 0 || rk == 0 {
            return Note::Copy {
                reg: rd,
                src: rj | rk,
            };
        }
        Note::Add {
            reg: rd,
            base: rj,
            index: rk,
            shift: 0,
            extend: Extend::None,
        }
    }

    /// A load of `size` bytes into `rd` from `imm(rj)`: a table's entry
    /// through an indexed address, or a slot at a fixed one.
    fn load(
        &mut self,
        rd: u32,
        rj: u32,
        imm: i64,
        (size, signed): (u8, bool),
        indexed: Option<Indexed>,
    ) -> Note {
        if rd == 0 {
            return Note::None;
        }
        let base_value = self.get(rj);
        self.set(rd, None);
        if let Some(Indexed {
            sum,
            base,
            index,
            shift,
        }) = indexed
            && sum == rj
        {
            return Note::Load {
                reg: rd,
                mem: Mem {
                    base: Some(base),
                    index: Some(index),
                    scale: 1 << shift,
                    disp: imm.cast_unsigned(),
                },
                size,
                signed,
            };
        }
        if !matches!(size, 4 | 8) {
            return Note::Clobber(1 << rd);
        }
        let slot = base_value.map(|base| base.wrapping_add_signed(imm));
        self.state.pending.loaded = slot.map(|slot| (rd, slot));
        let (base, disp) = slot.map_or((Some(rj), imm.cast_unsigned()), |slot| (None, slot));
        Note::Fetch {
            reg: rd,
            mem: Mem {
                base,
                index: None,
                scale: 1,
                disp,
            },
            size,
            signed,
        }
    }

    /// `ldx rd, rj, rk`: an entry of a table at `rj` (or `rk`) indexed by
    /// the other, scaled when an earlier shift scaled it.
    fn load_indexed(
        &mut self,
        rd: u32,
        (rj, rk): (u32, u32),
        shape: (u8, bool),
        scaled: Option<(u32, u8)>,
    ) -> Note {
        if rd == 0 {
            return Note::None;
        }
        self.set(rd, None);
        let (base, index, shift) = match scaled {
            Some((reg, shift)) if reg == rk => (rj, rk, shift),
            Some((reg, shift)) if reg == rj => (rk, rj, shift),
            _ => (rj, rk, 0),
        };
        Note::Load {
            reg: rd,
            mem: Mem {
                base: Some(base),
                index: Some(index),
                scale: 1 << shift,
                disp: 0,
            },
            size: shape.0,
            signed: shape.1,
        }
    }

    /// `jirl rd, rj, imm`: a return, a call (linking `ra`) or jump to a
    /// known address or through a slot, or through a register.
    fn jirl(&self, rd: u32, rj: u32, imm: i64, loaded: Option<(u32, u64)>) -> Flow {
        let link = rd == RA;
        if rd == 0 && rj == RA && imm == 0 {
            return Flow::Return;
        }
        if let Some(base) = self.get(rj).filter(|_| rj != 0) {
            let target = base.wrapping_add_signed(imm);
            return if link {
                Flow::Call(target)
            } else {
                Flow::Jump(target)
            };
        }
        if let Some((_, slot)) = loaded.filter(|&(reg, _)| reg == rj && imm == 0) {
            return if link {
                Flow::CallSlot(slot)
            } else {
                Flow::JumpSlot(slot)
            };
        }
        match (link, imm) {
            (true, 0) => Flow::CallRegister(rj),
            (true, _) => Flow::CallIndirect,
            (false, 0) => Flow::JumpRegister(rj),
            (false, _) => Flow::JumpIndirect,
        }
    }

    /// `bltu`/`bgeu rj, rd`'s note: an unsigned compare with a constant
    /// bounds a case value (`bltu n, a0, default` with `n` the highest
    /// case, `bltu a0, n, in_range` with it one past).
    fn compare(&self, rj: u32, rd: u32) -> Note {
        let constant = |reg: u32| self.get(reg).filter(|_| reg != 0);
        match (constant(rj), constant(rd)) {
            (None, Some(n)) if n > 0 => Note::Compare {
                reg: rj,
                imm: n.wrapping_sub(1),
            },
            (Some(n), None) => Note::Compare { reg: rd, imm: n },
            _ => Note::None,
        }
    }

    fn decode(&mut self, word: u32) -> (Flow, Note) {
        let rd = word & 0x1f;
        let rj = (word >> 5) & 0x1f;
        let rk = (word >> 10) & 0x1f;
        let si12 = sext((word >> 10) & 0xfff, 12);
        let si16 = sext((word >> 10) & 0xffff, 16);
        let si20 = sext((word >> 5) & 0xf_ffff, 20);
        let pending = std::mem::take(&mut self.state.pending);
        let Pending {
            scaled,
            indexed,
            loaded,
        } = pending;
        let addr = self.addr;
        let (flow, note) = match word >> 26 {
            // The reserved start of the encoding space (all zeros).
            0 if word >> 10 == 0 => (Flow::Invalid, Note::None),
            // BREAK
            0 if word >> 15 == 0x54 => (Flow::Stop, Note::None),
            0 => (Flow::Next, self.arithmetic(word, scaled)),
            // FP arithmetic and moves (some to integer registers), CSRs,
            // cache and TLB operations, four-operand FP and vector.
            1..=3 => match word {
                // ERTN: an exception handler's return.
                0x0648_3800 => (Flow::Return, Note::None),
                _ => (Flow::Next, self.clobber(rd)),
            },
            // ADDU16I.D
            4 => (Flow::Next, self.add_imm(rd, rj, si16 << 16, false)),
            // LU12I.W, LU32I.D
            5 if word >> 25 & 1 == 0 => (
                Flow::Next,
                self.value(rd, word_result((si20 << 12).cast_unsigned())),
            ),
            5 => (
                Flow::Next,
                match self.get(rd) {
                    Some(low) => self.value(rd, low & 0xffff_ffff | (si20 << 32).cast_unsigned()),
                    None => self.clobber(rd),
                },
            ),
            // PCADDI, PCALAU12I
            6 if word >> 25 & 1 == 0 => (
                Flow::Next,
                self.constant(rd, addr.wrapping_add_signed(si20 << 2)),
            ),
            6 => (
                Flow::Next,
                self.value(rd, (addr & !0xfff).wrapping_add_signed(si20 << 12)),
            ),
            // PCADDU12I, PCADDU18I
            7 => {
                let shift = if word >> 25 & 1 == 0 { 12 } else { 18 };
                (
                    Flow::Next,
                    self.value(rd, addr.wrapping_add_signed(si20 << shift)),
                )
            }
            // LL, SC; LDPTR, STPTR.
            8 => (Flow::Next, self.clobber(rd)),
            9 => match word >> 24 & 3 {
                0 => (
                    Flow::Next,
                    self.load(
                        rd,
                        rj,
                        sext((word >> 10) & 0x3fff, 14) << 2,
                        (4, true),
                        indexed,
                    ),
                ),
                2 => (
                    Flow::Next,
                    self.load(
                        rd,
                        rj,
                        sext((word >> 10) & 0x3fff, 14) << 2,
                        (8, false),
                        indexed,
                    ),
                ),
                _ => (Flow::Next, Note::None),
            },
            // Loads and stores with a 12-bit offset; vector loads and
            // stores; PRELD.
            0x0a | 0x0b => {
                let shape = match word >> 22 & 0xf {
                    0 => Some((1, true)),
                    1 => Some((2, true)),
                    2 => Some((4, true)),
                    3 => Some((8, false)),
                    8 => Some((1, false)),
                    9 => Some((2, false)),
                    10 => Some((4, false)),
                    _ => None,
                };
                match shape {
                    Some(shape) if word >> 26 == 0x0a => {
                        (Flow::Next, self.load(rd, rj, si12, shape, indexed))
                    }
                    _ => (Flow::Next, Note::None),
                }
            }
            // Vector element loads and stores.
            0x0c => (Flow::Next, Note::None),
            // Indexed loads and stores, atomics, barriers.
            0x0e => {
                let op = word >> 15;
                let shape = match op {
                    0x7000 => Some((1, true)),
                    0x7008 => Some((2, true)),
                    0x7010 => Some((4, true)),
                    0x7018 => Some((8, false)),
                    0x7040 => Some((1, false)),
                    0x7048 => Some((2, false)),
                    0x7050 => Some((4, false)),
                    _ => None,
                };
                match shape {
                    Some(shape) => (Flow::Next, self.load_indexed(rd, (rj, rk), shape, scaled)),
                    // Stores (integer, FP, vector), barriers, bounds-checked
                    // stores: no integer register written.
                    None if (0x7020..0x7040).contains(&op)
                        || (0x7060..0x70a0).contains(&op)
                        || matches!(op, 0x70e4 | 0x70e5) =>
                    {
                        (Flow::Next, Note::None)
                    }
                    None => (Flow::Next, self.clobber(rd)),
                }
            }
            // BEQZ, BNEZ; BCEQZ, BCNEZ.
            0x10..=0x12 => {
                let offs = ((word & 0x1f) << 16) | ((word >> 10) & 0xffff);
                let target = relative(addr, offs, 21, 4);
                (Flow::Branch(target), Note::None)
            }
            // JIRL
            0x13 => (self.jirl(rd, rj, si16 << 2, loaded), Note::None),
            // B, BL
            0x14 | 0x15 => {
                let offs = ((word & 0x3ff) << 16) | ((word >> 10) & 0xffff);
                let target = relative(addr, offs, 26, 4);
                if word >> 26 == 0x14 {
                    (Flow::Jump(target), Note::None)
                } else {
                    (Flow::Call(target), Note::None)
                }
            }
            // BEQ, BNE, BLT, BGE; BLTU, BGEU.
            0x16..=0x1b => {
                let target = addr.wrapping_add_signed(si16 << 2);
                let note = if word >> 26 >= 0x1a {
                    self.compare(rj, rd)
                } else {
                    Note::None
                };
                (Flow::Branch(target), note)
            }
            // The vector extensions (some write an integer register).
            0x1c | 0x1d => (Flow::Next, self.clobber(rd)),
            _ => (Flow::Invalid, Note::None),
        };
        self.keep(note, pending);
        (flow, note)
    }

    /// Opcode 0: the integer operations with two or three registers, a
    /// shift or bit field, and the 12-bit immediates; `break` and
    /// `syscall`.
    fn arithmetic(&mut self, word: u32, scaled: Option<(u32, u8)>) -> Note {
        let rd = word & 0x1f;
        let rj = (word >> 5) & 0x1f;
        let rk = (word >> 10) & 0x1f;
        let si12 = sext((word >> 10) & 0xfff, 12);
        let ui12 = u64::from((word >> 10) & 0xfff);
        match word >> 22 {
            // SLTI, SLTUI
            0x008 | 0x009 => self.clobber(rd),
            // ADDI.W, ADDI.D
            0x00a => self.add_imm(rd, rj, si12, true),
            0x00b => self.add_imm(rd, rj, si12, false),
            // LU52I.D
            0x00c => self.derive(rd, rj, |low| {
                low & 0x000f_ffff_ffff_ffff | (si12 << 52).cast_unsigned()
            }),
            // ANDI, ORI, XORI
            0x00d => self.derive(rd, rj, |value| value & ui12),
            0x00e => self.derive(rd, rj, |value| value | ui12),
            0x00f => self.derive(rd, rj, |value| value ^ ui12),
            // BSTRPICK.D rd, rj, 31, 0: a zero extension, as a copy.
            0x003 if (word >> 10) & 0xfff == 0x7c0 => self.add_imm(rd, rj, 0, false),
            // BSTRINS.D, BSTRPICK.D
            0x002 | 0x003 => self.clobber(rd),
            _ => match word >> 15 {
                // ADD.W, ADD.D
                0x20 => match self.get(rj).zip(self.get(rk)) {
                    Some((a, b)) => self.constant(rd, word_result(a.wrapping_add(b))),
                    None => self.clobber(rd),
                },
                0x21 => self.add(rd, rj, rk, scaled),
                // SUB.D
                0x23 => {
                    self.set(rd, None);
                    if rd == 0 {
                        Note::None
                    } else {
                        Note::Sub {
                            reg: rd,
                            base: rj,
                            index: rk,
                        }
                    }
                }
                // OR (`move rd, rj` is `or rd, rj, zero`)
                0x2a if rj == 0 || rk == 0 => self.add_imm(rd, rj | rk, 0, false),
                // ALSL.W, ALSL.WU, ALSL.D: `(rj << sa) + rk`.
                op if op >> 2 == 0x2 || op >> 2 == 0x3 || op >> 2 == 0x16 => {
                    let shift = u8::try_from(word >> 15 & 3).unwrap_or(0).saturating_add(1);
                    if op >> 2 == 0x16 {
                        self.indexed(rd, rk, rj, shift)
                    } else {
                        self.clobber(rd)
                    }
                }
                // SLLI.W; SLLI.D.
                0x81 => self.shift(rd, rj, (word >> 10) & 0x1f),
                op if op >> 1 == 0x41 => self.shift(rd, rj, (word >> 10) & 0x3f),
                // DBCL, SYSCALL
                0x55 | 0x56 => Note::None,
                _ => self.clobber(rd),
            },
        }
    }

    /// Carry what this instruction did not overwrite to the next one.
    fn keep(&mut self, note: Note, before: Pending) {
        let Pending {
            scaled,
            indexed,
            loaded,
        } = before;
        let written = if matches!(note, Note::Compare { .. }) {
            0
        } else {
            note.writes()
        } | self
            .state
            .pending
            .indexed
            .map_or(0, |indexed| 1 << indexed.sum);
        if self.state.pending.scaled.is_none()
            && let Some((reg, _)) = scaled
            && written >> reg & 1 == 0
        {
            self.state.pending.scaled = scaled;
        }
        if self.state.pending.indexed.is_none()
            && let Some(Indexed {
                sum, base, index, ..
            }) = indexed
            && written & (1 << sum | 1 << base | 1 << index) == 0
        {
            self.state.pending.indexed = indexed;
        }
        if self.state.pending.loaded.is_none()
            && let Some((reg, _)) = loaded
            && written >> reg & 1 == 0
        {
            self.state.pending.loaded = loaded;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decode `code` from `addr`, instruction by instruction.
    fn run(words: &[u32], addr: u64) -> Vec<Insn> {
        let mut decoder = Decoder::default();
        words
            .iter()
            .enumerate()
            .map(|(i, word)| decoder.decode(&word.to_le_bytes(), addr + 4 * i as u64))
            .collect()
    }

    fn flows(words: &[u32], addr: u64) -> Vec<Flow> {
        run(words, addr).iter().map(|insn| insn.flow).collect()
    }

    #[test]
    fn transfers() {
        assert_eq!(
            flows(
                &[
                    0x5000_ec00, // b +0xec
                    0x5400_1000, // bl +0x10
                    0x4c00_0020, // ret (jirl zero, ra, 0)
                    0x4c00_0180, // jr t0
                    0x4c00_0181, // jirl ra, t0, 0
                    0x4000_2080, // beqz a0, +0x20
                    0x47ff_f8ff, // bnez a3, -8
                    0x5fff_f8e9, // bne a3, a5, -8
                    0x002a_0000, // break 0
                    0x0340_0000, // nop
                    0x0000_0000, // reserved
                ],
                0x1000,
            ),
            [
                Flow::Jump(0x10ec),
                Flow::Call(0x1014),
                Flow::Return,
                Flow::JumpRegister(12),
                Flow::CallRegister(12),
                Flow::Branch(0x1034),
                Flow::Branch(0x1010),
                Flow::Branch(0x1014),
                Flow::Stop,
                Flow::Next,
                Flow::Invalid,
            ]
        );
        assert!(run(&[0x0340_0000], 0)[0].pad);
    }

    /// `pcaddu18i ra, 0; jirl ra, ra, 0x98`: a call beyond `bl`'s reach;
    /// `pcaddu18i t8, 0; jirl zero, t8, 0x518`: a far tail call.
    #[test]
    fn far_calls() {
        assert_eq!(
            flows(&[0x1e00_0001, 0x4c00_9821], 0x10c68)[1],
            Flow::Call(0x10d00)
        );
        assert_eq!(
            flows(&[0x1e00_0014, 0x4c05_1a80], 0x10b40)[1],
            Flow::Jump(0x11058)
        );
    }

    /// A PLT stub: `pcaddu12i t3, 0x2; ld.d t3, t3, 0x10; jirl t1, t3, 0;
    /// nop`; a call through the GOT: `pcalau12i t0, 0x40; ld.d t0, t0,
    /// -0x40; jirl ra, t0, 0`.
    #[test]
    fn slots() {
        assert_eq!(
            flows(&[0x1c00_004f, 0x28c0_41ef, 0x4c00_01ed, NOP], 0x1000)[2],
            Flow::JumpSlot(0x3010)
        );
        assert_eq!(
            flows(&[0x1a00_080c, 0x28ff_018c, 0x4c00_0181], 0x1_2000_0578)[2],
            Flow::CallSlot(0x1_2004_0000 - 0x40)
        );
    }

    /// LLVM's table: `ori a2, zero, 19; bltu a2, a0, default; slli.d a0,
    /// a0, 2; pcalau12i a2, -0x10; addi.d a2, a2, 0x340; ldx.w a0, a2, a0;
    /// add.d a0, a2, a0; jr a0`.
    #[test]
    fn relative_table() {
        let insns = run(
            &[
                0x0380_4c06,
                0x6800_d4c4,
                0x0041_0884,
                0x1bff_fe06,
                0x02cd_00c6,
                0x3808_10c4,
                0x0010_90c4,
                0x4c00_0080,
            ],
            0x10b78,
        );
        assert_eq!(insns[1].note, Note::Compare { reg: 4, imm: 19 });
        assert_eq!(
            insns[4].note,
            Note::Address {
                reg: 6,
                addr: 0x340,
            }
        );
        assert_eq!(
            insns[5].note,
            Note::Load {
                reg: 4,
                mem: Mem {
                    base: Some(6),
                    index: Some(4),
                    scale: 4,
                    disp: 0,
                },
                size: 4,
                signed: true,
            }
        );
        assert_eq!(insns[7].flow, Flow::JumpRegister(4));
    }

    /// GCC's table: `addi.w s1, zero, 6; bltu s1, t0, default; alsl.d t1,
    /// t0, s2, 3; ldptr.d t1, t1, 0; jr t1`.
    #[test]
    fn absolute_table() {
        let insns = run(
            &[
                0x0280_1818,
                0x6802_1b0c,
                0x002d_658d,
                0x2600_01ad,
                0x4c00_01a0,
            ],
            0x1000,
        );
        assert_eq!(insns[1].note, Note::Compare { reg: 12, imm: 6 });
        assert_eq!(
            insns[3].note,
            Note::Load {
                reg: 13,
                mem: Mem {
                    base: Some(25),
                    index: Some(12),
                    scale: 8,
                    disp: 0,
                },
                size: 8,
                signed: false,
            }
        );
        assert_eq!(insns[4].flow, Flow::JumpRegister(13));
    }

    #[test]
    fn constants() {
        // lu12i.w t0, 0x12345; ori t0, t0, 0x678; lu32i.d t0, 1;
        // lu52i.d t0, t0, 0x7ff.
        let insns = run(&[0x1424_68ac, 0x0399_e18c, 0x1600_002c, 0x031f_fd8c], 0);
        assert_eq!(
            insns[3].note,
            Note::Address {
                reg: 12,
                addr: 0x7ff0_0001_1234_5678,
            }
        );
    }

    #[test]
    fn frames() {
        let decoder = Decoder::default();
        assert!(decoder.starts_frame(&0x02ff_8063_u32.to_le_bytes()));
        assert!(!decoder.starts_frame(&0x02c0_8063_u32.to_le_bytes()));
    }
}
