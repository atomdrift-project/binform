//! RISC-V (RV32 and RV64, with the compressed instructions of the C
//! extension): control flow only. Instructions are 32 bits, or 16 when the
//! low two bits of the first halfword are not both set; there are no delay
//! slots.
//!
//! Transfers are `jal` (a call when it links `ra` or `t0`, a jump when it
//! links `x0`), `jalr` through a register, and the conditional branches. A
//! call to a function beyond `jal`'s reach is `auipc ra, hi; jalr ra,
//! lo(ra)`, and a far tail call `auipc t1, hi; jr lo(t1)`: the decoder
//! keeps the constants `lui`, `auipc` and `addi` leave in registers, so
//! such pairs read as direct calls and jumps. An import stub loads its slot
//! PC-relative and jumps through it (`auipc t3, hi; ld t3, lo(t3); jalr t1,
//! t3`).
//!
//! GCC's jump tables bound the case value with an unsigned compare against
//! a constant (`li a5, 9; bgtu a0, a5, default`), scale it (`slli`, or
//! Zba's `sh2add`), add the table's address and load the entry, absolute or
//! relative to the table (`lw a5, 0(a5); add a5, a5, a4; jr a5`).

use crate::isa::{Extend, Flow, Insn, Mem, Note};

/// What earlier instructions left that a later one needs.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct State {
    /// The constant in each register.
    regs: [Option<u64>; 32],
    /// A register holding another shifted left, and by how much.
    scaled: Option<(u32, u8)>,
    /// A register holding a base plus a scaled register, which a load then
    /// reads through: the sum, base, index and shift.
    indexed: Option<(u32, u32, u32, u8)>,
    /// The last register loaded from a fixed address, and that address.
    loaded: Option<(u32, u64)>,
    /// A register holding another shifted left by 32 (`slli a5, s0, 32`),
    /// which a right shift by 29-32 makes a zero-extended, scaled copy of.
    widened: Option<(u32, u32)>,
}

/// `ra`, the return address register, and `t0`, the alternate one.
const RA: u32 = 1;
const T0: u32 = 5;

/// The global pointer.
const GP: u32 = 3;

/// The registers a call may change: `ra`, `t0`-`t2`, `a0`-`a7`, `t3`-`t6`.
const VOLATILE: u32 = 0xf003_fce2;

/// `nop` (`addi x0, x0, 0`) and `c.nop`.
const NOP: u32 = 0x0000_0013;
const C_NOP: u16 = 0x0001;

/// Machine facts the decoder needs: 64-bit registers, and the value of the
/// global pointer (`gp`), when known.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Config {
    pub(crate) wide: bool,
    pub(crate) gp: Option<u64>,
}

fn half_at(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
}

fn word_at(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

pub(crate) fn decode(state: &mut State, config: Config, bytes: &[u8], addr: u64) -> Insn {
    let Some(half) = half_at(bytes, 0) else {
        return Insn::new(2, Flow::Invalid);
    };
    let mut cx = Cx {
        state,
        config,
        addr,
    };
    let (len, flow, note, pad) = if half & 3 != 3 {
        let (flow, note) = cx.compressed(half);
        (2, flow, note, half == C_NOP)
    } else if half & 0x1c != 0x1c {
        let Some(word) = word_at(bytes, 0) else {
            return Insn::new(2, Flow::Invalid);
        };
        let (flow, note) = cx.full(word);
        (4, flow, note, word == NOP)
    } else {
        // 48-bit and longer encodings: none in use.
        (2, Flow::Invalid, Note::None, false)
    };
    let state = cx.state;
    match flow {
        Flow::Next | Flow::Branch(_) => {}
        Flow::Call(_) | Flow::CallIndirect | Flow::CallRegister(_) | Flow::CallSlot(_) => {
            state.loaded = None;
            state.scaled = None;
            state.indexed = None;
            for (reg, value) in state.regs.iter_mut().enumerate() {
                if VOLATILE >> reg & 1 != 0 {
                    *value = None;
                }
            }
        }
        // Past a transfer that does not fall through, code is reached from
        // elsewhere.
        _ => *state = State::default(),
    }
    let mut insn = Insn::new(len, flow);
    insn.note = note;
    insn.pad = pad;
    insn
}

struct Cx<'a> {
    state: &'a mut State,
    config: Config,
    addr: u64,
}

impl Cx<'_> {
    fn wrap(&self, value: u64) -> u64 {
        if self.config.wide {
            value
        } else {
            value & 0xffff_ffff
        }
    }

    /// The constant in `reg`: zero in `x0`; in `gp`, the global pointer
    /// (which only start-up code sets) unless this block set it.
    fn get(&self, reg: u32) -> Option<u64> {
        let held = self.state.regs.get(reg as usize).copied().flatten();
        match reg {
            0 => Some(0),
            GP => held.or(self.config.gp),
            _ => held,
        }
    }

    fn set(&mut self, reg: u32, value: Option<u64>) {
        if reg != 0
            && let Some(slot) = self.state.regs.get_mut(reg as usize)
        {
            *slot = value;
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
        let value = self.wrap(value);
        self.set(rd, Some(value));
        Note::Address {
            reg: rd,
            addr: value,
        }
    }

    /// `rd = rs1 + imm` (`addi`, `c.addi`, `addiw` when `word`).
    fn add_imm(&mut self, rd: u32, rs1: u32, imm: i64, word: bool) -> Note {
        if rd == 0 {
            return Note::None;
        }
        if imm == 0 {
            // `mv`, `sext.w`.
            let value = self.get(rs1);
            self.set(rd, value);
            if rs1 == 0 {
                return self.constant(rd, 0);
            }
            return Note::Copy { reg: rd, src: rs1 };
        }
        match self.get(rs1) {
            Some(base) => {
                let sum = base.wrapping_add_signed(imm);
                let sum = if word {
                    i64::from(u32::try_from(sum & 0xffff_ffff).unwrap_or(0).cast_signed())
                        .cast_unsigned()
                } else {
                    sum
                };
                self.constant(rd, sum)
            }
            None => {
                self.set(rd, None);
                Note::Offset {
                    reg: rd,
                    src: rs1,
                    imm: self.wrap(imm.cast_unsigned()),
                }
            }
        }
    }

    /// `rd = rs1 << shift`: a scaled copy, when small; the first half of
    /// a zero extension, by 32.
    fn shift(&mut self, rd: u32, rs1: u32, shift: u32) -> Note {
        if rd == 0 {
            return Note::None;
        }
        self.set(rd, None);
        if shift == 32 && self.config.wide {
            self.state.widened = Some((rd, rs1));
            return Note::Clobber(1 << rd);
        }
        if (1..=3).contains(&shift) {
            self.state.scaled = Some((rd, u8::try_from(shift).unwrap_or(0)));
            Note::Copy { reg: rd, src: rs1 }
        } else {
            Note::Clobber(1 << rd)
        }
    }

    /// `rd = rs1 >> shift`, logical: after `slli rs1, src, 32`, a shift by
    /// 32 - n zero-extends `src` and scales it by n.
    fn shift_right(&mut self, rd: u32, rs1: u32, shift: u32, widened: Option<(u32, u32)>) -> Note {
        if rd == 0 {
            return Note::None;
        }
        self.set(rd, None);
        match widened {
            Some((reg, src)) if reg == rs1 && (29..=32).contains(&shift) => {
                let scale = 32 - shift;
                if scale > 0 {
                    self.state.scaled = Some((rd, u8::try_from(scale).unwrap_or(0)));
                }
                Note::Copy { reg: rd, src }
            }
            _ => Note::Clobber(1 << rd),
        }
    }

    /// `rd = (index << shift) + base` (`sh1add`-`sh3add`), the address a
    /// table entry is loaded from.
    fn indexed(&mut self, rd: u32, base: u32, index: u32, shift: u8) -> Note {
        if rd == 0 {
            return Note::None;
        }
        self.set(rd, None);
        self.state.indexed = Some((rd, base, index, shift));
        Note::None
    }

    /// `rd = rs1 + rs2`: a base plus a scaled case value, which a load then
    /// reads through, or a table's entry plus its base.
    fn add(&mut self, rd: u32, rs1: u32, rs2: u32, scaled: Option<(u32, u8)>) -> Note {
        if rd == 0 {
            return Note::None;
        }
        if let Some((reg, shift)) = scaled
            && (reg == rs1 || reg == rs2)
        {
            let base = if reg == rs1 { rs2 } else { rs1 };
            return self.indexed(rd, base, reg, shift);
        }
        let value = self
            .get(rs1)
            .zip(self.get(rs2))
            .map(|(a, b)| a.wrapping_add(b));
        if let Some(value) = value {
            return self.constant(rd, value);
        }
        self.set(rd, None);
        Note::Add {
            reg: rd,
            base: rs1,
            index: rs2,
            shift: 0,
            extend: Extend::None,
        }
    }

    /// A load of `size` bytes into `rd` from `imm(rs1)`: a table's entry
    /// through an indexed address, or a slot at a fixed one.
    fn load(
        &mut self,
        rd: u32,
        rs1: u32,
        imm: i64,
        (size, signed): (u8, bool),
        indexed: Option<(u32, u32, u32, u8)>,
    ) -> Note {
        if rd == 0 {
            return Note::None;
        }
        let base_value = self.get(rs1);
        self.set(rd, None);
        if let Some((sum, base, index, shift)) = indexed
            && sum == rs1
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
        let slot = base_value.map(|base| self.wrap(base.wrapping_add_signed(imm)));
        self.state.loaded = slot.map(|slot| (rd, slot));
        let (base, disp) = slot.map_or((Some(rs1), imm.cast_unsigned()), |slot| (None, slot));
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

    /// `jalr rd, imm(rs1)`: a return, a call or jump to a known address or
    /// through a slot, or through a register.
    fn jalr(&self, rd: u32, rs1: u32, imm: i64, loaded: Option<(u32, u64)>) -> Flow {
        let link = rd == RA || rd == T0;
        if rd == 0 && (rs1 == RA || rs1 == T0) && imm == 0 {
            return Flow::Return;
        }
        if let Some(base) = self.get(rs1).filter(|_| rs1 != 0) {
            let target = self.wrap(base.wrapping_add_signed(imm)) & !1;
            return if link {
                Flow::Call(target)
            } else {
                Flow::Jump(target)
            };
        }
        if let Some((_, slot)) = loaded.filter(|&(reg, _)| reg == rs1 && imm == 0) {
            return if link {
                Flow::CallSlot(slot)
            } else {
                Flow::JumpSlot(slot)
            };
        }
        match (link, imm) {
            (true, 0) => Flow::CallRegister(rs1),
            (true, _) => Flow::CallIndirect,
            (false, 0) => Flow::JumpRegister(rs1),
            (false, _) => Flow::JumpIndirect,
        }
    }

    /// A conditional branch's note: an unsigned compare with a constant
    /// bounds a case value (`bgtu a0, a5, default` with `a5` holding the
    /// highest case, `bltu a0, a5, in_range` with it one past).
    fn compare(&self, funct3: u32, rs1: u32, rs2: u32) -> Note {
        let constant = |reg: u32| self.get(reg).filter(|_| reg != 0);
        match (funct3, constant(rs1), constant(rs2)) {
            // BLTU, BGEU rs1, n: rs1 below n is in range.
            (6 | 7, None, Some(n)) if n > 0 => Note::Compare {
                reg: rs1,
                imm: n - 1,
            },
            // BLTU, BGEU n, rs2 (`bgtu rs2, n`, `bleu rs2, n`): rs2 up to n.
            (6 | 7, Some(n), None) => Note::Compare { reg: rs2, imm: n },
            _ => Note::None,
        }
    }

    fn full(&mut self, word: u32) -> (Flow, Note) {
        let rd = (word >> 7) & 0x1f;
        let funct3 = (word >> 12) & 7;
        let rs1 = (word >> 15) & 0x1f;
        let rs2 = (word >> 20) & 0x1f;
        let funct7 = word >> 25;
        let imm_i = i64::from(word.cast_signed() >> 20);
        let imm_u = i64::from((word & 0xffff_f000).cast_signed());
        let scaled = self.state.scaled.take();
        let indexed = self.state.indexed.take();
        let loaded = self.state.loaded.take();
        let widened = self.state.widened.take();
        let addr = self.addr;
        let (flow, note) = match word & 0x7f {
            // JAL
            0x6f => {
                let imm = ((word >> 31) & 1) << 20
                    | ((word >> 12) & 0xff) << 12
                    | ((word >> 20) & 1) << 11
                    | ((word >> 21) & 0x3ff) << 1;
                let target = self.wrap(addr.wrapping_add_signed(sign(imm, 21)));
                let flow = if rd == 0 {
                    Flow::Jump(target)
                } else {
                    Flow::Call(target)
                };
                (flow, Note::None)
            }
            // JALR
            0x67 if funct3 == 0 => (self.jalr(rd, rs1, imm_i, loaded), Note::None),
            // BEQ, BNE, BLT, BGE, BLTU, BGEU
            0x63 if !matches!(funct3, 2 | 3) => {
                let imm = ((word >> 31) & 1) << 12
                    | ((word >> 7) & 1) << 11
                    | ((word >> 25) & 0x3f) << 5
                    | ((word >> 8) & 0xf) << 1;
                let target = self.wrap(addr.wrapping_add_signed(sign(imm, 13)));
                (Flow::Branch(target), self.compare(funct3, rs1, rs2))
            }
            // LUI, AUIPC
            0x37 => (Flow::Next, self.constant(rd, imm_u.cast_unsigned())),
            0x17 => (
                Flow::Next,
                self.constant(rd, addr.wrapping_add_signed(imm_u)),
            ),
            // OP-IMM: ADDI, SLLI; the rest write rd some other way.
            0x13 => (
                Flow::Next,
                match funct3 {
                    0 => self.add_imm(rd, rs1, imm_i, false),
                    1 if funct7 >> 1 == 0 => self.shift(rd, rs1, (word >> 20) & 0x3f),
                    5 if funct7 >> 1 == 0 => {
                        self.shift_right(rd, rs1, (word >> 20) & 0x3f, widened)
                    }
                    _ => self.clobber(rd),
                },
            ),
            // OP-IMM-32: ADDIW, SLLIW.
            0x1b => (
                Flow::Next,
                match funct3 {
                    0 => self.add_imm(rd, rs1, imm_i, true),
                    1 if funct7 == 0 => self.shift(rd, rs1, rs2),
                    // Zba's SLLI.UW: a zero-extended, scaled copy.
                    1 if funct7 >> 1 == 2 => self.shift(rd, rs1, (word >> 20) & 0x3f),
                    _ => self.clobber(rd),
                },
            ),
            // OP and OP-32: ADD, ADDW; SUB; Zba's SH1ADD-SH3ADD and their
            // `.uw` forms.
            0x33 | 0x3b => (
                Flow::Next,
                match (funct7, funct3) {
                    (0, 0) => self.add(rd, rs1, rs2, scaled),
                    (0x20, 0) if word & 0x7f == 0x33 => {
                        self.set(rd, None);
                        if rd == 0 {
                            Note::None
                        } else {
                            Note::Sub {
                                reg: rd,
                                base: rs1,
                                index: rs2,
                            }
                        }
                    }
                    (0x10, 2 | 4 | 6) => {
                        self.indexed(rd, rs2, rs1, u8::try_from(funct3 / 2).unwrap_or(0))
                    }
                    // Zba's ADD.UW with x0 (`zext.w`): a copy.
                    (4, 0) if word & 0x7f == 0x3b && rs2 == 0 => self.add_imm(rd, rs1, 0, false),
                    _ => self.clobber(rd),
                },
            ),
            // LOAD
            0x03 => {
                let shape = match funct3 {
                    0 => (1, true),
                    1 => (2, true),
                    2 => (4, true),
                    3 => (8, false),
                    4 => (1, false),
                    5 => (2, false),
                    6 => (4, false),
                    _ => return (Flow::Invalid, Note::None),
                };
                (Flow::Next, self.load(rd, rs1, imm_i, shape, indexed))
            }
            // STORE, FP loads and stores, fences, fused multiply-adds.
            0x23 | 0x07 | 0x27 | 0x0f | 0x43 | 0x47 | 0x4b | 0x4f => (Flow::Next, Note::None),
            // SYSTEM: `ecall` returns; `ebreak` and `unimp` (`csrrw x0,
            // cycle, x0`) trap; the CSR instructions write rd.
            0x73 => match word {
                0x0000_0073 => (Flow::Next, Note::None),
                0x0010_0073 | 0xc000_1073 => (Flow::Stop, Note::None),
                _ if funct3 == 0 => (Flow::Next, Note::None),
                _ => (Flow::Next, self.clobber(rd)),
            },
            // FP arithmetic (some write an integer register), atomics, and
            // the vector set.
            0x53 | 0x2f | 0x57 => (Flow::Next, self.clobber(rd)),
            _ => (Flow::Invalid, Note::None),
        };
        self.keep(note, (scaled, indexed, loaded, widened));
        (flow, note)
    }

    /// Carry what this instruction did not overwrite to the next one.
    #[allow(clippy::type_complexity)]
    fn keep(
        &mut self,
        note: Note,
        (scaled, indexed, loaded, widened): (
            Option<(u32, u8)>,
            Option<(u32, u32, u32, u8)>,
            Option<(u32, u64)>,
            Option<(u32, u32)>,
        ),
    ) {
        let written = if matches!(note, Note::Compare { .. }) {
            0
        } else {
            note.writes()
        } | self.state.indexed.map_or(0, |(sum, ..)| 1 << sum);
        if self.state.scaled.is_none()
            && let Some((reg, _)) = scaled
            && written >> reg & 1 == 0
        {
            self.state.scaled = scaled;
        }
        if self.state.indexed.is_none()
            && let Some((sum, base, index, _)) = indexed
            && written & (1 << sum | 1 << base | 1 << index) == 0
        {
            self.state.indexed = indexed;
        }
        if self.state.loaded.is_none()
            && let Some((reg, _)) = loaded
            && written >> reg & 1 == 0
        {
            self.state.loaded = loaded;
        }
        if self.state.widened.is_none()
            && let Some((reg, src)) = widened
            && written & (1 << reg | 1 << src) == 0
        {
            self.state.widened = widened;
        }
    }

    fn compressed(&mut self, half: u16) -> (Flow, Note) {
        let h = u32::from(half);
        let funct3 = h >> 13;
        // The full and the compact (x8-x15) register fields.
        let rd = (h >> 7) & 0x1f;
        let rs2 = (h >> 2) & 0x1f;
        let rd_c = ((h >> 2) & 7) + 8;
        let rs1_c = ((h >> 7) & 7) + 8;
        let imm6 = sign((h >> 12 & 1) << 5 | (h >> 2) & 0x1f, 6);
        let scaled = self.state.scaled.take();
        let indexed = self.state.indexed.take();
        let loaded = self.state.loaded.take();
        let widened = self.state.widened.take();
        let addr = self.addr;
        let wide = self.config.wide;
        let (flow, note) = match (h & 3, funct3) {
            // The all-zero halfword is defined illegal.
            (0, 0) if h == 0 => (Flow::Invalid, Note::None),
            // C.ADDI4SPN: rd' = sp + n.
            (0, 0) => (Flow::Next, self.clobber(rd_c)),
            // C.LW, C.LD (RV64; C.FLW on RV32).
            (0, 2) => {
                let off = ((h >> 10) & 7) << 3 | ((h >> 6) & 1) << 2 | ((h >> 5) & 1) << 6;
                (
                    Flow::Next,
                    self.load(rd_c, rs1_c, i64::from(off), (4, true), indexed),
                )
            }
            (0, 3) if wide => {
                let off = ((h >> 10) & 7) << 3 | ((h >> 5) & 3) << 6;
                (
                    Flow::Next,
                    self.load(rd_c, rs1_c, i64::from(off), (8, false), indexed),
                )
            }
            // Zcb's byte and halfword loads and stores.
            (0, 4) if (h >> 10) & 7 < 4 && (h >> 11) & 1 == 0 => (Flow::Next, self.clobber(rd_c)),
            // FP loads, stores.
            (0, _) => (Flow::Next, Note::None),
            // C.ADDI (C.NOP with rd zero).
            (1, 0) => (Flow::Next, self.add_imm(rd, rd, imm6, false)),
            // C.JAL on RV32; C.ADDIW on RV64.
            (1, 1) if !wide => (Flow::Call(self.cj(h)), Note::None),
            (1, 1) => (Flow::Next, self.add_imm(rd, rd, imm6, true)),
            // C.LI
            (1, 2) => (Flow::Next, self.constant(rd, imm6.cast_unsigned())),
            // C.ADDI16SP; C.LUI.
            (1, 3) if rd == 2 => (Flow::Next, self.clobber(2)),
            (1, 3) => (Flow::Next, self.constant(rd, (imm6 << 12).cast_unsigned())),
            // The ALU group on rd'.
            (1, 4) => (
                Flow::Next,
                match ((h >> 10) & 3, (h >> 12) & 1, (h >> 5) & 3) {
                    // C.SUB
                    (3, 0, 0) => {
                        self.set(rs1_c, None);
                        Note::Sub {
                            reg: rs1_c,
                            base: rs1_c,
                            index: rd_c,
                        }
                    }
                    // C.ADDW
                    (3, 1, 1) => self.add(rs1_c, rs1_c, rd_c, scaled),
                    // C.SRLI
                    (0, ..) => {
                        let shift = (h >> 12 & 1) << 5 | (h >> 2) & 0x1f;
                        self.shift_right(rs1_c, rs1_c, shift, widened)
                    }
                    _ => self.clobber(rs1_c),
                },
            ),
            // C.J
            (1, 5) => (Flow::Jump(self.cj(h)), Note::None),
            // C.BEQZ, C.BNEZ
            (1, 6 | 7) => {
                let imm = ((h >> 12) & 1) << 8
                    | ((h >> 10) & 3) << 3
                    | ((h >> 5) & 3) << 6
                    | ((h >> 3) & 3) << 1
                    | ((h >> 2) & 1) << 5;
                let target = self.wrap(addr.wrapping_add_signed(sign(imm, 9)));
                (Flow::Branch(target), Note::None)
            }
            // C.SLLI
            (2, 0) => (
                Flow::Next,
                self.shift(rd, rd, (h >> 12 & 1) << 5 | (h >> 2) & 0x1f),
            ),
            // C.LWSP, C.LDSP: stack slots.
            (2, 2) => (Flow::Next, self.clobber(rd)),
            (2, 3) if wide => (Flow::Next, self.clobber(rd)),
            (2, 4) => match ((h >> 12) & 1, rs2) {
                // C.JR
                (0, 0) if rd != 0 => (self.jalr(0, rd, 0, loaded), Note::None),
                // C.MV
                (0, _) => (Flow::Next, self.add_imm(rd, rs2, 0, false)),
                // C.EBREAK
                (1, 0) if rd == 0 => (Flow::Stop, Note::None),
                // C.JALR
                (1, 0) => (self.jalr(RA, rd, 0, loaded), Note::None),
                // C.ADD
                (1, _) => (Flow::Next, self.add(rd, rd, rs2, scaled)),
                _ => (Flow::Invalid, Note::None),
            },
            // FP loads from the stack, stores to it.
            (2, _) => (Flow::Next, Note::None),
            _ => (Flow::Invalid, Note::None),
        };
        self.keep(note, (scaled, indexed, loaded, widened));
        (flow, note)
    }

    /// The target of C.J and C.JAL.
    fn cj(&self, h: u32) -> u64 {
        let imm = ((h >> 12) & 1) << 11
            | ((h >> 11) & 1) << 4
            | ((h >> 9) & 3) << 8
            | ((h >> 8) & 1) << 10
            | ((h >> 7) & 1) << 6
            | ((h >> 6) & 1) << 7
            | ((h >> 3) & 7) << 1
            | ((h >> 2) & 1) << 5;
        self.wrap(self.addr.wrapping_add_signed(sign(imm, 12)))
    }
}

/// `value`'s low `bits` bits, sign-extended.
fn sign(value: u32, bits: u32) -> i64 {
    let shift = 64 - bits;
    (i64::from(value) << shift) >> shift
}

/// Whether `bytes` begin a frame: the stack pointer lowered (`addi sp, sp,
/// -n`, `c.addi16sp sp, -n`, `c.addi sp, -n`) among the first three
/// instructions.
pub(crate) fn starts_frame(bytes: &[u8]) -> bool {
    let mut at = 0;
    for _ in 0..3 {
        let Some(half) = half_at(bytes, at) else {
            return false;
        };
        if half & 3 != 3 {
            // C.ADDI16SP and C.ADDI sp with the sign bit set.
            if half & 0xef83 == 0x6101 && half & 0x1000 != 0 {
                return true;
            }
            if half & 0xef83 == 0x0101 && half & 0x1000 != 0 {
                return true;
            }
            at += 2;
        } else {
            let Some(word) = word_at(bytes, at) else {
                return false;
            };
            if word & 0x000f_ffff == 0x0001_0113 && word >> 31 == 1 {
                return true;
            }
            at += 4;
        }
    }
    false
}

/// The value start-up code sets the global pointer to, from the first
/// instructions at `bytes`, mapped at `addr`: `auipc gp, hi; addi gp, gp,
/// lo` (the `.option norelax` sequence `_start` begins with).
pub(crate) fn gp_setup(bytes: &[u8], addr: u64, wide: bool) -> Option<u64> {
    let mut state = State::default();
    let config = Config { wide, gp: None };
    let mut at = 0_usize;
    for _ in 0..6 {
        let insn = decode(&mut state, config, bytes.get(at..)?, addr + at as u64);
        if let Note::Address { reg: GP, addr } = insn.note
            && matches!(bytes.get(at), Some(b) if b & 0x7f == 0x13)
        {
            return Some(addr);
        }
        if insn.flow != Flow::Next {
            return None;
        }
        at += insn.len as usize;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const RV64: Config = Config {
        wide: true,
        gp: None,
    };

    /// Decode `code` from `addr`, instruction by instruction.
    fn run(code: &[u8], addr: u64) -> Vec<Insn> {
        let mut state = State::default();
        let mut at = 0;
        let mut insns = Vec::new();
        while at < code.len() {
            let insn = decode(&mut state, RV64, &code[at..], addr + at as u64);
            at += insn.len as usize;
            insns.push(insn);
        }
        insns
    }

    fn words(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|w| w.to_le_bytes()).collect()
    }

    fn halves(halves: &[u16]) -> Vec<u8> {
        halves.iter().flat_map(|h| h.to_le_bytes()).collect()
    }

    #[test]
    fn transfers() {
        let insns = run(
            &words(&[
                0x0100_00ef, // jal ra, +0x10
                0x0100_006f, // j +0x10
                0x0000_8067, // ret
                0x0005_0067, // jr a0
                0x000500e7,  // jalr a0
                0x00b5_0463, // beq a0, a1, +8
                0x0010_0073, // ebreak
                0x0000_0013, // nop
            ]),
            0x1000,
        );
        let flows: Vec<Flow> = insns.iter().map(|insn| insn.flow).collect();
        assert_eq!(
            flows,
            [
                Flow::Call(0x1010),
                Flow::Jump(0x1014),
                Flow::Return,
                Flow::JumpRegister(10),
                Flow::CallRegister(10),
                Flow::Branch(0x101c),
                Flow::Stop,
                Flow::Next,
            ]
        );
        assert!(insns[7].pad);
    }

    #[test]
    fn compressed() {
        let insns = run(
            &halves(&[
                0x8082, // c.jr ra (ret)
                0x9502, // c.jalr a0
                0xa011, // c.j +4
                0xc111, // c.beqz a0, +4
                0x9002, // c.ebreak
                0x0001, // c.nop
                0x0000, // illegal
            ]),
            0x1000,
        );
        let flows: Vec<Flow> = insns.iter().map(|insn| insn.flow).collect();
        assert_eq!(
            flows,
            [
                Flow::Return,
                Flow::CallRegister(10),
                Flow::Jump(0x1008),
                Flow::Branch(0x100a),
                Flow::Stop,
                Flow::Next,
                Flow::Invalid,
            ]
        );
        assert!(insns.iter().all(|insn| insn.len == 2));
        assert!(insns[5].pad);
    }

    /// `auipc ra, 0x1; jalr ra, -0x10(ra)`: a call beyond `jal`'s reach;
    /// `auipc t1, 0; jr 0x20(t1)`: a far tail call.
    #[test]
    fn far_calls() {
        let insns = run(&words(&[0x0000_1097, 0xff00_80e7]), 0x1000);
        assert_eq!(insns[1].flow, Flow::Call(0x1ff0));
        let insns = run(&words(&[0x0000_0317, 0x0203_0067]), 0x1000);
        assert_eq!(insns[1].flow, Flow::Jump(0x1020));
    }

    /// A PLT stub: `auipc t3, 0x2; ld t3, 0x10(t3); jalr t1, t3; nop`.
    #[test]
    fn plt_stub() {
        let insns = run(
            &words(&[0x0000_2e17, 0x010e_3e03, 0x000e_0367, 0x0000_0013]),
            0x1000,
        );
        assert_eq!(insns[2].flow, Flow::JumpSlot(0x3010));
    }

    /// GCC's table: `li a5, 9; bgtu a0, a5, default; slli a0, a0, 2; lui
    /// a5, 0x12; addi a5, a5, 0x340; add a0, a0, a5; lw a0, 0(a0); jr a0`.
    #[test]
    fn zero_extended_index() {
        let insns = run(
            &words(&[
                0x0204_1793, // slli a5, s0, 32
                0x0001_2737, // lui a4, 0x12
                0x3407_0713, // addi a4, a4, 0x340
                0x01e7_d413, // srli s0, a5, 30
                0x00e4_0433, // add s0, s0, a4
                0x0004_2783, // lw a5, 0(s0)
                0x00e7_87b3, // add a5, a5, a4
                0x0007_8067, // jr a5
            ]),
            0x1000,
        );
        assert_eq!(insns[0].note, Note::Clobber(1 << 15));
        assert_eq!(insns[3].note, Note::Copy { reg: 8, src: 8 });
        assert_eq!(
            insns[5].note,
            Note::Load {
                reg: 15,
                mem: Mem {
                    base: Some(14),
                    index: Some(8),
                    scale: 4,
                    disp: 0,
                },
                size: 4,
                signed: true,
            }
        );
    }

    #[test]
    fn switch_notes() {
        let insns = run(
            &words(&[
                0x0090_0793, // li a5, 9
                0x00a7_e863, // bltu a5, a0, +16 (bgtu a0, a5)
                0x0025_1513, // slli a0, a0, 2
                0x0001_27b7, // lui a5, 0x12
                0x3407_8793, // addi a5, a5, 0x340
                0x00f5_0533, // add a0, a0, a5
                0x0005_2503, // lw a0, 0(a0)
                0x0005_0067, // jr a0
            ]),
            0x1000,
        );
        assert_eq!(insns[1].note, Note::Compare { reg: 10, imm: 9 });
        assert_eq!(
            insns[4].note,
            Note::Address {
                reg: 15,
                addr: 0x12340
            }
        );
        assert_eq!(insns[5].note, Note::None);
        assert_eq!(
            insns[6].note,
            Note::Load {
                reg: 10,
                mem: Mem {
                    base: Some(15),
                    index: Some(10),
                    scale: 4,
                    disp: 0,
                },
                size: 4,
                signed: true,
            }
        );
        assert_eq!(insns[7].flow, Flow::JumpRegister(10));
    }

    #[test]
    fn frames() {
        // addi sp, sp, -32
        assert!(starts_frame(&words(&[0xfe01_0113])));
        // c.addi16sp sp, -48
        assert!(starts_frame(&halves(&[0x7179])));
        // c.addi sp, -16
        assert!(starts_frame(&halves(&[0x1141])));
        assert!(!starts_frame(&words(&[0x0000_8067])));
    }

    #[test]
    fn global_pointer() {
        // auipc gp, 0x2; addi gp, gp, -0x7f0
        let code = words(&[0x0000_2197, 0x8101_8193]);
        assert_eq!(gp_setup(&code, 0x1000, true), Some(0x2810));
    }
}
