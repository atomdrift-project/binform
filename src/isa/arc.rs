//! Synopsys ARC (32-bit, little-endian): ARCompact (ARC600/ARC700) and
//! ARCv2 (EM, HS). Control flow, and the few register values jump tables
//! and calls through registers need.
//!
//! Instructions are 16 or 32 bits, stored as little-endian halfwords, the
//! most significant first. The top five bits pick the major opcode: on
//! ARCompact 0x00-0x0b are 32-bit and the rest 16-bit; on ARCv2 0x08-0x0b
//! are 16-bit too. A register field of 62 (`limm`; 30 in ARCv2's 16-bit
//! `h` field) reads a 32-bit immediate stored after the instruction, again
//! high halfword first: that is how code builds addresses (`mov_s r0,
//! main`). Register 63 reads as `pcl`, the instruction's address rounded
//! down to a word, which relative branches and PC-relative loads add to.
//!
//! Transfers delay only when their `.d` bit says so, and run the 16- or
//! 32-bit instruction after them first. Returns are `j_s [blink]` (or a
//! conditional `jeq_s [blink]`), ARCv2's `leave_s` with its jump bit, and
//! `rtie`. Compare-and-branch instructions (`brhs r1, 7, default`) bound
//! a case value as `cmp` does. GCC's tables are absolute (`ld.as r2,
//! [table, r2]; j_s [r2]`) or relative to `pcl` (`add_s r0, r0, 4; ldw.as
//! r0, [pcl, r0]; add_s r0, r0, pcl; j_s [r0]`, and a byte form with
//! `ldb_s`); ARCv2 adds `bi [c]` and `bih [c]`, which jump into a run of
//! branch instructions.

use crate::isa::{Extend, Flow, Insn, Mem, Note};

/// What earlier instructions left that a later one needs.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct State {
    /// The constant in each core register, and whether it was built like
    /// an address (from a `limm` or `pcl`) rather than from a short
    /// immediate.
    regs: [Option<(u64, bool)>; 32],
    /// A register holding another plus a constant, which a load folds
    /// into its displacement: the register and the constant. The walk was
    /// told the register is a copy of the other.
    displaced: Option<(u32, u64)>,
    /// The register a table entry was last loaded into.
    entry: Option<u32>,
    /// The last register loaded from a fixed address, and that address.
    loaded: Option<(u32, u64)>,
}

/// The link register calls set.
const BLINK: u32 = 31;
/// The stack pointer.
const SP: u32 = 28;
/// The `limm` register field.
const LIMM: u32 = 62;
/// The `pcl` register field.
const PCL: u32 = 63;
/// Where an address `st limm, [...]` stores goes: a pointer the program
/// keeps (a callback it registers). Register 61 is reserved.
const STORED: u32 = 61;
/// The registers a call may change: the arguments and temporaries (`r0`
/// to `r12`) and the link register.
const VOLATILE: u32 = 0x8000_1fff;

/// The halfword at `at`.
fn half(bytes: &[u8], at: usize) -> Option<u32> {
    let b: [u8; 2] = bytes.get(at..at + 2)?.try_into().ok()?;
    Some(u32::from(u16::from_le_bytes(b)))
}

/// The 32-bit word at `at`, high halfword first.
fn word_at(bytes: &[u8], at: usize) -> Option<u32> {
    Some(half(bytes, at)? << 16 | half(bytes, at + 2)?)
}

/// The bytes a load or store of size field `zz` moves: a word, a byte, a
/// halfword, or (ARCv2's `ldd`) a pair.
const fn zz_size(zz: u32) -> u8 {
    match zz & 3 {
        0 => 4,
        1 => 1,
        2 => 2,
        _ => 8,
    }
}

/// `value`'s low `bits` bits, sign-extended.
fn sign(value: u32, bits: u32) -> i64 {
    let shift = 64 - bits;
    (i64::from(value) << shift) >> shift
}

/// A 16-bit instruction's three-bit register field: `r0`-`r3`, `r12`-`r15`.
const fn short(field: u32) -> u32 {
    let field = field & 7;
    if field < 4 { field } else { field + 8 }
}

/// What one instruction is.
#[derive(Clone, Copy, Debug)]
enum Kind {
    /// No transfer; `None` when it does not decode.
    Op(Option<Note>),
    /// A transfer: where it goes, whether a delay slot runs first, whether
    /// it may not happen (a condition), and the compare it makes (a
    /// compare-and-branch).
    Transfer {
        flow: Flow,
        delay: bool,
        falls: bool,
        compare: Option<Note>,
    },
}

/// A second operand.
#[derive(Clone, Copy, Debug)]
enum Src {
    Reg(u32),
    /// A short immediate.
    Imm(u64),
}

pub(crate) fn decode(state: &mut State, bytes: &[u8], addr: u64, v2: bool) -> Insn {
    let mut cx = Cx { state, addr, v2 };
    let Some((len, kind)) = cx.parse(bytes) else {
        *cx.state = State::default();
        return Insn::new(2, Flow::Invalid);
    };
    let (flow, delay, falls, compare) = match kind {
        Kind::Op(Some(note)) => {
            let mut insn = Insn::new(len, Flow::Next);
            insn.note = note;
            // nop_s, nop (mov 0, 0)
            insn.pad = matches!(half(bytes, 0), Some(0x78e0))
                || (len == 4 && word_at(bytes, 0) == Some(0x264a_7000));
            return insn;
        }
        Kind::Op(None) => {
            *cx.state = State::default();
            return Insn::new(2, Flow::Invalid);
        }
        Kind::Transfer {
            flow,
            delay,
            falls,
            compare,
        } => (flow, delay, falls, compare),
    };
    let mut len = len;
    let mut note = compare.unwrap_or(Note::None);
    if delay {
        // A transfer may not sit in a delay slot; one with no slot after it
        // is cut short.
        let at = usize::try_from(len).unwrap_or(usize::MAX);
        cx.addr = addr.wrapping_add(u64::from(len)) & 0xffff_ffff;
        let slot = bytes.get(at..).and_then(|slot| cx.parse(slot));
        let Some((slot_len, Kind::Op(Some(slot_note)))) = slot else {
            *cx.state = State::default();
            return Insn::new(2, Flow::Invalid);
        };
        len += slot_len;
        // The slot's note, unless it leaves the compared register alone:
        // `brhs.d r1, 7, default; ld r4, [r5, -4]` still bounds `r1`.
        note = match compare {
            Some(compare @ Note::Compare { reg, .. })
                if slot_note.writes() >> reg & 1 == 0
                    && !matches!(
                        slot_note,
                        Note::Address { .. }
                            | Note::Fetch {
                                mem: Mem { base: None, .. },
                                ..
                            }
                    ) =>
            {
                compare
            }
            _ => slot_note,
        };
    }
    let state = cx.state;
    match flow {
        Flow::Next | Flow::Branch(_) => {}
        Flow::Call(_) | Flow::CallIndirect | Flow::CallRegister(_) | Flow::CallSlot(_) => {
            state.loaded = None;
            state.entry = None;
            state.displaced = None;
            for (reg, value) in state.regs.iter_mut().enumerate() {
                if VOLATILE >> reg & 1 != 0 {
                    *value = None;
                }
            }
        }
        _ if falls => {}
        _ => *state = State::default(),
    }
    let mut insn = Insn::new(len, flow);
    insn.note = note;
    insn.falls = falls;
    insn
}

struct Cx<'a> {
    state: &'a mut State,
    addr: u64,
    /// ARCv2's encodings, not ARCompact's.
    v2: bool,
}

impl Cx<'_> {
    fn pcl(&self) -> u64 {
        self.addr & 0xffff_fffc
    }

    /// The value of register `reg`, reading `limm` from `limm`, and whether
    /// it was built like an address.
    fn value(&self, reg: u32, limm: Option<u32>) -> Option<(u64, bool)> {
        match reg {
            LIMM => limm.map(|limm| (u64::from(limm), true)),
            PCL => Some((self.pcl(), true)),
            _ => self.state.regs.get(reg as usize).copied().flatten(),
        }
    }

    fn src(&self, src: Src, limm: Option<u32>) -> Option<(u64, bool)> {
        match src {
            Src::Reg(reg) => self.value(reg, limm),
            Src::Imm(imm) => Some((imm, false)),
        }
    }

    fn set(&mut self, reg: u32, value: Option<(u64, bool)>) {
        if let Some(slot) = self.state.regs.get_mut(reg as usize) {
            *slot = value.map(|(value, addr)| (value & 0xffff_ffff, addr));
        }
    }

    /// `reg` changes some way not modelled.
    fn clobber(&mut self, reg: u32) -> Note {
        self.set(reg, None);
        match reg {
            0..32 => Note::Clobber(1 << reg),
            LIMM | PCL => Note::None,
            _ => Note::Write(reg),
        }
    }

    fn clobber2(&mut self, a: u32, b: u32) -> Note {
        self.set(a, None);
        self.set(b, None);
        let mask = |reg: u32| if reg < 32 { 1 << reg } else { 0 };
        Note::Clobber(mask(a) | mask(b))
    }

    /// `reg = value`: an address when built like one, else an integer.
    fn constant(&mut self, reg: u32, value: u64, addr: bool) -> Note {
        if reg >= 32 {
            return self.clobber(reg);
        }
        let value = value & 0xffff_ffff;
        self.set(reg, Some((value, addr)));
        if addr {
            Note::Address { reg, addr: value }
        } else {
            Note::Pc { reg, addr: value }
        }
    }

    fn copy(&mut self, reg: u32, src: u32, limm: Option<u32>) -> Note {
        if reg >= 32 {
            return self.clobber(reg);
        }
        if let Some((value, addr)) = self.value(src, limm) {
            return self.constant(reg, value, addr);
        }
        if src >= 32 {
            return self.clobber(reg);
        }
        let value = self.value(src, limm);
        self.set(reg, value);
        if reg == src {
            return Note::None;
        }
        Note::Copy { reg, src }
    }

    /// Where a jump or call through register `reg` goes.
    fn through(&self, reg: u32, limm: Option<u32>, call: bool) -> Flow {
        match (self.value(reg, limm), self.state.loaded) {
            (Some((target, _)), _) if call => Flow::Call(target),
            (Some((target, _)), _) => Flow::Jump(target),
            (None, Some((loaded, slot))) if loaded == reg && call => Flow::CallSlot(slot),
            (None, Some((loaded, slot))) if loaded == reg => Flow::JumpSlot(slot),
            _ if call => Flow::CallRegister(reg),
            _ => Flow::JumpRegister(reg),
        }
    }

    /// The instruction at the start of `bytes`: its length, and what it is.
    fn parse(&mut self, bytes: &[u8]) -> Option<(u32, Kind)> {
        let first = half(bytes, 0)?;
        let major = first >> 11;
        let wide = if self.v2 { major < 8 } else { major < 12 };
        if wide {
            let word = word_at(bytes, 0)?;
            let limm_at = |uses: bool| -> Option<Option<u32>> {
                if uses {
                    word_at(bytes, 4).map(Some)
                } else {
                    Some(None)
                }
            };
            let uses = self.uses_limm(word);
            let limm = limm_at(uses)?;
            let len = if uses { 8 } else { 4 };
            let kind = self.wide(word, limm, len);
            Some((len, kind))
        } else {
            let (uses, len) = self.short_limm(first);
            let limm = if uses { Some(word_at(bytes, 2)?) } else { None };
            Some((len, self.narrow(first, limm, len)))
        }
    }

    /// Whether a 32-bit instruction reads a `limm`.
    fn uses_limm(&self, word: u32) -> bool {
        let major = word >> 27;
        let b = (word >> 24) & 7 | ((word >> 12) & 7) << 3;
        let c = (word >> 6) & 0x3f;
        match major {
            // Bcc, BLcc
            0 => false,
            1 if word & 0x1_0000 == 0 => false,
            // BRcc: b, or c when it is a register.
            1 => b == LIMM || (word & 0x10 == 0 && c == LIMM),
            2 => b == LIMM,
            // ST c, [b, s9]; ARCv2's bit 0 makes `c` a 6-bit immediate.
            3 => b == LIMM || (c == LIMM && !(self.v2 && word & 1 != 0)),
            _ => {
                let p = (word >> 22) & 3;
                let c_reg = match p {
                    0 => true,
                    3 => word & 0x20 == 0,
                    _ => false,
                };
                let sub = (word >> 16) & 0x3f;
                // LD a, [b, c] keeps its addressing mode where `p` is.
                let c_reg = c_reg || (major == 4 && (0x30..0x38).contains(&sub));
                // MOV, LR and the single-operand instructions only write
                // `b` (62 is no register then).
                let b_read = !(matches!(major, 4 | 5) && matches!(sub, 0x0a | 0x2a | 0x2f));
                (b_read && b == LIMM) || (c_reg && c == LIMM)
            }
        }
    }

    /// Whether a 16-bit instruction reads a `limm`, and its length.
    fn short_limm(&self, half: u32) -> (bool, u32) {
        let major = half >> 11;
        let uses = if self.v2 {
            let h = ((half >> 5) & 7) | (half & 3) << 3;
            match major {
                // mov_s g, h; ld_s rN, [h, u5]
                0x08 => h == 30,
                0x0e => match (half >> 2) & 7 {
                    // mov_s h, s3: h = 30 is no register, and no limm.
                    3 => false,
                    _ => h == 30,
                },
                _ => false,
            }
        } else {
            major == 0x0e && ((half & 7) << 3 | (half >> 5) & 7) == LIMM
        };
        (uses, if uses { 6 } else { 2 })
    }

    /// A 32-bit instruction.
    #[allow(clippy::too_many_lines)]
    fn wide(&mut self, word: u32, limm: Option<u32>, len: u32) -> Kind {
        let major = word >> 27;
        let b = (word >> 24) & 7 | ((word >> 12) & 7) << 3;
        let c = (word >> 6) & 0x3f;
        let a = word & 0x3f;
        let delay = word & 0x20 != 0;
        let pcl = self.pcl();
        let relative = |offset: i64| pcl.wrapping_add_signed(offset) & 0xffff_ffff;
        match major {
            // Bcc s21; B s25
            0 => {
                let low = ((word >> 17) & 0x3ff) << 1 | ((word >> 6) & 0x3ff) << 11;
                if word & 0x1_0000 == 0 {
                    let to = relative(sign(low, 21));
                    let cond = word & 0x1f;
                    let flow = if cond == 0 {
                        Flow::Jump(to)
                    } else {
                        Flow::Branch(to)
                    };
                    transfer(flow, delay)
                } else {
                    if word & 0x10 != 0 {
                        return Kind::Op(None);
                    }
                    let to = relative(sign(low | (word & 0xf) << 21, 25));
                    transfer(Flow::Jump(to), delay)
                }
            }
            1 if word & 0x1_0000 == 0 => {
                // BLcc s21; BL s25
                let low = ((word >> 18) & 0x1ff) << 2 | ((word >> 6) & 0x3ff) << 11;
                let to = if word & 0x2_0000 == 0 {
                    relative(sign(low, 21))
                } else {
                    if word & 0x10 != 0 {
                        return Kind::Op(None);
                    }
                    relative(sign(low | (word & 0xf) << 21, 25))
                };
                transfer(Flow::Call(to), delay)
            }
            // BRcc b, c, s9; BBIT0, BBIT1
            1 => {
                // BREQ, BRNE, BRLT, BRGE, BRLO, BRHS, BBIT0, BBIT1; bit 3
                // is not read.
                let sub = word & 7;
                let offset = ((word >> 17) & 0x7f) << 1 | ((word >> 15) & 1) << 8;
                let to = relative(sign(offset, 9));
                let src = if word & 0x10 == 0 {
                    Src::Reg(c)
                } else {
                    Src::Imm(u64::from(c))
                };
                let compare = match sub {
                    // BRLO, BRHS: unsigned, below `c` in range.
                    4 | 5 => self.bound(b, src, limm, 1),
                    _ => None,
                };
                Kind::Transfer {
                    flow: Flow::Branch(to),
                    delay,
                    falls: false,
                    compare,
                }
            }
            // LD a, [b, s9]
            2 => {
                let s9 = sign(((word >> 15) & 1) << 8 | ((word >> 16) & 0xff), 9);
                let aa = (word >> 9) & 3;
                let zz = (word >> 7) & 3;
                let signed = word & 0x40 != 0;
                if zz == 3 && !self.v2 {
                    return Kind::Op(None);
                }
                let size = zz_size(zz);
                // .as scales the offset by the size.
                let disp = match aa {
                    3 => s9 << zz_size(zz).trailing_zeros().min(2),
                    _ => s9,
                };
                Kind::Op(Some(self.load(
                    a,
                    b,
                    Src::Imm(disp.cast_unsigned()),
                    1,
                    aa,
                    size,
                    signed,
                    limm,
                )))
            }
            // ST c, [b, s9]
            3 => {
                if word & 1 != 0 && !self.v2 {
                    return Kind::Op(None);
                }
                let aa = (word >> 3) & 3;
                Kind::Op(Some(if matches!(aa, 1 | 2) && b != LIMM {
                    self.clobber(b)
                } else if c == LIMM
                    && word & 1 == 0
                    && let Some(addr) = limm
                {
                    Note::Address {
                        reg: STORED,
                        addr: u64::from(addr),
                    }
                } else {
                    Note::None
                }))
            }
            4..=7 => self.general(word, limm, len),
            _ => Kind::Op(None),
        }
    }

    /// The general format of majors 4 to 7: `op a, b, c` with `c` a
    /// register or `u6` (`p` 0 and 1), `op b, b, s12` (2), or a conditional
    /// `op.cc b, b, c` (3).
    #[allow(clippy::too_many_lines)]
    fn general(&mut self, word: u32, limm: Option<u32>, len: u32) -> Kind {
        let major = word >> 27;
        let sub = (word >> 16) & 0x3f;
        let p = (word >> 22) & 3;
        let b = (word >> 24) & 7 | ((word >> 12) & 7) << 3;
        let c = (word >> 6) & 0x3f;
        let a = word & 0x3f;
        let valid: u64 = match (major, self.v2) {
            (4, false) => 0x00ff_8f0f_3fff_ffff,
            (4, true) => 0xffff_bfff_ffff_ffff,
            (5, false) => 0x03ff_93c0_0017_7dcf,
            (5, true) => u64::MAX,
            (6, false) => 0x0000_87ff_03ff_ff07,
            (6, true) => 0x03ff_bfff_ffff_ffff,
            (7, true) => 0x0000_8007_0000_0000,
            _ => 0,
        };
        if valid >> sub & 1 == 0 {
            return Kind::Op(None);
        }
        // LD a, [b, c]: the addressing mode sits where `p` is.
        if major == 4 && (0x30..0x38).contains(&sub) {
            let aa = p;
            let zz = (word >> 17) & 3;
            if zz == 3 && !self.v2 {
                return Kind::Op(None);
            }
            let size = zz_size(zz);
            let scale = if aa == 3 { zz_size(zz) } else { 1 };
            let signed = word & 0x1_0000 != 0;
            return Kind::Op(Some(self.load(
                a,
                b,
                Src::Reg(c),
                scale,
                aa,
                size,
                signed,
                limm,
            )));
        }
        let (dest, src, cond) = match p {
            0 => (a, Src::Reg(c), 0),
            1 => (a, Src::Imm(u64::from(c)), 0),
            2 => (
                b,
                Src::Imm(sign(c | (word & 0x3f) << 6, 12).cast_unsigned() & 0xffff_ffff),
                0,
            ),
            _ => (
                b,
                if word & 0x20 == 0 {
                    Src::Reg(c)
                } else {
                    Src::Imm(u64::from(c))
                },
                word & 0x1f,
            ),
        };
        if major == 4 {
            match sub {
                // J, J.D, JL, JL.D
                0x20..=0x23 => {
                    let call = sub >= 0x22;
                    let delay = sub & 1 != 0;
                    let flow = match src {
                        // j [blink]; j.f [ilink1], [ilink2]
                        Src::Reg(BLINK | 29 | 30) if !call => Flow::Return,
                        Src::Reg(reg) => self.through(reg, limm, call),
                        Src::Imm(to) if call => Flow::Call(to),
                        Src::Imm(to) => Flow::Jump(to),
                    };
                    return Kind::Transfer {
                        flow,
                        delay,
                        falls: cond != 0 && !call,
                        compare: None,
                    };
                }
                // BI [c], BIH [c] (ARCv2): into a run of 32- or 16-bit
                // branches after it.
                0x24 | 0x25 if self.v2 => {
                    let Src::Reg(reg) = src else {
                        return Kind::Op(None);
                    };
                    let next = self.addr.wrapping_add(u64::from(len)) & 0xffff_ffff;
                    return Kind::Transfer {
                        flow: Flow::JumpTable {
                            mem: Mem {
                                base: None,
                                index: Some(reg),
                                scale: 1,
                                disp: 0,
                            },
                            size: 0,
                            base: next,
                            shift: if sub == 0x24 { 2 } else { 1 },
                        },
                        delay: false,
                        falls: false,
                        compare: None,
                    };
                }
                // LP: a zero-overhead loop, ending at its target.
                0x28 => {
                    let offset = match (p, src) {
                        (2, Src::Imm(imm)) => imm.cast_signed() << 1,
                        (3, Src::Imm(imm)) => imm.cast_signed() << 1,
                        _ => return Kind::Op(None),
                    };
                    let to = self.pcl().wrapping_add_signed(offset) & 0xffff_ffff;
                    return Kind::Transfer {
                        flow: Flow::Branch(to),
                        delay: false,
                        falls: false,
                        compare: None,
                    };
                }
                // FLAG: bit 0 halts.
                0x29 => {
                    let halts = matches!(self.src(src, limm), Some((value, false)) if value & 1 != 0)
                        && cond == 0;
                    return if halts {
                        Kind::Transfer {
                            flow: Flow::Stop,
                            delay: false,
                            falls: false,
                            compare: None,
                        }
                    } else {
                        Kind::Op(Some(Note::None))
                    };
                }
                // Single-operand instructions: `op b, c`.
                0x2f => return self.single(word, b, src, limm),
                _ => {}
            }
        }
        if major != 4 {
            // Extension ALU instructions: write their destination.
            if sub == 0x2f {
                return Kind::Op(Some(if a == 0x3f {
                    Note::None
                } else {
                    self.clobber(b)
                }));
            }
            return Kind::Op(Some(self.clobber(dest)));
        }
        let conditional = cond != 0;
        let note = match sub {
            // ADD, SUB, ADD1-3, SUB1-3
            0x00 | 0x02 | 0x14..=0x19 if !conditional => {
                let shift = match sub {
                    0x14..=0x16 => sub - 0x13,
                    0x17..=0x19 => sub - 0x16,
                    _ => 0,
                };
                let negate = sub == 0x02 || sub >= 0x17;
                self.add(dest, b, src, shift, negate, limm)
            }
            // MOV b, c
            0x0a if !conditional => match src {
                Src::Reg(reg) => self.copy(b, reg, limm),
                Src::Imm(imm) => self.constant(b, imm, false),
            },
            // AND, OR with constants
            0x04 | 0x05 if !conditional => match self.value(b, limm).zip(self.src(src, limm)) {
                Some(((x, ax), (y, ay))) => {
                    let value = if sub == 0x04 { x & y } else { x | y };
                    self.constant(dest, value, ax || ay)
                }
                None => self.clobber(dest),
            },
            // TST, CMP, RCMP, BTST: flags only.
            0x0b | 0x0d | 0x11 => Note::None,
            0x0c => {
                let note = self.bound(b, src, limm, 0).unwrap_or(Note::None);
                if let Note::Compare { reg, .. } = note
                    && self.state.displaced.is_some_and(|(held, _)| held == reg)
                {
                    self.state.displaced = None;
                }
                note
            }
            // LR (an auxiliary register), SR, AEX, LDI
            0x2a | 0x26 | 0x27 => self.clobber(b),
            0x2b => Note::None,
            _ => self.clobber(dest),
        };
        Kind::Op(Some(note))
    }

    /// `op b, c` (the general format's sub-opcode 0x2f): the operation is
    /// in the `a` field; 0x3f holds the ones without operands.
    fn single(&mut self, word: u32, b: u32, src: Src, limm: Option<u32>) -> Kind {
        let op = word & 0x3f;
        let ok = if self.v2 {
            matches!(op, 0x00..=0x0d | 0x10..=0x13 | 0x3f)
        } else {
            matches!(op, 0x00..=0x0c | 0x10 | 0x11 | 0x3f)
        };
        if !ok {
            return Kind::Op(None);
        }
        if op != 0x3f {
            // EXTB, EXTW of a constant stay constants.
            let note = match (op, self.src(src, limm)) {
                (0x07, Some((value, addr))) => self.constant(b, value & 0xff, addr),
                (0x08, Some((value, addr))) => self.constant(b, value & 0xffff, addr),
                _ => self.clobber(b),
            };
            return Kind::Op(Some(note));
        }
        let zop = b;
        let flow = match (zop, self.v2) {
            // RTIE
            (4, _) => Flow::Return,
            // BRK
            (5, _) => Flow::Stop,
            // SLEEP, SWI/TRAP0, SYNC; ARCv2's SETI, CLRI, WEVT, WLFC, DSYNC,
            // DMB
            (1..=3, _) | (6..=0x0b, true) => return Kind::Op(Some(Note::None)),
            _ => return Kind::Op(None),
        };
        Kind::Transfer {
            flow,
            delay: false,
            falls: false,
            compare: None,
        }
    }

    /// A compare of register `reg` with `src`: a bound when `src` is a
    /// constant. `less` is 1 when in range means below `src` (`brlo`).
    fn bound(&self, reg: u32, src: Src, limm: Option<u32>, less: u64) -> Option<Note> {
        if reg >= 32 || self.value(reg, limm).is_some() {
            return None;
        }
        let (n, _) = self.src(src, limm)?;
        Some(Note::Compare {
            reg,
            imm: n.checked_sub(less)?,
        })
    }

    /// `dest = b + (src << shift)` (or minus): a constant, a copy of a
    /// register a load folds the constant into, an entry made relative, or
    /// a register sum.
    fn add(
        &mut self,
        dest: u32,
        b: u32,
        src: Src,
        shift: u32,
        negate: bool,
        limm: Option<u32>,
    ) -> Note {
        if dest >= 32 {
            return self.clobber(dest);
        }
        let x = self.value(b, limm);
        let y = self.src(src, limm);
        let scaled = |value: u64| {
            let value = value << shift;
            if negate { value.wrapping_neg() } else { value }
        };
        // `pcl` plus an offset is mostly the address of data kept in the
        // code (constants, tables): held, but no pointer to a function.
        let pc_relative = b == PCL || matches!(src, Src::Reg(PCL));
        match (x, y) {
            (Some((x, ax)), Some((y, ay))) => {
                self.constant(dest, x.wrapping_add(scaled(y)), (ax || ay) && !pc_relative)
            }
            // A table entry plus a base.
            (None, Some((y, _))) if self.state.entry == Some(b) && shift == 0 && !negate => {
                self.set(dest, None);
                Note::Offset {
                    reg: dest,
                    src: b,
                    imm: y & 0xffff_ffff,
                }
            }
            (None, Some((y, _))) if b < 32 => {
                let note = self.copy(dest, b, limm);
                self.state.displaced = Some((dest, scaled(y) & 0xffff_ffff));
                note
            }
            (Some((x, _)), None) if !negate && shift == 0 => match src {
                Src::Reg(reg) if reg < 32 => {
                    if self.state.entry == Some(reg) {
                        self.set(dest, None);
                        return Note::Offset {
                            reg: dest,
                            src: reg,
                            imm: x & 0xffff_ffff,
                        };
                    }
                    let note = self.copy(dest, reg, limm);
                    self.state.displaced = Some((dest, x & 0xffff_ffff));
                    note
                }
                _ => self.clobber(dest),
            },
            (None, None) if !negate && b < 32 => match src {
                Src::Reg(reg) if reg < 32 => {
                    self.set(dest, None);
                    Note::Add {
                        reg: dest,
                        base: b,
                        index: reg,
                        shift: u8::try_from(shift).unwrap_or(0),
                        extend: Extend::None,
                    }
                }
                _ => self.clobber(dest),
            },
            _ => self.clobber(dest),
        }
    }

    /// `a = [b + index * scale]`, `index` a register or a constant offset,
    /// with addressing mode `aa` (1 and 2 write the address back to `b`).
    #[allow(clippy::too_many_arguments)]
    fn load(
        &mut self,
        a: u32,
        b: u32,
        index: Src,
        scale: u8,
        aa: u32,
        size: u8,
        signed: bool,
        limm: Option<u32>,
    ) -> Note {
        if matches!(aa, 1 | 2) && b < 32 {
            return self.clobber2(a, b);
        }
        if a >= 32 {
            return self.clobber(a);
        }
        let base = self.value(b, limm);
        let displaced = self.state.displaced;
        let folded = |reg: u32| displaced.filter(|&(held, _)| held == reg).map(|(_, k)| k);
        let note = match (base, index) {
            // [constant + register]: a table indexed by the register.
            (Some((base, _)), Src::Reg(reg)) if reg < 32 && self.value(reg, limm).is_none() => {
                let disp =
                    base.wrapping_add(folded(reg).unwrap_or(0).wrapping_mul(u64::from(scale)));
                Some(Note::Load {
                    reg: a,
                    mem: Mem {
                        base: None,
                        index: Some(reg),
                        scale,
                        disp: disp & 0xffff_ffff,
                    },
                    size,
                    signed,
                })
            }
            // [register + constant], the register a constant plus a case
            // value: a table of bytes after `pcl`.
            (None, index) if b < 32 && folded(b).is_some() && scale == 1 => {
                let offset = match index {
                    Src::Imm(imm) => Some(imm),
                    Src::Reg(reg) => self.value(reg, limm).map(|(value, _)| value),
                };
                offset.map(|offset| Note::Load {
                    reg: a,
                    mem: Mem {
                        base: None,
                        index: Some(b),
                        scale: 1,
                        disp: folded(b).unwrap_or(0).wrapping_add(offset) & 0xffff_ffff,
                    },
                    size,
                    signed,
                })
            }
            _ => None,
        };
        if let Some(note) = note {
            self.set(a, None);
            self.state.entry = Some(a);
            return note;
        }
        let offset = match index {
            Src::Imm(imm) => Some(imm),
            Src::Reg(reg) => self.value(reg, limm).map(|(value, _)| value),
        };
        self.set(a, None);
        if size != 4 {
            return Note::Clobber(1 << a);
        }
        match (base, offset) {
            (Some((base, _)), Some(offset)) => {
                let slot = base.wrapping_add(offset) & 0xffff_ffff;
                self.state.loaded = Some((a, slot));
                Note::Fetch {
                    reg: a,
                    mem: Mem {
                        base: None,
                        index: None,
                        scale: 1,
                        disp: slot,
                    },
                    size,
                    signed: false,
                }
            }
            (None, Some(offset)) if b < 32 => Note::Fetch {
                reg: a,
                mem: Mem {
                    base: Some(b),
                    index: None,
                    scale: 1,
                    disp: offset & 0xffff_ffff,
                },
                size,
                signed: false,
            },
            _ => Note::Clobber(1 << a),
        }
    }

    /// A 16-bit instruction.
    #[allow(clippy::too_many_lines)]
    fn narrow(&mut self, half: u32, limm: Option<u32>, len: u32) -> Kind {
        let major = half >> 11;
        let b = short(half >> 8);
        let c = short(half >> 5);
        let a = short(half);
        let pcl = self.pcl();
        let relative = |offset: i64| pcl.wrapping_add_signed(offset) & 0xffff_ffff;
        let op = |note: Note| Kind::Op(Some(note));
        let branch = |flow: Flow| transfer(flow, false);
        let _ = len;
        match major {
            // ARCv2: mov_s g, h; ld_s r0-r3, [h, u5]
            0x08 => {
                let h = ((half >> 5) & 7) | (half & 3) << 3;
                let h = if h == 30 { LIMM } else { h };
                if half & 4 == 0 {
                    let g = ((half >> 8) & 7) | ((half >> 3) & 3) << 3;
                    if g == 30 {
                        return op(Note::None);
                    }
                    op(self.copy(g, h, limm))
                } else {
                    let dest = (half >> 8) & 3;
                    let u5 = (((half >> 3) & 3) | ((half >> 10) & 1) << 2) << 2;
                    op(self.load(dest, h, Src::Imm(u64::from(u5)), 1, 0, 4, false, limm))
                }
            }
            // ARCv2: ld_s.as a, [b, c]; sub_s a, b, c; add_s r0/r1, b, u6
            0x09 => {
                if half & 8 != 0 {
                    let dest = (half >> 7) & 1;
                    let u6 = ((half & 7) | ((half >> 4) & 7) << 3) as u64;
                    op(self.add(dest, b, Src::Imm(u6), 0, false, None))
                } else if half & 0x10 == 0 {
                    op(self.load(a, b, Src::Reg(c), 4, 3, 4, false, None))
                } else {
                    op(self.clobber(a))
                }
            }
            // ARCv2: ld_s r1, [gp, s11]; ldi_s b, u7; st_s r0, [gp, s11]
            0x0a => {
                if half & 8 != 0 {
                    op(self.clobber(b))
                } else if half & 0x10 == 0 {
                    op(self.clobber(1))
                } else {
                    op(Note::None)
                }
            }
            // ARCv2: jli_s u10 (a call through a table); ei_s u10
            0x0b => {
                if half & 0x400 == 0 {
                    branch(Flow::CallIndirect)
                } else {
                    op(Note::None)
                }
            }
            // ld_s a, [b, c]; ldb_s; ldw_s; add_s a, b, c
            0x0c => match (half >> 3) & 3 {
                3 => op(self.add(a, b, Src::Reg(c), 0, false, None)),
                sub => {
                    let size = match sub {
                        0 => 4,
                        1 => 1,
                        _ => 2,
                    };
                    op(self.load(a, b, Src::Reg(c), 1, 0, size, false, None))
                }
            },
            // add_s c, b, u3; sub_s; asl_s; asr_s
            0x0d => {
                let u3 = u64::from(half & 7);
                match (half >> 3) & 3 {
                    0 => op(self.add(c, b, Src::Imm(u3), 0, false, None)),
                    1 => op(self.add(c, b, Src::Imm(u3), 0, true, None)),
                    _ => op(self.clobber(c)),
                }
            }
            0x0e if self.v2 => {
                let h = ((half >> 5) & 7) | (half & 3) << 3;
                let s3 = {
                    let s = (half >> 8) & 7;
                    // -1 is encoded as 7.
                    if s == 7 { u64::MAX } else { u64::from(s) }
                };
                let hreg = if h == 30 { LIMM } else { h };
                match (half >> 2) & 7 {
                    0 => op(self.add(b, b, Src::Reg(hreg), 0, false, limm)),
                    1 if h == 30 => op(Note::None),
                    1 => op(self.add(h, h, Src::Imm(s3), 0, false, None)),
                    3 if h == 30 => op(Note::None),
                    3 => op(self.constant(h, s3, false)),
                    4 => op(self.bound(b, Src::Reg(hreg), limm, 0).unwrap_or(Note::None)),
                    5 => op(if h == 30 {
                        Note::None
                    } else {
                        self.bound(h, Src::Imm(s3), None, 0).unwrap_or(Note::None)
                    }),
                    // mov_s.ne b, h
                    7 => op(self.clobber(b)),
                    _ => Kind::Op(None),
                }
            }
            // add_s b, b, h; mov_s b, h; cmp_s b, h; mov_s h, b
            0x0e => {
                let h = (half & 7) << 3 | (half >> 5) & 7;
                match (half >> 3) & 3 {
                    0 => op(self.add(b, b, Src::Reg(h), 0, false, limm)),
                    1 => op(self.copy(b, h, limm)),
                    2 => op(self.bound(b, Src::Reg(h), limm, 0).unwrap_or(Note::None)),
                    _ if h == LIMM => op(Note::None),
                    _ => op(self.copy(h, b, None)),
                }
            }
            0x0f => self.general_short(half, b, c),
            // ld_s c, [b, u7]; ldb_s; ldw_s; ldw_s.x
            0x10..=0x13 => {
                let (size, signed) = match major {
                    0x10 => (4, false),
                    0x11 => (1, false),
                    0x12 => (2, false),
                    _ => (2, true),
                };
                let u5 = u64::from(half & 0x1f) * u64::from(size);
                op(self.load(c, b, Src::Imm(u5), 1, 0, size, signed, None))
            }
            // st_s, stb_s, stw_s
            0x14..=0x16 => op(Note::None),
            // asl_s, lsr_s, asr_s, sub_s, bset_s, bclr_s, bmsk_s b, b, u5;
            // btst_s
            0x17 => match (half >> 5) & 7 {
                3 => op(self.add(b, b, Src::Imm(u64::from(half & 0x1f)), 0, true, None)),
                7 => op(Note::None),
                _ => op(self.clobber(b)),
            },
            // Stack-pointer forms.
            0x18 => {
                let u5 = half & 0x1f;
                match (half >> 5) & 7 {
                    0 => op(self.load(b, SP, Src::Imm(u64::from(u5 * 4)), 1, 0, 4, false, None)),
                    1 => op(self.clobber(b)),
                    2 | 3 => op(Note::None),
                    4 => op(self.clobber(b)),
                    // add_s, sub_s sp, sp, u7
                    5 => match (half >> 8) & 7 {
                        0 | 1 => op(self.clobber(SP)),
                        _ => Kind::Op(None),
                    },
                    // pop_s b, pop_s blink; ARCv2's leave_s
                    6 => match u5 {
                        1 => op(self.clobber2(b, SP)),
                        0x11 => op(self.clobber2(BLINK, SP)),
                        _ if self.v2 && half & 1 == 0 => {
                            if half & 0x400 != 0 {
                                branch(Flow::Return)
                            } else {
                                op(Note::Clobber(0x3fff_e000 | 1 << BLINK))
                            }
                        }
                        _ => Kind::Op(None),
                    },
                    // push_s b, push_s blink; ARCv2's enter_s
                    _ => match u5 {
                        1 | 0x11 => op(self.clobber(SP)),
                        _ if self.v2 && half & 0x301 == 0 => op(self.clobber2(SP, 27)),
                        _ => Kind::Op(None),
                    },
                }
            }
            // ld_s r0, [gp, s11]; ldb_s; ldw_s; add_s r0, gp, s11
            0x19 => op(self.clobber(0)),
            // ld_s b, [pcl, u10]
            0x1a => {
                let u10 = u64::from(half & 0xff) * 4;
                op(self.load(b, PCL, Src::Imm(u10), 1, 0, 4, false, None))
            }
            // mov_s b, u8
            0x1b => op(self.constant(b, u64::from(half & 0xff), false)),
            // add_s b, b, u7; cmp_s b, u7
            0x1c => {
                let u7 = u64::from(half & 0x7f);
                if half & 0x80 == 0 {
                    op(self.add(b, b, Src::Imm(u7), 0, false, None))
                } else {
                    let note = self.bound(b, Src::Imm(u7), None, 0).unwrap_or(Note::None);
                    if self.state.displaced.is_some_and(|(held, _)| held == b) {
                        self.state.displaced = None;
                    }
                    op(note)
                }
            }
            // breq_s, brne_s b, 0, s8
            0x1d => branch(Flow::Branch(relative(sign((half & 0x7f) << 1, 8)))),
            // b_s, beq_s, bne_s s10; bcc_s s7
            0x1e => match (half >> 9) & 3 {
                0 => branch(Flow::Jump(relative(sign((half & 0x1ff) << 1, 10)))),
                1 | 2 => branch(Flow::Branch(relative(sign((half & 0x1ff) << 1, 10)))),
                _ => branch(Flow::Branch(relative(sign((half & 0x3f) << 1, 7)))),
            },
            // bl_s s13
            _ => branch(Flow::Call(relative(sign((half & 0x7ff) << 2, 13)))),
        }
    }

    /// The 16-bit general format: `op_s b, b, c`, sub-opcode in the low
    /// five bits.
    fn general_short(&mut self, half: u32, b: u32, c: u32) -> Kind {
        let op = |note: Note| Kind::Op(Some(note));
        match half & 0x1f {
            0x00 => match (half >> 5) & 7 {
                // j_s [b], j_s.d [b], jl_s [b], jl_s.d [b]
                sub @ 0..=3 => {
                    let call = sub >= 2;
                    let flow = if b == BLINK {
                        Flow::Return
                    } else {
                        self.through(b, None, call)
                    };
                    transfer(flow, sub & 1 != 0)
                }
                // sub_s.ne b, b, b
                6 => op(self.clobber(b)),
                // Instructions without operands, in `b`.
                7 => match (half >> 8) & 7 {
                    0 => op(Note::None),
                    // unimp_s
                    1 => transfer(Flow::Stop, false),
                    // swi_s
                    2 if self.v2 => op(Note::None),
                    // jeq_s [blink], jne_s [blink]
                    4 | 5 => Kind::Transfer {
                        flow: Flow::Return,
                        delay: false,
                        falls: true,
                        compare: None,
                    },
                    6 => transfer(Flow::Return, false),
                    7 => transfer(Flow::Return, true),
                    _ => Kind::Op(None),
                },
                _ => Kind::Op(None),
            },
            0x02 => op(self.add(b, b, Src::Reg(c), 0, true, None)),
            0x04..=0x07 | 0x0d..=0x13 | 0x18..=0x1d => op(self.clobber(b)),
            // mpyw_s, mpyuw_s, mpy_s (ARCv2)
            0x09 | 0x0a | 0x0c if self.v2 => op(self.clobber(b)),
            // tst_s
            0x0b => op(Note::None),
            // add1_s, add2_s, add3_s
            sub @ 0x14..=0x16 => op(self.add(b, b, Src::Reg(c), sub - 0x13, false, None)),
            // trap_s u6: a system call, which returns.
            0x1e => op(Note::None),
            // brk_s; ARCv2's swi_s u6
            _ if half == 0x7fff => transfer(Flow::Stop, false),
            0x1f if self.v2 => op(Note::None),
            _ => Kind::Op(None),
        }
    }
}

const fn transfer(flow: Flow, delay: bool) -> Kind {
    Kind::Transfer {
        flow,
        delay,
        falls: false,
        compare: None,
    }
}

/// Whether `bytes` are one of the entries into GCC's millicode epilogue
/// (`__ld_r13_to_rN_ret`), which functions built with `-mmillicode` jump to
/// rather than call: a run of `ld rN, [sp, 4 * (N - 13)]`, highest first,
/// ending in `ld blink, [sp, r12]`.
pub(crate) fn millicode(bytes: &[u8]) -> bool {
    let mut at = 0;
    let mut last = 26;
    for _ in 0..14 {
        let Some(word) = word_at(bytes, at) else {
            return false;
        };
        // ld blink, [sp, r12]
        if word == 0x2430_331f {
            return true;
        }
        let b = (word >> 24) & 7 | ((word >> 12) & 7) << 3;
        let a = word & 0x3f;
        let s9 = ((word >> 15) & 1) << 8 | ((word >> 16) & 0xff);
        // ld rN, [sp, s9]: no write-back, a word, no sign extension.
        if word >> 27 != 2 || b != SP || word & 0x7c0 != 0 || !(13..last).contains(&a) {
            return false;
        }
        if s9 != 4 * (a - 13) {
            return false;
        }
        last = a;
        at += 4;
    }
    false
}

/// Whether `bytes` begin a frame: the link register pushed (`push_s
/// blink`, `st.a blink, [sp, -n]`), the stack pointer lowered (`sub_s sp,
/// sp, u7`, `sub sp, sp, n`, `st.a rN, [sp, -n]`) or ARCv2's `enter_s`
/// among the first three instructions.
pub(crate) fn starts_frame(bytes: &[u8], v2: bool) -> bool {
    let mut state = State::default();
    let mut at = 0usize;
    for _ in 0..3 {
        let Some(rest) = bytes.get(at..) else {
            return false;
        };
        let Some(first) = half(rest, 0) else {
            return false;
        };
        let major = first >> 11;
        let wide = if v2 { major < 8 } else { major < 12 };
        if wide {
            let Some(word) = word_at(rest, 0) else {
                return false;
            };
            let b = (word >> 24) & 7 | ((word >> 12) & 7) << 3;
            // st.a c, [sp, -n]
            if word >> 27 == 3 && b == SP && (word >> 3) & 3 == 1 && word & 0x8000 != 0 {
                return true;
            }
            // sub sp, sp, u6 / s12
            if word >> 27 == 4
                && (word >> 16) & 0x3f == 0x02
                && b == SP
                && matches!((word >> 22) & 3, 1 | 2)
                && ((word >> 22) & 3 == 2 || word & 0x3f == SP)
            {
                return true;
            }
        } else if first == 0xc0f1 || first & 0xffe0 == 0xc1a0 || (v2 && first & 0xfce1 == 0xc0e0) {
            return true;
        }
        let mut cx = Cx {
            state: &mut state,
            addr: 0,
            v2,
        };
        match cx.parse(rest) {
            Some((len, Kind::Op(Some(_)))) => at += len as usize,
            _ => return false,
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Halfwords to bytes; a 32-bit instruction or `limm` is two of them,
    /// high first.
    fn code(halves: &[u16]) -> Vec<u8> {
        halves.iter().flat_map(|h| h.to_le_bytes()).collect()
    }

    fn run(halves: &[u16], addr: u64, v2: bool) -> Vec<(u64, Insn)> {
        let code = code(halves);
        let mut state = State::default();
        let mut at = 0;
        let mut insns = Vec::new();
        while at < code.len() {
            let insn = decode(&mut state, &code[at..], addr + at as u64, v2);
            insns.push((addr + at as u64, insn));
            at += insn.len as usize;
        }
        insns
    }

    fn flows(halves: &[u16], addr: u64) -> Vec<(u64, u32, Flow)> {
        run(halves, addr, false)
            .into_iter()
            .map(|(at, insn)| (at, insn.len, insn.flow))
            .collect()
    }

    /// From rizin's disassembly of a bot's `.text`.
    #[test]
    fn transfers() {
        assert_eq!(
            flows(
                &[
                    0x0ebe, 0x0560, // 0x1014c bl.d 0x1b008
                    0xd901, // mov_s r1, 1
                    0x70a9, // mov_s r0, r13
                    0xedfb, // 0x10154 brne_s r13, 0, 0x1014a
                    0x1404, 0x301f, // ld blink, [sp, 4]
                    0xc500, // ld_s r13, [sp, 0]
                    0x7fe0, // 0x1015c j_s.d [blink]
                    0xc0a2, // add_s sp, sp, 8
                    0x7ce0, // 0x10160 jeq_s [blink]
                ],
                0x1014c
            ),
            [
                (0x1014c, 6, Flow::Call(0x1b008)),
                (0x10152, 2, Flow::Next),
                (0x10154, 2, Flow::Branch(0x1014a)),
                (0x10156, 4, Flow::Next),
                (0x1015a, 2, Flow::Next),
                (0x1015c, 4, Flow::Return),
                (0x10160, 2, Flow::Return),
            ]
        );
    }

    /// `mov_s r0, 0x00010160` reads a `limm`, which is an address;
    /// `mov_s r2, 0` is an integer.
    #[test]
    fn limm() {
        let insns = run(&[0x70cf, 0x0001, 0x0160, 0xda00], 0x1066e, false);
        assert_eq!(insns[0].1.len, 6);
        assert_eq!(
            insns[0].1.note,
            Note::Address {
                reg: 0,
                addr: 0x10160
            }
        );
        assert_eq!(insns[1].1.note, Note::Pc { reg: 2, addr: 0 });
    }

    /// `cmp r0, 240; bhi default; add_s r0, r0, 4; ldw.as r0, [pcl, r0];
    /// add_s r0, r0, pcl; j_s [r0]` at 0x19ed8.
    #[test]
    fn pcl_table() {
        let insns = run(
            &[
                0x208c, 0x8c03, // cmp r0, 240
                0x140c, 0x301f, // ld blink, [sp, 12]
                0xc1a2, // sub_s sp, sp, 8
                0x01fe, 0x000d, // bhi 0x1a0de
                0x6804, // add_s r0, r0, 4
                0x27f4, 0x7000, // ldw.as r0, [pcl, r0]
                0x70e7, // add_s r0, r0, pcl
                0x7800, // j_s [r0]
            ],
            0x19ed8,
            false,
        );
        assert_eq!(insns[0].1.note, Note::Compare { reg: 0, imm: 240 });
        assert_eq!(insns[3].1.flow, Flow::Branch(0x1a0de));
        let insns = &insns[3..];
        assert_eq!(
            insns[2].1.note,
            Note::Load {
                reg: 0,
                mem: Mem {
                    base: None,
                    index: Some(0),
                    scale: 2,
                    disp: 0x19ef0,
                },
                size: 2,
                signed: false,
            }
        );
        assert_eq!(
            insns[3].1.note,
            Note::Offset {
                reg: 0,
                src: 0,
                imm: 0x19eec
            }
        );
        assert_eq!(insns[4].1.flow, Flow::JumpRegister(0));
    }

    /// `cmp_s r2, 4; bhi; ld.as r2, [0x32cb8, r2]; j_s [r2]`.
    #[test]
    fn absolute_table() {
        let insns = run(
            &[
                0xe284, // cmp_s r2, 4
                0x0126, 0x000d, // bhi
                0x26f0, 0x7082, 0x0003, 0x2cb8, // ld.as r2, [limm, r2]
                0x7a00, // j_s [r2]
            ],
            0x16cae,
            false,
        );
        assert_eq!(insns[0].1.note, Note::Compare { reg: 2, imm: 4 });
        assert_eq!(insns[2].1.len, 8);
        assert_eq!(
            insns[2].1.note,
            Note::Load {
                reg: 2,
                mem: Mem {
                    base: None,
                    index: Some(2),
                    scale: 4,
                    disp: 0x32cb8,
                },
                size: 4,
                signed: false,
            }
        );
        assert_eq!(insns[3].1.flow, Flow::JumpRegister(2));
    }

    /// `brhs.d r1, 7, default; ld r4, [r5, -4]; add_s r1, r1, pcl; ldb_s
    /// r1, [r1, 8]; add_s r1, r1, pcl; j_s [r1]` at 0x27a80.
    #[test]
    fn byte_table() {
        let insns = run(
            &[
                0x09ab, 0x01f5, // brhs.d r1, 7
                0x15fc, 0x8004, // ld r4, [r5, -4]
                0x71e7, // add_s r1, r1, pcl
                0x8928, // ldb_s r1, [r1, 8]
                0x71e7, // add_s r1, r1, pcl
                0x7900, // j_s [r1]
            ],
            0x27a80,
            false,
        );
        assert_eq!(insns[0].1.len, 8);
        assert_eq!(insns[0].1.flow, Flow::Branch(0x27b2a));
        assert_eq!(insns[0].1.note, Note::Compare { reg: 1, imm: 6 });
        assert_eq!(insns[1].1.note, Note::None);
        assert_eq!(
            insns[2].1.note,
            Note::Load {
                reg: 1,
                mem: Mem {
                    base: None,
                    index: Some(1),
                    scale: 1,
                    disp: 0x27a90,
                },
                size: 1,
                signed: false,
            }
        );
        assert_eq!(
            insns[3].1.note,
            Note::Offset {
                reg: 1,
                src: 1,
                imm: 0x27a8c
            }
        );
        assert_eq!(insns[4].1.flow, Flow::JumpRegister(1));
    }

    /// `ld r1, [0x4411c]; j_s.d [r1]`: a jump through a slot.
    #[test]
    fn slot() {
        let insns = run(
            &[0x1600, 0x7001, 0x0004, 0x411c, 0x7920, 0xc0a4],
            0x21076,
            false,
        );
        assert_eq!(insns[1].1.flow, Flow::JumpSlot(0x4411c));
        assert_eq!(insns[1].1.len, 4);
    }

    /// ARCv2: `mov_s g, limm`, `bi [r0]`, `leave_s` that returns.
    #[test]
    fn v2() {
        let insns = run(
            &[0x40c3, 0x0001, 0x2000, 0x2024, 0x0000, 0xc4c0],
            0x1000,
            true,
        );
        assert_eq!(
            insns[0].1.note,
            Note::Address {
                reg: 0,
                addr: 0x12000
            }
        );
        assert_eq!(
            insns[1].1.flow,
            Flow::JumpTable {
                mem: Mem {
                    base: None,
                    index: Some(0),
                    scale: 1,
                    disp: 0
                },
                size: 0,
                base: 0x100a,
                shift: 2
            }
        );
        assert_eq!(insns[2].1.flow, Flow::Return);
    }

    #[test]
    fn frames() {
        // push_s blink
        assert!(starts_frame(&code(&[0xc0f1]), false));
        // mov_s r2, 0; st.a r13, [sp, -48]
        assert!(starts_frame(&code(&[0xda00, 0x1cd0, 0xb348]), false));
        assert!(!starts_frame(&code(&[0xda00, 0x7fe0]), false));
    }
}
