//! Motorola 68000 family (68000-68060, 32-bit, big-endian): control flow
//! only. An instruction is an operation word and up to ten extension words;
//! its length follows from the operation and its effective addresses.
//!
//! Transfers are `bsr`/`jsr` (calls), `bra`/`jmp`, `Bcc`, `DBcc`, and
//! `rts`/`rtd`/`rtr`/`rte`. `jsr`/`jmp` take an effective address: an
//! absolute or PC-relative one is a direct transfer, `(An)` goes through a
//! register (whose constant `lea`, `movea` or `move.l #` leaves), and the
//! 68020's memory-indirect `([d,pc])` through a slot: a PLT stub.
//!
//! GCC's jump tables are halfword offsets from the table, which follows the
//! jump: `cmpi.l #n, d0; bhi default; move.w (2,pc,d0.l*2), d0; jmp
//! (2,pc,d0.w)` (on the 68000, `add.l d0, d0` scales). The case value is
//! often bounded in memory and reloaded (`moveq #n, d1; cmp.l 12(a3), d1;
//! bcs default; move.l 12(a3), d0`): the decoder remembers the operand
//! compared, so the reload carries the bound.

use crate::isa::{Flow, Insn, Mem, Note};

/// What earlier instructions left that a later one needs.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct State {
    /// The constant in each register: `d0`-`d7` are 0-7, `a0`-`a7` 8-15.
    regs: [Option<u64>; 16],
    /// A data register holding another shifted left, and by how much.
    scaled: Option<(u32, u8)>,
    /// The last register loaded from a fixed address, and that address.
    loaded: Option<(u32, u64)>,
    /// The memory operand (`d16(An)`) a compare bounded.
    compared: Option<(u32, i64)>,
}

/// `a7`, the stack pointer.
const SP: u32 = 15;
/// The registers a call may change: `d0`, `d1`, `a0`, `a1`.
const VOLATILE: u64 = 0x0303;
/// A jump table's address, as the `jmp` that indexes it computes it.
const TABLE: u32 = 33;
/// The memory operand a compare bounded.
const SLOT: u32 = 34;
/// Where an address `pea` or `move.l #` stores goes: a pointer the program
/// keeps (`main`, which start-up code pushes; a callback it registers).
const STORED: u32 = 35;
const NOP: u16 = 0x4e71;

/// An effective address, decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ea {
    Data(u32),
    Addr(u32),
    /// `(An)`, `(An)+`, `-(An)`.
    Ind(u32),
    /// `d16(An)`
    Disp(u32, i64),
    /// `(d8, base, Xn.size*scale)`, the base `None` for the PC (whose
    /// value is then folded into `disp`): register, long, scale.
    Index {
        base: Option<u32>,
        index: u32,
        long: bool,
        scale: u8,
        disp: u64,
    },
    /// `([bd, pc])`: through the slot at a fixed address.
    Slot(u64),
    /// An absolute or PC-relative address.
    Abs(u64),
    Imm(u64),
    /// Any other mode.
    Other,
}

/// The instruction's words, and where the next extension word is.
struct Words<'a> {
    bytes: &'a [u8],
    at: usize,
    addr: u64,
}

impl Words<'_> {
    fn next(&mut self) -> Option<u16> {
        let word = u16::from_be_bytes(self.bytes.get(self.at..self.at + 2)?.try_into().ok()?);
        self.at += 2;
        Some(word)
    }

    fn long(&mut self) -> Option<u32> {
        Some(u32::from(self.next()?) << 16 | u32::from(self.next()?))
    }

    /// The address of the next extension word: what the PC reads as in a
    /// PC-relative mode.
    fn pc(&self) -> u64 {
        self.addr.wrapping_add(self.at as u64) & 0xffff_ffff
    }

    /// A `size`-byte operand (an immediate's; 1 takes a whole word, 12 is
    /// the FPU's extended and packed formats).
    fn skip(&mut self, size: u8) -> Option<u64> {
        match size {
            1 => Some(u64::from(self.next()? & 0xff)),
            2 => Some(u64::from(self.next()?)),
            4 => Some(u64::from(self.long()?)),
            _ => {
                for _ in 0..size / 2 {
                    self.next()?;
                }
                Some(0)
            }
        }
    }

    /// The effective address `mode`/`reg` names, with an immediate of
    /// `size` bytes.
    fn ea(&mut self, mode: u16, reg: u16, size: u8) -> Option<Ea> {
        let r = u32::from(reg);
        Some(match mode {
            0 => Ea::Data(r),
            1 => Ea::Addr(r + 8),
            2..=4 => Ea::Ind(r + 8),
            5 => Ea::Disp(r + 8, i64::from(self.next()?.cast_signed())),
            6 => self.indexed(Some(r + 8))?,
            7 => match reg {
                0 => Ea::Abs(i64::from(self.next()?.cast_signed()).cast_unsigned() & 0xffff_ffff),
                1 => Ea::Abs(u64::from(self.long()?)),
                2 => {
                    let pc = self.pc();
                    let disp = i64::from(self.next()?.cast_signed());
                    Ea::Abs(pc.wrapping_add_signed(disp) & 0xffff_ffff)
                }
                3 => self.indexed(None)?,
                4 => Ea::Imm(self.skip(size)?),
                _ => return None,
            },
            _ => return None,
        })
    }

    /// The indexed modes: the brief extension word, or the 68020's full
    /// one (base and outer displacements, memory indirection).
    fn indexed(&mut self, base: Option<u32>) -> Option<Ea> {
        let pc = self.pc();
        let ext = self.next()?;
        let index = u32::from(ext >> 12 & 0xf);
        let long = ext & 0x800 != 0;
        let scale = 1_u8 << (ext >> 9 & 3);
        let origin = |disp: i64| match base {
            Some(_) => disp.cast_unsigned(),
            None => pc.wrapping_add_signed(disp) & 0xffff_ffff,
        };
        if ext & 0x100 == 0 {
            let disp = sign8(ext);
            return Some(Ea::Index {
                base,
                index,
                long,
                scale,
                disp: origin(disp),
            });
        }
        let bd = match ext >> 4 & 3 {
            1 => 0,
            2 => i64::from(self.next()?.cast_signed()),
            3 => i64::from(self.long()?.cast_signed()),
            _ => return None,
        };
        let iis = ext & 7;
        match iis & 3 {
            0 | 1 => {}
            2 => {
                self.next()?;
            }
            _ => {
                self.long()?;
            }
        }
        if iis == 4 || (ext & 0x40 != 0 && iis > 3) {
            return None;
        }
        let suppressed = ext & 0x40 != 0;
        let base_suppressed = ext & 0x80 != 0;
        Some(match (iis, suppressed, base, base_suppressed) {
            // `([bd, pc])`, `([bd])`: a slot.
            (1, true, None, false) => Ea::Slot(origin(bd)),
            (1, true, _, true) => Ea::Slot(bd.cast_unsigned() & 0xffff_ffff),
            (0, false, _, false) => Ea::Index {
                base,
                index,
                long,
                scale,
                disp: origin(bd),
            },
            (0, true, None, false) => Ea::Abs(origin(bd)),
            _ => Ea::Other,
        })
    }
}

/// The low 16 bits of `value`, sign-extended.
fn signed16(value: u64) -> u64 {
    i64::from(u16::try_from(value & 0xffff).unwrap_or(0).cast_signed()).cast_unsigned()
}

/// The low 8 bits of `value`, sign-extended.
fn sign8(value: u16) -> i64 {
    i64::from(u8::try_from(value & 0xff).unwrap_or(0).cast_signed())
}

fn half(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
}

/// The instruction's operand size from a two-bit field: 0 byte, 1 word, 2
/// long.
fn size2(bits: u16) -> Option<u8> {
    match bits {
        0 => Some(1),
        1 => Some(2),
        2 => Some(4),
        _ => None,
    }
}

pub(crate) fn decode(state: &mut State, bytes: &[u8], addr: u64) -> Insn {
    let mut words = Words { bytes, at: 0, addr };
    let mut cx = Cx {
        state,
        addr,
        scaled: None,
    };
    let decoded = words
        .next()
        .and_then(|op| cx.decode(op, &mut words).map(|d| (op, d)));
    let Some((op, (flow, note))) = decoded else {
        *cx.state = State::default();
        return Insn::new(2, Flow::Invalid);
    };
    let len = u32::try_from(words.at).unwrap_or(2);
    let state = cx.state;
    match flow {
        Flow::Next | Flow::Branch(_) => {}
        Flow::Call(_) | Flow::CallIndirect | Flow::CallRegister(_) | Flow::CallSlot(_) => {
            state.loaded = None;
            state.scaled = None;
            state.compared = None;
            for (reg, value) in state.regs.iter_mut().enumerate() {
                if VOLATILE >> reg & 1 != 0 {
                    *value = None;
                }
            }
        }
        _ => *state = State::default(),
    }
    let mut insn = Insn::new(len, flow);
    insn.note = note;
    insn.pad = op == NOP;
    insn
}

struct Cx<'a> {
    state: &'a mut State,
    #[allow(dead_code)]
    addr: u64,
    /// The scaled register earlier instructions left.
    scaled: Option<(u32, u8)>,
}

impl Cx<'_> {
    fn get(&self, reg: u32) -> Option<u64> {
        self.state.regs.get(reg as usize).copied().flatten()
    }

    fn set(&mut self, reg: u32, value: Option<u64>) {
        if let Some(slot) = self.state.regs.get_mut(reg as usize) {
            *slot = value.map(|value| value & 0xffff_ffff);
        }
        if self.state.compared.is_some_and(|(base, _)| base == reg) {
            self.state.compared = None;
        }
    }

    fn clobber(&mut self, reg: u32) -> Note {
        self.set(reg, None);
        Note::Clobber(1 << reg)
    }

    /// Whatever `ea` writes, when it is a register.
    fn write(&mut self, ea: Ea) -> Note {
        match ea {
            Ea::Data(reg) | Ea::Addr(reg) => self.clobber(reg),
            // Post-increment and pre-decrement change the address register.
            Ea::Ind(reg) => {
                self.set(reg, None);
                Note::None
            }
            _ => Note::None,
        }
    }

    fn constant(&mut self, reg: u32, value: u64) -> Note {
        let value = value & 0xffff_ffff;
        self.set(reg, Some(value));
        Note::Address { reg, addr: value }
    }

    /// The address `ea` computes, as `lea` and `jsr` read it.
    fn address(&self, ea: Ea) -> Option<u64> {
        match ea {
            Ea::Abs(addr) => Some(addr),
            Ea::Ind(reg) => self.get(reg),
            Ea::Disp(reg, disp) => Some(self.get(reg)?.wrapping_add_signed(disp) & 0xffff_ffff),
            _ => None,
        }
    }

    /// `move src, dst` of `size` bytes (and `movea`).
    fn moved(&mut self, src: Ea, dst: Ea, size: u8) -> Note {
        let reg = match dst {
            Ea::Data(reg) | Ea::Addr(reg) => reg,
            _ => {
                if let Ea::Ind(reg) = dst {
                    self.set(reg, None);
                }
                if let Ea::Ind(reg) = src {
                    self.set(reg, None);
                }
                return match src {
                    Ea::Imm(addr) if size == 4 => Note::Address { reg: STORED, addr },
                    _ => Note::None,
                };
            }
        };
        let whole = size == 4 || reg >= 8;
        match src {
            Ea::Imm(value) if whole => {
                let value = if size == 2 { signed16(value) } else { value };
                self.constant(reg, value)
            }
            Ea::Data(src) | Ea::Addr(src) if size == 4 => {
                let value = self.get(src);
                self.set(reg, value);
                Note::Copy { reg, src }
            }
            Ea::Abs(slot) if size == 4 => {
                self.set(reg, None);
                self.state.loaded = Some((reg, slot));
                Note::Fetch {
                    reg,
                    mem: Mem {
                        base: None,
                        index: None,
                        scale: 1,
                        disp: slot,
                    },
                    size: 4,
                    signed: false,
                }
            }
            Ea::Disp(base, disp) if size == 4 && self.state.compared == Some((base, disp)) => {
                self.set(reg, None);
                Note::Copy { reg, src: SLOT }
            }
            Ea::Index {
                base,
                index,
                scale,
                disp,
                ..
            } => {
                self.set(reg, None);
                let scale = match self.scaled {
                    Some((held, shift)) if held == index && scale == 1 => 1 << shift,
                    _ => scale,
                };
                Note::Load {
                    reg,
                    mem: Mem {
                        base,
                        index: Some(index),
                        scale,
                        disp,
                    },
                    size,
                    signed: true,
                }
            }
            _ => {
                if let Ea::Ind(src) = src {
                    self.set(src, None);
                }
                self.clobber(reg)
            }
        }
    }

    /// `cmp src, Dn` (and `cmpi #n, dst`): an unsigned bound on whichever
    /// operand is not a constant.
    fn compare(&mut self, src: Ea, dst: Ea) -> Note {
        let constant = |cx: &Self, ea: Ea| match ea {
            Ea::Imm(value) => Some(value),
            Ea::Data(reg) => cx.get(reg),
            _ => None,
        };
        let bounded = |cx: &mut Self, ea: Ea, imm: u64| match ea {
            Ea::Data(reg) => Note::Compare { reg, imm },
            Ea::Disp(base, disp) => {
                cx.state.compared = Some((base, disp));
                Note::Compare { reg: SLOT, imm }
            }
            _ => Note::None,
        };
        match (constant(self, src), constant(self, dst)) {
            (Some(imm), None) => bounded(self, dst, imm),
            (None, Some(imm)) => bounded(self, src, imm),
            _ => Note::None,
        }
    }

    /// `jsr`, `jmp`.
    fn transfer(&self, ea: Ea, call: bool, loaded: Option<(u32, u64)>) -> Flow {
        if let Some(target) = self.address(ea) {
            return if call {
                Flow::Call(target)
            } else {
                Flow::Jump(target)
            };
        }
        match ea {
            Ea::Slot(slot) if call => Flow::CallSlot(slot),
            Ea::Slot(slot) => Flow::JumpSlot(slot),
            Ea::Ind(reg) => match loaded.filter(|&(held, _)| held == reg) {
                Some((_, slot)) if call => Flow::CallSlot(slot),
                Some((_, slot)) => Flow::JumpSlot(slot),
                None if call => Flow::CallRegister(reg),
                None => Flow::JumpRegister(reg),
            },
            _ if call => Flow::CallIndirect,
            // `jmp (2, pc, d0.w)`, `jmp (a0, d0.w)`: a table's address plus
            // its entry.
            Ea::Index {
                base: None,
                index,
                scale: 1,
                ..
            } => Flow::JumpAdd { base: TABLE, index },
            Ea::Index {
                base: Some(base),
                index,
                scale: 1,
                disp: 0,
                ..
            } => Flow::JumpAdd { base, index },
            _ => Flow::JumpIndirect,
        }
    }

    #[allow(clippy::too_many_lines)]
    fn decode(&mut self, op: u16, words: &mut Words<'_>) -> Option<(Flow, Note)> {
        let mode = op >> 3 & 7;
        let reg = op & 7;
        let dreg = u32::from(op >> 9 & 7);
        let scaled = self.state.scaled.take();
        let loaded = self.state.loaded.take();
        self.scaled = scaled;
        let result = match op >> 12 {
            0 => self.group0(op, words)?,
            // MOVE.B, MOVE.L, MOVE.W
            1..=3 => {
                let size = match op >> 12 {
                    1 => 1,
                    3 => 2,
                    _ => 4,
                };
                let (dst_mode, dst_reg) = (op >> 6 & 7, op >> 9 & 7);
                if (dst_mode == 7 && dst_reg >= 2) || (dst_mode == 1 && size == 1) {
                    return None;
                }
                let src = words.ea(mode, reg, size)?;
                let dst = words.ea(dst_mode, dst_reg, size)?;
                (Flow::Next, self.moved(src, dst, size))
            }
            4 => return self.group4(op, words, loaded),
            5 => {
                let size = op >> 6 & 3;
                if size != 3 {
                    // ADDQ, SUBQ
                    let data = match op >> 9 & 7 {
                        0 => 8,
                        n => i64::from(n),
                    };
                    let data = if op & 0x100 != 0 { -data } else { data };
                    let ea = words.ea(mode, reg, 1)?;
                    let note = match ea {
                        Ea::Data(r) | Ea::Addr(r) => match self.get(r) {
                            Some(value) if size == 2 || r >= 8 => {
                                self.constant(r, value.wrapping_add_signed(data))
                            }
                            None if r >= 8 && r != SP => {
                                self.set(r, None);
                                Note::Offset {
                                    reg: r,
                                    src: r,
                                    imm: data.cast_unsigned() & 0xffff_ffff,
                                }
                            }
                            _ => self.clobber(r),
                        },
                        ea => self.write(ea),
                    };
                    (Flow::Next, note)
                } else if mode == 1 {
                    // DBcc
                    let pc = words.pc();
                    let disp = i64::from(words.next()?.cast_signed());
                    let note = self.clobber(u32::from(reg));
                    (
                        Flow::Branch(pc.wrapping_add_signed(disp) & 0xffff_ffff),
                        note,
                    )
                } else if mode == 7 && (2..=4).contains(&reg) {
                    // TRAPcc
                    words.skip(match reg {
                        2 => 2,
                        3 => 4,
                        _ => 0,
                    })?;
                    (Flow::Next, Note::None)
                } else {
                    // Scc
                    let ea = words.ea(mode, reg, 1)?;
                    (Flow::Next, self.write(ea))
                }
            }
            // BRA, BSR, Bcc
            6 => {
                let pc = words.pc();
                let disp = match op & 0xff {
                    0 => i64::from(words.next()?.cast_signed()),
                    0xff => i64::from(words.long()?.cast_signed()),
                    d => sign8(d),
                };
                let target = pc.wrapping_add_signed(disp) & 0xffff_ffff;
                let flow = match op >> 8 & 0xf {
                    0 => Flow::Jump(target),
                    1 => Flow::Call(target),
                    _ => Flow::Branch(target),
                };
                (flow, Note::None)
            }
            // MOVEQ
            7 if op & 0x100 == 0 => {
                let value = sign8(op).cast_unsigned();
                (Flow::Next, self.constant(dreg, value))
            }
            7 => return None,
            // OR, DIV, SBCD, PACK, UNPK; SUB, SUBX, SUBA; AND, MUL, ABCD,
            // EXG; ADD, ADDX, ADDA.
            8 | 9 | 0xc | 0xd => {
                let opmode = op >> 6 & 7;
                let group = op >> 12;
                match (opmode, mode) {
                    // DIVU.W, DIVS.W, MULU.W, MULS.W
                    (3 | 7, _) if matches!(group, 8 | 0xc) => {
                        words.ea(mode, reg, 2)?;
                        (Flow::Next, self.clobber(dreg))
                    }
                    // SUBA, ADDA
                    (3 | 7, _) => {
                        let src = words.ea(mode, reg, if opmode == 3 { 2 } else { 4 })?;
                        let an = dreg + 8;
                        let note = match (src, self.get(an)) {
                            (Ea::Imm(imm), Some(value)) if group == 0xd => {
                                let imm = if opmode == 3 { signed16(imm) } else { imm };
                                self.constant(an, value.wrapping_add(imm))
                            }
                            _ if an == SP => {
                                self.set(an, None);
                                Note::None
                            }
                            _ => self.clobber(an),
                        };
                        (Flow::Next, note)
                    }
                    // SBCD, ABCD; SUBX, ADDX; EXG
                    (4, 0 | 1) => (Flow::Next, self.clobber(dreg)),
                    (5 | 6, 0 | 1) if group == 0xc => {
                        let note = Note::Clobber(1 << dreg | 1 << (dreg + 8) | 0x101 << reg);
                        self.set(dreg, None);
                        self.set(dreg + 8, None);
                        self.set(u32::from(reg), None);
                        self.set(u32::from(reg) + 8, None);
                        (Flow::Next, note)
                    }
                    // PACK, UNPK
                    (5 | 6, 0 | 1) if group == 8 => {
                        words.next()?;
                        (Flow::Next, self.clobber(dreg))
                    }
                    // SUBX, ADDX
                    (5 | 6, 0 | 1) => (Flow::Next, self.clobber(dreg)),
                    _ => {
                        let size = size2(opmode & 3)?;
                        let ea = words.ea(mode, reg, size)?;
                        let note = if opmode & 4 != 0 {
                            self.write(ea)
                        } else if group == 0xd && size == 4 && ea == Ea::Data(dreg) {
                            // `add.l d0, d0`: twice the case value.
                            self.set(dreg, None);
                            self.state.scaled = Some((dreg, 1));
                            Note::Copy {
                                reg: dreg,
                                src: dreg,
                            }
                        } else {
                            if let Ea::Ind(r) = ea {
                                self.set(r, None);
                            }
                            self.clobber(dreg)
                        };
                        (Flow::Next, note)
                    }
                }
            }
            // Line A: unimplemented.
            0xa => return None,
            // CMP, CMPA, CMPM, EOR
            0xb => {
                let opmode = op >> 6 & 7;
                match opmode {
                    3 | 7 => {
                        words.ea(mode, reg, if opmode == 3 { 2 } else { 4 })?;
                        (Flow::Next, Note::None)
                    }
                    0..=2 => {
                        let src = words.ea(mode, reg, size2(opmode)?)?;
                        (Flow::Next, self.compare(src, Ea::Data(dreg)))
                    }
                    _ if mode == 1 => {
                        self.set(u32::from(reg) + 8, None);
                        self.set(dreg + 8, None);
                        (Flow::Next, Note::None)
                    }
                    _ => {
                        let ea = words.ea(mode, reg, size2(opmode & 3)?)?;
                        (Flow::Next, self.write(ea))
                    }
                }
            }
            // Shifts and rotates; the 68020's bit fields.
            0xe => {
                let size = op >> 6 & 3;
                if size != 3 {
                    let count = op >> 9 & 7;
                    let note = if op & 0x20 == 0
                        && op & 0x100 != 0
                        && size == 2
                        && op >> 3 & 3 <= 1
                        && (1..=3).contains(&count)
                    {
                        // `lsl.l #n, d0`, `asl.l #n, d0`
                        let r = u32::from(reg);
                        self.set(r, None);
                        self.state.scaled = Some((r, u8::try_from(count).unwrap_or(0)));
                        Note::Copy { reg: r, src: r }
                    } else {
                        self.clobber(u32::from(reg))
                    };
                    (Flow::Next, note)
                } else if op & 0x800 == 0 {
                    let ea = words.ea(mode, reg, 2)?;
                    (Flow::Next, self.write(ea))
                } else {
                    // BFTST, BFEXTU, ... : an extension word, then the field.
                    let ext = words.next()?;
                    words.ea(mode, reg, 1)?;
                    let note = if matches!(op >> 8 & 7, 1 | 3 | 5) {
                        self.clobber(u32::from(ext >> 12 & 7))
                    } else {
                        Note::None
                    };
                    (Flow::Next, note)
                }
            }
            // Coprocessors: the FPU; `move16` and the cache operations.
            _ => return self.line_f(op, words),
        };
        // What this instruction did not overwrite lasts.
        if self.state.scaled.is_none()
            && let Some((reg, _)) = scaled
            && result.1.writes() >> reg & 1 == 0
        {
            self.state.scaled = scaled;
        }
        if let Some((reg, _)) = loaded
            && result.1.writes() >> reg & 1 == 0
            && self.state.loaded.is_none()
        {
            self.state.loaded = loaded;
        }
        Some(result)
    }

    /// Bit operations, immediate arithmetic, `movep`, `cas`, `cmp2`/`chk2`,
    /// `moves`.
    fn group0(&mut self, op: u16, words: &mut Words<'_>) -> Option<(Flow, Note)> {
        let mode = op >> 3 & 7;
        let reg = op & 7;
        let size = op >> 6 & 3;
        if op & 0x100 != 0 {
            if mode == 1 {
                // MOVEP
                words.next()?;
                let note = if op & 0x80 == 0 {
                    self.clobber(u32::from(op >> 9 & 7))
                } else {
                    Note::None
                };
                return Some((Flow::Next, note));
            }
            // BTST, BCHG, BCLR, BSET with the bit number in a register.
            let ea = words.ea(mode, reg, 1)?;
            let note = if size == 0 {
                Note::None
            } else {
                self.write(ea)
            };
            return Some((Flow::Next, note));
        }
        match op >> 9 & 7 {
            // To CCR and SR: a word of immediate.
            0 | 1 | 5 if op & 0xff == 0x3c || op & 0xff == 0x7c => {
                words.next()?;
                Some((Flow::Next, Note::None))
            }
            // BTST, BCHG, BCLR, BSET with the bit number in a word.
            4 => {
                words.next()?;
                let ea = words.ea(mode, reg, 1)?;
                let note = if size == 0 {
                    Note::None
                } else {
                    self.write(ea)
                };
                Some((Flow::Next, note))
            }
            // CMP2, CHK2; CAS; CAS2; CALLM, RTM; MOVES.
            n if size == 3 => {
                if n == 3 && mode <= 1 {
                    // RTM
                    return Some((Flow::Return, Note::None));
                }
                if matches!(n, 6 | 7) && op & 0x3f == 0x3c {
                    words.next()?;
                    words.next()?;
                    return Some((Flow::Next, Note::Clobber(0xffff)));
                }
                let ext = words.next()?;
                words.ea(mode, reg, 1)?;
                if n == 3 {
                    return Some((Flow::Next, Note::None));
                }
                let note = if n >= 5 {
                    self.clobber(u32::from(ext & 7))
                } else {
                    Note::None
                };
                Some((Flow::Next, note))
            }
            7 => {
                // MOVES
                let ext = words.next()?;
                words.ea(mode, reg, 1)?;
                let note = if ext & 0x800 == 0 {
                    self.clobber(u32::from(ext >> 12 & 0xf))
                } else {
                    Note::None
                };
                Some((Flow::Next, note))
            }
            // ORI, ANDI, SUBI, ADDI, EORI, CMPI
            n => {
                let size = size2(size)?;
                let imm = words.skip(size)?;
                let ea = words.ea(mode, reg, size)?;
                let note = if n == 6 {
                    self.compare(Ea::Imm(imm), ea)
                } else {
                    self.write(ea)
                };
                Some((Flow::Next, note))
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn group4(
        &mut self,
        op: u16,
        words: &mut Words<'_>,
        loaded: Option<(u32, u64)>,
    ) -> Option<(Flow, Note)> {
        let mode = op >> 3 & 7;
        let reg = op & 7;
        let r = u32::from(reg);
        let next = |note| Some((Flow::Next, note));
        match op {
            0x4afc => return Some((Flow::Stop, Note::None)),
            0x4e70 | 0x4e71 | 0x4e76 => return next(Note::None),
            0x4e72 => {
                words.next()?;
                return Some((Flow::Stop, Note::None));
            }
            0x4e73 | 0x4e75 | 0x4e77 => return Some((Flow::Return, Note::None)),
            0x4e74 => {
                words.next()?;
                return Some((Flow::Return, Note::None));
            }
            0x4e40..=0x4e4f => return next(Note::None),
            // LINK.W, UNLK
            0x4e50..=0x4e57 => {
                words.next()?;
                self.set(SP, None);
                return next(self.clobber(r + 8));
            }
            0x4e58..=0x4e5f => {
                self.set(SP, None);
                return next(self.clobber(r + 8));
            }
            // MOVE USP
            0x4e60..=0x4e67 => return next(Note::None),
            0x4e68..=0x4e6f => return next(self.clobber(r + 8)),
            // MOVEC
            0x4e7a | 0x4e7b => {
                let ext = words.next()?;
                let note = if op == 0x4e7a {
                    self.clobber(u32::from(ext >> 12))
                } else {
                    Note::None
                };
                return next(note);
            }
            // LINK.L
            0x4808..=0x480f => {
                words.long()?;
                self.set(SP, None);
                return next(self.clobber(r + 8));
            }
            // BKPT
            0x4848..=0x484f => return Some((Flow::Stop, Note::None)),
            _ => {}
        }
        let dreg = u32::from(op >> 9 & 7);
        // EXTB.L
        if op & 0xfff8 == 0x49c0 {
            return next(self.clobber(r));
        }
        if op & 0x100 != 0 {
            return match op >> 6 & 7 {
                // LEA
                7 => {
                    let ea = words.ea(mode, reg, 4)?;
                    let an = dreg + 8;
                    let note = match (self.address(ea), ea) {
                        (Some(addr), _) => self.constant(an, addr),
                        (None, Ea::Disp(base, disp)) if base != SP && an != SP => {
                            self.set(an, None);
                            Note::Offset {
                                reg: an,
                                src: base,
                                imm: disp.cast_unsigned() & 0xffff_ffff,
                            }
                        }
                        _ => self.clobber(an),
                    };
                    next(note)
                }
                // CHK.L, CHK.W
                4 => {
                    words.ea(mode, reg, 4)?;
                    next(Note::None)
                }
                6 => {
                    words.ea(mode, reg, 2)?;
                    next(Note::None)
                }
                _ => None,
            };
        }
        match op >> 6 {
            // NEGX, CLR, NEG, NOT
            0x100..=0x102 | 0x108..=0x10a | 0x110..=0x112 | 0x118..=0x11a => {
                let ea = words.ea(mode, reg, 1)?;
                next(self.write(ea))
            }
            // MOVE from SR, from CCR
            0x103 | 0x10b => {
                let ea = words.ea(mode, reg, 2)?;
                next(self.write(ea))
            }
            // MOVE to CCR, to SR
            0x113 | 0x11b => {
                words.ea(mode, reg, 2)?;
                next(Note::None)
            }
            // NBCD; LINK.L is above.
            0x120 => {
                let ea = words.ea(mode, reg, 1)?;
                next(self.write(ea))
            }
            // SWAP; BKPT is above; PEA.
            0x121 if mode == 0 => next(self.clobber(r)),
            0x121 => {
                let ea = words.ea(mode, reg, 4)?;
                self.set(SP, None);
                next(match ea {
                    Ea::Abs(addr) => Note::Address { reg: STORED, addr },
                    _ => Note::None,
                })
            }
            // EXT.W, EXT.L, EXTB.L; MOVEM to memory.
            0x122 | 0x123 | 0x127 if mode == 0 => next(self.clobber(r)),
            0x122 | 0x123 => {
                words.next()?;
                let ea = words.ea(mode, reg, 2)?;
                next(self.write(ea))
            }
            // TST
            0x128..=0x12a => {
                let size = size2(op >> 6 & 3)?;
                words.ea(mode, reg, size)?;
                next(Note::None)
            }
            // TAS
            0x12b => {
                let ea = words.ea(mode, reg, 1)?;
                next(self.write(ea))
            }
            // MULU.L, MULS.L, DIVU.L, DIVS.L
            0x130 | 0x131 => {
                let ext = words.next()?;
                words.ea(mode, reg, 4)?;
                let (dl, dh) = (u32::from(ext >> 12 & 7), u32::from(ext & 7));
                self.set(dl, None);
                self.set(dh, None);
                next(Note::Clobber(1 << dl | 1 << dh))
            }
            // MOVEM to registers.
            0x132 | 0x133 => {
                let mask = words.next()?;
                words.ea(mode, reg, 2)?;
                for i in 0..16 {
                    if mask >> i & 1 != 0 {
                        self.set(i, None);
                    }
                }
                if mode == 3 {
                    self.set(r + 8, None);
                }
                next(Note::Clobber(u32::from(mask)))
            }
            // JSR, JMP
            0x13a | 0x13b => {
                let ea = words.ea(mode, reg, 4)?;
                if matches!(ea, Ea::Data(_) | Ea::Addr(_) | Ea::Imm(_)) || mode == 3 || mode == 4 {
                    return None;
                }
                let flow = self.transfer(ea, op >> 6 == 0x13a, loaded);
                let note = match ea {
                    Ea::Index {
                        base: None, disp, ..
                    } if op >> 6 == 0x13b => Note::Pc {
                        reg: TABLE,
                        addr: disp,
                    },
                    _ => Note::None,
                };
                Some((flow, note))
            }
            _ => None,
        }
    }

    /// Line F: the FPU (coprocessor 1), `move16`, cache operations.
    fn line_f(&mut self, op: u16, words: &mut Words<'_>) -> Option<(Flow, Note)> {
        let mode = op >> 3 & 7;
        let reg = op & 7;
        let next = |note| Some((Flow::Next, note));
        match op >> 9 & 7 {
            1 => {}
            // CINV, CPUSH
            2 if op & 0xff00 == 0xf400 => return next(Note::None),
            // MOVE16
            3 if op & 0xfff8 == 0xf620 => {
                words.next()?;
                return next(Note::None);
            }
            3 if op & 0xffe0 == 0xf600 => {
                words.long()?;
                return next(Note::None);
            }
            _ => return None,
        }
        match op >> 6 & 7 {
            // The general operations.
            0 => {
                let ext = words.next()?;
                let note = match ext >> 13 {
                    // Register to register.
                    0 => Note::None,
                    // From memory or an integer register; to it.
                    2 | 3 => {
                        let size = match ext >> 10 & 7 {
                            0 | 1 => 4,
                            2 | 3 | 7 => 12,
                            4 => 2,
                            5 => 8,
                            _ => 1,
                        };
                        let ea = words.ea(mode, reg, size)?;
                        if ext >> 13 == 3 {
                            self.write(ea)
                        } else {
                            Note::None
                        }
                    }
                    // FMOVE, FMOVEM of control registers; FMOVEM.
                    4 | 5 => {
                        let count = (ext >> 10 & 7).count_ones();
                        let ea = words.ea(mode, reg, u8::try_from(4 * count).unwrap_or(4))?;
                        if ext >> 13 == 5 {
                            self.write(ea)
                        } else {
                            Note::None
                        }
                    }
                    6 | 7 => {
                        let ea = words.ea(mode, reg, 12)?;
                        self.write(ea)
                    }
                    _ => return None,
                };
                next(note)
            }
            // FScc, FDBcc, FTRAPcc
            1 => {
                words.next()?;
                if mode == 1 {
                    let pc = words.pc();
                    let disp = i64::from(words.next()?.cast_signed());
                    let note = self.clobber(u32::from(reg));
                    return Some((
                        Flow::Branch(pc.wrapping_add_signed(disp) & 0xffff_ffff),
                        note,
                    ));
                }
                if mode == 7 && (2..=4).contains(&reg) {
                    words.skip(match reg {
                        2 => 2,
                        3 => 4,
                        _ => 0,
                    })?;
                    return next(Note::None);
                }
                let ea = words.ea(mode, reg, 1)?;
                next(self.write(ea))
            }
            // FBcc.W, FBcc.L (FNOP is FBF.W with no offset)
            2 | 3 => {
                let pc = words.pc();
                let disp = if op >> 6 & 1 == 0 {
                    i64::from(words.next()?.cast_signed())
                } else {
                    i64::from(words.long()?.cast_signed())
                };
                if op & 0x3f == 0 && disp == 0 {
                    return next(Note::None);
                }
                let target = pc.wrapping_add_signed(disp) & 0xffff_ffff;
                let flow = if op & 0x3f == 0xf {
                    Flow::Jump(target)
                } else {
                    Flow::Branch(target)
                };
                Some((flow, Note::None))
            }
            // FSAVE, FRESTORE
            4 | 5 => {
                words.ea(mode, reg, 4)?;
                next(Note::None)
            }
            _ => None,
        }
    }
}

/// Whether `bytes` begin a frame: `link a6, #-n`, registers saved
/// (`movem.l ..., -(sp)`), or the stack pointer lowered (`lea -n(sp), sp`,
/// `subq.l #n, sp`, `suba.l #n, sp`), among the first three instructions.
pub(crate) fn starts_frame(bytes: &[u8]) -> bool {
    let mut state = State::default();
    let mut at = 0_usize;
    for _ in 0..3 {
        let Some(rest) = bytes.get(at..) else {
            return false;
        };
        let Some(op) = half(rest, 0) else {
            return false;
        };
        let second = half(rest, 2);
        match op {
            0x4e50..=0x4e57 if second.is_some_and(|d| d.cast_signed() <= 0) => return true,
            0x4808..=0x480f | 0x48e7 => return true,
            0x4fef if second.is_some_and(|d| d.cast_signed() < 0) => return true,
            _ if op & 0xf1ff == 0x518f || op == 0x9ffc => return true,
            _ => {}
        }
        let insn = decode(&mut state, rest, 0);
        if insn.flow != Flow::Next {
            return false;
        }
        at += insn.len as usize;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(words: &[u16], addr: u64) -> Vec<Insn> {
        let code: Vec<u8> = words.iter().flat_map(|w| w.to_be_bytes()).collect();
        let mut state = State::default();
        let mut at = 0;
        let mut insns = Vec::new();
        while at < code.len() {
            let insn = decode(&mut state, &code[at..], addr + at as u64);
            at += insn.len as usize;
            insns.push(insn);
        }
        insns
    }

    fn shape(words: &[u16], addr: u64) -> Vec<(u32, Flow)> {
        run(words, addr).iter().map(|i| (i.len, i.flow)).collect()
    }

    #[test]
    fn transfers() {
        assert_eq!(
            shape(
                &[
                    0x4eb9, 0x8000, 0x940a, // jsr 0x8000940a.l
                    0x61ff, 0x0000, 0x76cc, // bsr.l +0x76cc
                    0x6100, 0x0010, // bsr.w +0x10
                    0x6720, // beq.b +0x20
                    0x6000, 0xff28, // bra.w -0xd8
                    0x4e92, // jsr (a2)
                    0x4ed1, // jmp (a1)
                    0x51c8, 0xfffc, // dbra d0, -4
                    0x4e75, // rts
                    0x4afc, // illegal
                    0x4e71, // nop
                ],
                0x1000,
            ),
            [
                (6, Flow::Call(0x8000_940a)),
                (6, Flow::Call(0x1008 + 0x76cc)),
                (4, Flow::Call(0x100e + 0x10)),
                (2, Flow::Branch(0x1012 + 0x20)),
                (4, Flow::Jump(0x1014 - 0xd8)),
                (2, Flow::CallRegister(10)),
                (2, Flow::JumpRegister(9)),
                (4, Flow::Branch(0x101c - 4)),
                (2, Flow::Return),
                (2, Flow::Stop),
                (2, Flow::Next),
            ]
        );
    }

    /// `lea 0x80006b28.l, a2; jsr (a2)`: a call through a register that
    /// holds a constant.
    #[test]
    fn register_calls() {
        let insns = run(&[0x45f9, 0x8000, 0x6b28, 0x4e92], 0x1000);
        assert_eq!(insns[1].flow, Flow::Call(0x8000_6b28));
    }

    /// Lengths of the forms with extension words and immediates.
    #[test]
    fn lengths() {
        let lens = |words: &[u16]| -> Vec<u32> { run(words, 0).iter().map(|i| i.len).collect() };
        assert_eq!(
            lens(&[
                0x0c6f, 0xffff, 0x003c, // cmpi.w #-1, 0x3c(a7)
                0x2779, 0x8003, 0xcae2, 0x0008, // move.l 0x8003cae2.l, 8(a3)
                0x48e7, 0x3820, // movem.l d2-d4/a2, -(a7)
                0x0680, 0x0000, 0x0001, // addi.l #1, d0
                0x4c00, 0x0800, // mulu.l d0, d0
                0x4e56, 0xfff0, // link.w a6, #-16
                0x0801, 0x0003, // btst #3, d1
                0x303b, 0x0a06, // move.w (6, pc, d0.l*2), d0
                0x4efb, 0x0171, 0x0000, 0x2000, // jmp ([0x2000, pc])
                0xf23c, 0x5400, 0x4000, 0, 0, 0,      // fmove.d #2.0, fp0
                0x7001, // moveq #1, d0
            ]),
            [6, 8, 4, 6, 4, 4, 4, 4, 8, 12, 2]
        );
    }

    /// GCC's table, bounded in memory: `moveq #10, d1; cmp.l 12(a3), d1;
    /// bcs default; move.l 12(a3), d0; move.w (6, pc, d0.l*2), d0; jmp (2,
    /// pc, d0.w)`.
    #[test]
    fn switch_notes() {
        let insns = run(
            &[
                0x720a, 0xb2ab, 0x000c, 0x658e, 0x202b, 0x000c, 0x303b, 0x0a06, 0x4efb, 0x0002,
            ],
            0x8001_2f56,
        );
        assert_eq!(insns[1].note, Note::Compare { reg: SLOT, imm: 10 });
        assert_eq!(insns[3].note, Note::Copy { reg: 0, src: SLOT });
        assert_eq!(
            insns[4].note,
            Note::Load {
                reg: 0,
                mem: Mem {
                    base: None,
                    index: Some(0),
                    scale: 2,
                    disp: 0x8001_2f6a,
                },
                size: 2,
                signed: true,
            }
        );
        assert_eq!(
            insns[5].note,
            Note::Pc {
                reg: TABLE,
                addr: 0x8001_2f6a
            }
        );
        assert_eq!(
            insns[5].flow,
            Flow::JumpAdd {
                base: TABLE,
                index: 0
            }
        );
    }

    /// A PLT stub: `jmp ([0x2000, pc])`.
    #[test]
    fn plt_stub() {
        let insns = run(&[0x4efb, 0x0171, 0x0000, 0x2000], 0x1000);
        assert_eq!(insns[0].flow, Flow::JumpSlot(0x1002 + 0x2000));
    }

    #[test]
    fn frames() {
        let code =
            |words: &[u16]| -> Vec<u8> { words.iter().flat_map(|w| w.to_be_bytes()).collect() };
        assert!(starts_frame(&code(&[0x4e56, 0x0000])));
        assert!(starts_frame(&code(&[0x2f02, 0x48e7, 0x3820])));
        assert!(!starts_frame(&code(&[0x4e75])));
    }
}
