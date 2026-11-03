//! Xilinx MicroBlaze (32-bit, either byte order): control flow only.
//! Instructions are 32 bits. Type A takes registers `rD, rA, rB`; type B
//! takes `rD, rA` and a 16-bit immediate, which an `imm` instruction
//! before it widens to 32 bits (its high half). There are no literal
//! pools: addresses are `imm hi; addik rD, r0, lo`.
//!
//! Transfers delay only when their `D` bit says so: `brid`, `brlid` (a
//! call, linking `r15`), `brald` (through a register), the conditional
//! `beqid` and kin, and `rtsd r15, 8` (the return) run the instruction
//! after them first; `bri`, `beqi` and `brki` (a trap: `brki r14, 8` is
//! Linux's system call, which returns) do not.
//!
//! Compares write a register (`cmpu r18, rA, rB`) a conditional branch
//! tests. Without a barrel shifter GCC scales a case value by adding it to
//! itself (`addk r3, r3, r3`) before it loads the entry (`lw r3, r3, rT`
//! or `imm hi; lwi r3, r3, lo`) and jumps (`bra r3`).

use crate::isa::{Extend, Flow, Insn, Mem, Note};

/// What earlier instructions left that a later one needs.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct State {
    /// The constant in each register.
    regs: [Option<u64>; 32],
    /// The high half an `imm` gave the next instruction's immediate, and
    /// that instruction's address.
    imm: Option<(u64, u32)>,
    /// A register holding another shifted left, and by how much.
    scaled: Option<(u32, u8)>,
    /// A register holding a base plus a scaled register: the sum, base,
    /// index and shift.
    indexed: Option<(u32, u32, u32, u8)>,
    /// A register holding a scaled register plus a constant (a table's
    /// address): the sum, index, shift and constant.
    displaced: Option<(u32, u32, u8, u64)>,
    /// The last register loaded from a fixed address, and that address.
    loaded: Option<(u32, u64)>,
}

/// A register a load may read a table entry through.
#[derive(Clone, Copy)]
enum Sum {
    /// A base register plus a scaled one: the sum, base, index and shift.
    Indexed((u32, u32, u32, u8)),
    /// A scaled register plus a constant: the sum, index, shift and
    /// constant.
    Displaced((u32, u32, u8, u64)),
}

/// The link register calls set.
const LR: u32 = 15;
/// The registers a call may change: the return values (`r3`, `r4`), the
/// arguments (`r5`-`r10`), the temporaries (`r11`, `r12`), the link
/// register and the assembler's temporary (`r18`).
const VOLATILE: u32 = 0x0004_9ff8;

fn word_at(bytes: &[u8], big: bool) -> Option<u32> {
    let word: [u8; 4] = bytes.get(..4)?.try_into().ok()?;
    Some(if big {
        u32::from_be_bytes(word)
    } else {
        u32::from_le_bytes(word)
    })
}

/// `value`'s low `bits` bits, sign-extended.
fn sign(value: u32, bits: u32) -> i64 {
    let shift = 64 - bits;
    (i64::from(value) << shift) >> shift
}

/// A register's value as a signed 32-bit offset.
fn signed32(value: u64) -> i64 {
    i64::from(
        u32::try_from(value & 0xffff_ffff)
            .unwrap_or(0)
            .cast_signed(),
    )
}

pub(crate) fn decode(state: &mut State, bytes: &[u8], addr: u64, big: bool) -> Insn {
    let Some(word) = word_at(bytes, big) else {
        return Insn::new(4, Flow::Invalid);
    };
    // Only for the instruction right after it: other code may be decoded
    // in between (a callee checked for a stub).
    let high = state
        .imm
        .take()
        .filter(|&(at, _)| at == addr)
        .map(|(_, high)| high);
    let mut cx = Cx { state, addr, high };
    let Some((flow, delayed)) = cx.transfer(word) else {
        let note = cx.step(word);
        let mut insn = Insn::new(
            4,
            if note.is_some() {
                Flow::Next
            } else {
                Flow::Invalid
            },
        );
        insn.note = note.unwrap_or(Note::None);
        // OR r0, r0, r0
        insn.pad = word == 0x8000_0000;
        if note.is_none() {
            *cx.state = State::default();
        }
        return insn;
    };
    let note = if delayed {
        // A transfer with no slot after it is cut short; `imm` and
        // transfers may not sit in one.
        let slot = bytes.get(4..8).and_then(|b| word_at(b, big));
        let Some(slot) = slot.filter(|&slot| slot >> 26 != 0x2c && cx.transfer(slot).is_none())
        else {
            *cx.state = State::default();
            return Insn::new(4, Flow::Invalid);
        };
        cx.high = None;
        match cx.step(slot) {
            Some(note) => note,
            None => {
                *cx.state = State::default();
                return Insn::new(4, Flow::Invalid);
            }
        }
    } else {
        Note::None
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
        _ => *state = State::default(),
    }
    let mut insn = Insn::new(if delayed { 8 } else { 4 }, flow);
    insn.note = note;
    insn
}

struct Cx<'a> {
    state: &'a mut State,
    addr: u64,
    /// The high half an `imm` before this instruction gave.
    high: Option<u32>,
}

impl Cx<'_> {
    fn get(&self, reg: u32) -> Option<u64> {
        if reg == 0 {
            return Some(0);
        }
        self.state.regs.get(reg as usize).copied().flatten()
    }

    fn set(&mut self, reg: u32, value: Option<u64>) {
        if reg != 0
            && let Some(slot) = self.state.regs.get_mut(reg as usize)
        {
            *slot = value.map(|value| value & 0xffff_ffff);
        }
    }

    /// A type B instruction's immediate: sign-extended, or completed by the
    /// `imm` before it.
    fn immediate(&self, word: u32) -> i64 {
        match self.high {
            Some(high) => i64::from((high << 16 | (word & 0xffff)).cast_signed()),
            None => sign(word & 0xffff, 16),
        }
    }

    fn clobber(&mut self, reg: u32) -> Note {
        if reg == 0 {
            return Note::None;
        }
        self.set(reg, None);
        Note::Clobber(1 << reg)
    }

    fn constant(&mut self, reg: u32, value: u64) -> Note {
        if reg == 0 {
            return Note::None;
        }
        let value = value & 0xffff_ffff;
        self.set(reg, Some(value));
        Note::Address { reg, addr: value }
    }

    /// A value that is no pointer: an integer, or the PC.
    fn integer(&mut self, reg: u32, value: u64) -> Note {
        match self.constant(reg, value) {
            Note::Address { reg, addr } => Note::Pc { reg, addr },
            note => note,
        }
    }

    /// Where `target` in a register takes a jump or a call.
    fn through(&self, reg: u32, call: bool) -> Flow {
        match (self.get(reg).filter(|_| reg != 0), self.state.loaded) {
            (Some(target), _) if call => Flow::Call(target),
            (Some(target), _) => Flow::Jump(target),
            (None, Some((loaded, slot))) if loaded == reg && call => Flow::CallSlot(slot),
            (None, Some((loaded, slot))) if loaded == reg => Flow::JumpSlot(slot),
            _ if call => Flow::CallRegister(reg),
            _ => Flow::JumpRegister(reg),
        }
    }

    /// Where control goes after `word`, if it is a transfer, and whether a
    /// delay slot runs first.
    fn transfer(&self, word: u32) -> Option<(Flow, bool)> {
        let rd = (word >> 21) & 0x1f;
        let ra = (word >> 16) & 0x1f;
        let rb = (word >> 11) & 0x1f;
        let imm = self.immediate(word);
        let relative = |offset: i64| self.addr.wrapping_add_signed(offset) & 0xffff_ffff;
        Some(match word >> 26 {
            // BR, BRA, BRD, BRAD, BRLD, BRALD; BRK
            op @ (0x26 | 0x2e) => {
                let (delay, absolute, link) = (ra & 0x10 != 0, ra & 0x08 != 0, ra & 0x04 != 0);
                match ra & 0x1f {
                    // MBAR, and the sleep/hibernate forms of it
                    0x02 if op == 0x2e => return None,
                    // BRK, BRKI: traps that return (the system call).
                    0x0c => (Flow::Next, false),
                    0x00 | 0x08 | 0x10 | 0x18 | 0x14 | 0x1c => {
                        let call = link && rd != 0;
                        let flow = if op == 0x2e {
                            let to = if absolute {
                                imm.cast_unsigned() & 0xffff_ffff
                            } else {
                                relative(imm)
                            };
                            if call { Flow::Call(to) } else { Flow::Jump(to) }
                        } else if absolute {
                            self.through(rb, call)
                        } else {
                            match self.get(rb).filter(|_| rb != 0) {
                                Some(offset) => {
                                    let to = relative(signed32(offset));
                                    if call { Flow::Call(to) } else { Flow::Jump(to) }
                                }
                                None if call => Flow::CallIndirect,
                                None => Flow::JumpIndirect,
                            }
                        };
                        (flow, delay)
                    }
                    _ => return None,
                }
            }
            // BEQ, BNE, BLT, BLE, BGT, BGE (and their D forms)
            op @ (0x27 | 0x2f) if rd & 0xf < 6 => {
                let offset = if op == 0x2f {
                    Some(imm)
                } else {
                    self.get(rb).filter(|_| rb != 0).map(signed32)
                };
                let flow = offset.map_or(Flow::Next, |offset| Flow::Branch(relative(offset)));
                (flow, rd & 0x10 != 0)
            }
            // RTSD, RTID, RTBD, RTED
            0x2d if matches!(rd, 0x10 | 0x11 | 0x12 | 0x14) => {
                if rd != 0x10 || ra == LR {
                    (Flow::Return, true)
                } else {
                    let flow = match self.get(ra).filter(|_| ra != 0) {
                        Some(base) => Flow::Jump(base.wrapping_add_signed(imm) & 0xffff_ffff),
                        None if imm == 0 => self.through(ra, false),
                        None => Flow::JumpIndirect,
                    };
                    (flow, true)
                }
            }
            _ => return None,
        })
    }

    /// What a non-transfer `word` does to registers; `None` when it does
    /// not decode.
    #[allow(clippy::too_many_lines)]
    fn step(&mut self, word: u32) -> Option<Note> {
        let rd = (word >> 21) & 0x1f;
        let ra = (word >> 16) & 0x1f;
        let rb = (word >> 11) & 0x1f;
        let func = word & 0x7ff;
        let imm = self.immediate(word);
        let uimm = imm.cast_unsigned() & 0xffff_ffff;
        let scaled = self.state.scaled.take();
        let indexed = self.state.indexed.take();
        let displaced = self.state.displaced.take();
        let loaded = self.state.loaded.take();
        let note = match word >> 26 {
            // ADD, ADDK
            0x00 | 0x04 if func == 0 => self.add(rd, ra, rb, scaled),
            // RSUB, RSUBK: rB - rA.
            0x01 | 0x05 if func == 0 => {
                self.set(rd, None);
                if rd == 0 {
                    Note::None
                } else {
                    Note::Sub {
                        reg: rd,
                        base: rb,
                        index: ra,
                    }
                }
            }
            // CMP, CMPU: rD's sign is whether rB < rA.
            0x05 if func == 1 => self.clobber(rd),
            0x05 if func == 3 => {
                let note = self.compare(ra, rb);
                self.set(rd, None);
                note
            }
            // ADDC, RSUBC, ADDKC, RSUBKC
            0x02 | 0x03 | 0x06 | 0x07 if func == 0 => self.clobber(rd),
            // ADDI, ADDIK
            0x08 | 0x0c => self.add_imm(rd, ra, imm, scaled),
            // RSUBI, ADDIC, RSUBIC, RSUBIK, ADDIKC, RSUBIKC
            0x09 | 0x0d => match self.get(ra) {
                Some(value) => self.integer(rd, uimm.wrapping_sub(value)),
                None => self.clobber(rd),
            },
            0x0a | 0x0b | 0x0e | 0x0f => self.clobber(rd),
            // MUL, barrel shifts, IDIV, FPU; MULI, barrel shifts by an
            // immediate.
            0x10 | 0x11 | 0x12 | 0x16 | 0x18 | 0x19 => self.clobber(rd),
            // GET, PUT and kin (stream links)
            0x13 | 0x1b => self.clobber(rd),
            // OR (with r0: a copy), AND, XOR, ANDN, and the pattern compares.
            0x20 if func == 0 && (ra == 0 || rb == 0) => self.copy(rd, ra | rb),
            0x20..=0x23 => self.clobber(rd),
            // SRA, SRC, SRL, SEXT8, SEXT16, CLZ, cache operations, SWAPB...
            0x24 => self.clobber(rd),
            // MFS rD, rPC
            0x25 if (word >> 14) & 3 == 2 && word & 0x3fff == 0 && ra == 0 => {
                self.integer(rd, self.addr)
            }
            // MTS, MFS, MSRCLR, MSRSET
            0x25 => self.clobber(rd),
            // ORI, ANDI, XORI, ANDNI
            0x28 => match self.get(ra) {
                // An immediate alone is an address only when `imm` widened
                // it.
                Some(value) if ra == 0 && self.high.is_none() => self.integer(rd, value | uimm),
                Some(value) => self.constant(rd, value | uimm),
                None => self.clobber(rd),
            },
            0x29..=0x2b => self.clobber(rd),
            // MBAR (a transfer's opcode, no transfer)
            0x2e if ra == 0x02 => Note::None,
            // IMM
            0x2c => {
                self.state.imm = Some((self.addr.wrapping_add(4) & 0xffff_ffff, word & 0xffff));
                // Nothing this prefixes has run yet.
                self.state.scaled = scaled;
                self.state.indexed = indexed;
                self.state.displaced = displaced;
                self.state.loaded = loaded;
                return Some(Note::None);
            }
            // LBU, LHU, LW (rA + rB)
            op @ 0x30..=0x32 => {
                let size = match op {
                    0x30 => 1,
                    0x31 => 2,
                    _ => 4,
                };
                self.load_indexed(rd, ra, rb, size, scaled)
            }
            // LBUI, LHUI, LWI
            op @ 0x38..=0x3a => {
                let size = match op {
                    0x38 => 1,
                    0x39 => 2,
                    _ => 4,
                };
                self.load(
                    rd,
                    ra,
                    imm,
                    size,
                    scaled,
                    indexed.map(Sum::Indexed).or(displaced.map(Sum::Displaced)),
                )
            }
            // SB, SH, SW; SBI, SHI, SWI
            0x34..=0x36 | 0x3c..=0x3e => Note::None,
            _ => return None,
        };
        // What this instruction did not overwrite lasts.
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
        if self.state.displaced.is_none()
            && let Some((sum, index, ..)) = displaced
            && written & (1 << sum | 1 << index) == 0
        {
            self.state.displaced = displaced;
        }
        if self.state.loaded.is_none()
            && let Some((reg, _)) = loaded
            && written >> reg & 1 == 0
        {
            self.state.loaded = loaded;
        }
        Some(note)
    }

    fn copy(&mut self, rd: u32, src: u32) -> Note {
        if rd == 0 {
            return Note::None;
        }
        if src == 0 {
            return self.integer(rd, 0);
        }
        let value = self.get(src);
        self.set(rd, value);
        Note::Copy { reg: rd, src }
    }

    fn add_imm(&mut self, rd: u32, ra: u32, imm: i64, scaled: Option<(u32, u8)>) -> Note {
        if rd == 0 {
            return Note::None;
        }
        if imm == 0 {
            return self.copy(rd, ra);
        }
        // A table's address: the scaled index stays the note's, so one
        // that overwrites it says nothing.
        if let Some((reg, shift)) = scaled
            && reg == ra
        {
            self.set(rd, None);
            self.state.displaced = Some((rd, ra, shift, imm.cast_unsigned() & 0xffff_ffff));
            return if rd == ra {
                Note::None
            } else {
                Note::Clobber(1 << rd)
            };
        }
        match self.get(ra) {
            // An immediate alone is an address only when `imm` widened it.
            Some(base) if ra == 0 && self.high.is_none() => {
                self.integer(rd, base.wrapping_add_signed(imm))
            }
            Some(base) => self.constant(rd, base.wrapping_add_signed(imm)),
            None => {
                self.set(rd, None);
                Note::Offset {
                    reg: rd,
                    src: ra,
                    imm: imm.cast_unsigned() & 0xffff_ffff,
                }
            }
        }
    }

    fn add(&mut self, rd: u32, ra: u32, rb: u32, scaled: Option<(u32, u8)>) -> Note {
        if rd == 0 {
            return Note::None;
        }
        if ra == 0 || rb == 0 {
            return self.copy(rd, ra | rb);
        }
        // A register added to itself: doubled.
        if ra == rb && ra != 0 && self.get(ra).is_none() {
            let shift = match scaled {
                Some((reg, shift)) if reg == ra => shift + 1,
                _ => 1,
            };
            self.set(rd, None);
            if shift <= 3 {
                self.state.scaled = Some((rd, shift));
            }
            return if rd == ra {
                Note::None
            } else {
                Note::Copy { reg: rd, src: ra }
            };
        }
        if let Some((reg, shift)) = scaled
            && (reg == ra || reg == rb)
        {
            let base = if reg == ra { rb } else { ra };
            self.set(rd, None);
            self.state.indexed = Some((rd, base, reg, shift));
            return Note::None;
        }
        if let Some((a, b)) = self.get(ra).zip(self.get(rb)) {
            return self.constant(rd, a.wrapping_add(b));
        }
        self.set(rd, None);
        Note::Add {
            reg: rd,
            base: ra,
            index: rb,
            shift: 0,
            extend: Extend::None,
        }
    }

    /// `lw rD, rA, rB`: a table entry when one register is scaled.
    fn load_indexed(
        &mut self,
        rd: u32,
        ra: u32,
        rb: u32,
        size: u8,
        scaled: Option<(u32, u8)>,
    ) -> Note {
        if rd == 0 {
            return Note::None;
        }
        self.set(rd, None);
        if size == 4
            && let Some((reg, shift)) = scaled
            && (reg == ra || reg == rb)
        {
            let base = if reg == ra { rb } else { ra };
            return Note::Load {
                reg: rd,
                mem: Mem {
                    base: Some(base).filter(|&b| b != 0),
                    index: Some(reg),
                    scale: 1 << shift,
                    disp: 0,
                },
                size,
                signed: false,
            };
        }
        if size == 4
            && let Some(slot) = self
                .get(ra)
                .zip(self.get(rb))
                .map(|(a, b)| a.wrapping_add(b))
        {
            let slot = slot & 0xffff_ffff;
            self.state.loaded = Some((rd, slot));
            return Note::Fetch {
                reg: rd,
                mem: Mem {
                    base: None,
                    index: None,
                    scale: 1,
                    disp: slot,
                },
                size,
                signed: false,
            };
        }
        Note::Clobber(1 << rd)
    }

    fn load(
        &mut self,
        rd: u32,
        ra: u32,
        imm: i64,
        size: u8,
        scaled: Option<(u32, u8)>,
        sum: Option<Sum>,
    ) -> Note {
        if rd == 0 {
            return Note::None;
        }
        let base_value = self.get(ra);
        self.set(rd, None);
        if let Some(Sum::Displaced((sum, index, shift, disp))) = sum
            && sum == ra
        {
            return Note::Load {
                reg: rd,
                mem: Mem {
                    base: None,
                    index: Some(index),
                    scale: 1 << shift,
                    disp: disp.wrapping_add_signed(imm) & 0xffff_ffff,
                },
                size,
                signed: false,
            };
        }
        if let Some(Sum::Indexed((sum, base, index, shift))) = sum
            && sum == ra
        {
            return Note::Load {
                reg: rd,
                mem: Mem {
                    base: Some(base),
                    index: Some(index),
                    scale: 1 << shift,
                    disp: imm.cast_unsigned() & 0xffff_ffff,
                },
                size,
                signed: false,
            };
        }
        if size == 4
            && let Some((reg, shift)) = scaled
            && reg == ra
        {
            return Note::Load {
                reg: rd,
                mem: Mem {
                    base: None,
                    index: Some(reg),
                    scale: 1 << shift,
                    disp: imm.cast_unsigned() & 0xffff_ffff,
                },
                size,
                signed: false,
            };
        }
        if size != 4 {
            return Note::Clobber(1 << rd);
        }
        let slot = base_value.map(|base| base.wrapping_add_signed(imm) & 0xffff_ffff);
        self.state.loaded = slot.map(|slot| (rd, slot));
        let (base, disp) = slot.map_or((Some(ra), imm.cast_unsigned()), |slot| (None, slot));
        Note::Fetch {
            reg: rd,
            mem: Mem {
                base,
                index: None,
                scale: 1,
                disp,
            },
            size,
            signed: false,
        }
    }

    /// `cmpu rD, rA, rB`, whose sign says `rB < rA`: with the bound in rB
    /// the case value in rA is in range up to it; with the bound in rA, the
    /// case value in rB is in range below it.
    fn compare(&self, ra: u32, rb: u32) -> Note {
        let constant = |reg: u32| self.get(reg).filter(|_| reg != 0);
        match (constant(ra), constant(rb)) {
            (None, Some(n)) => Note::Compare { reg: ra, imm: n },
            (Some(0), None) => Note::None,
            (Some(n), None) => Note::Compare {
                reg: rb,
                imm: n - 1,
            },
            _ => Note::None,
        }
    }
}

/// Whether `bytes` begin a frame: the stack pointer lowered (`addik r1,
/// r1, -n`) or the link register saved (`swi r15, r1, 0`) among the first
/// three instructions.
pub(crate) fn starts_frame(bytes: &[u8], big: bool) -> bool {
    (0..3).any(|i| {
        bytes
            .get(i * 4..)
            .and_then(|b| word_at(b, big))
            .is_some_and(|word| {
                (matches!(word >> 16, 0x3021 | 0x2021) && word & 0x8000 != 0) || word == 0xf9e1_0000
            })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(words: &[u32], addr: u64) -> Vec<Insn> {
        let code: Vec<u8> = words.iter().flat_map(|w| w.to_be_bytes()).collect();
        let mut state = State::default();
        let mut at = 0;
        let mut insns = Vec::new();
        while at < code.len() {
            let insn = decode(&mut state, &code[at..], addr + at as u64, true);
            at += insn.len as usize;
            insns.push(insn);
        }
        insns
    }

    #[test]
    fn transfers() {
        let flows: Vec<(u32, Flow)> = run(
            &[
                0xb9f4_0040, // brlid r15, +0x40
                0x8000_0000, // nop
                0xb810_0010, // brid +0x10
                0x8000_0000,
                0xb800_0008, // bri +8
                0xbc03_0010, // beqi r3, +0x10
                0xbe23_0010, // bneid r3, +0x10
                0x8000_0000,
                0xb60f_0008, // rtsd r15, 8
                0x8000_0000,
                0x99fc_1800, // brald r15, r3
                0x8000_0000,
                0x9818_1800, // brad r3
                0x8000_0000,
                0xb9cc_0008, // brki r14, 8
                0xb000_1000, // imm 0x1000
                0xb9f4_1854, // brlid r15, ...
                0x8000_0000,
                0xfc00_0000, // invalid
            ],
            0x1000,
        )
        .iter()
        .map(|insn| (insn.len, insn.flow))
        .collect();
        assert_eq!(
            flows,
            [
                (8, Flow::Call(0x1040)),
                (8, Flow::Jump(0x1018)),
                (4, Flow::Jump(0x1018)),
                (4, Flow::Branch(0x1024)),
                (8, Flow::Branch(0x1028)),
                (8, Flow::Return),
                (8, Flow::CallRegister(3)),
                (8, Flow::JumpRegister(3)),
                (4, Flow::Next),
                (4, Flow::Next),
                (8, Flow::Call(0x1000_2894)),
                (4, Flow::Invalid),
            ]
        );
    }

    /// `imm 0x1000; addik r5, r0, 0x31d8; brlid r15, f`: `main`'s address
    /// for `__uClibc_main`, and `imm 0x1002; lwi r3, r0, 0x2288; brald
    /// r15, r3`: a call through a slot.
    #[test]
    fn addresses() {
        let insns = run(
            &[
                0xb000_1000,
                0x30a0_31d8,
                0x3060_0005, // addik r3, r0, 5: an integer
                0xb000_1002,
                0xe860_2288,
                0x99fc_1800,
                0x8000_0000,
            ],
            0x1000_1000,
        );
        assert_eq!(
            insns[1].note,
            Note::Address {
                reg: 5,
                addr: 0x1000_31d8
            }
        );
        assert_eq!(insns[2].note, Note::Pc { reg: 3, addr: 5 });
        assert_eq!(insns[5].flow, Flow::CallSlot(0x1002_2288));
    }

    /// `addik r18, r0, 19; cmpu r18, r3, r18; blti r18, default; addk r3,
    /// r3, r3; addk r3, r3, r3; imm 0x1002; lwi r3, r3, 0x2000; bra r3`.
    #[test]
    fn switch_notes() {
        let insns = run(
            &[
                0x3240_0013,
                0x1643_9003,
                0xbc52_0040,
                0x1063_1800,
                0x1063_1800,
                0xb000_1002,
                0xe863_2000,
                0x9808_1800,
            ],
            0x1000,
        );
        assert_eq!(insns[1].note, Note::Compare { reg: 3, imm: 19 });
        assert_eq!(
            insns[6].note,
            Note::Load {
                reg: 3,
                mem: Mem {
                    base: None,
                    index: Some(3),
                    scale: 4,
                    disp: 0x1002_2000,
                },
                size: 4,
                signed: false,
            }
        );
        assert_eq!(insns[7].flow, Flow::JumpRegister(3));
    }

    /// `addik r22, r0, 6; cmpu r18, r4, r22; bltid r18, default; xori r3,
    /// r4, 4; addk r3, r0, r4; addk r3, r4, r4; addk r3, r3, r3; imm
    /// 0x1002; addik r3, r3, 0xf768; lwi r3, r3, 0; bra r3`.
    #[test]
    fn displaced_table() {
        let insns = run(
            &[
                0x32c0_0006,
                0x1644_b003,
                0xbe52_02c0,
                0xa864_0004,
                0x1060_2000,
                0x1064_2000,
                0x1063_1800,
                0xb000_1002,
                0x3063_f768,
                0xe863_0000,
                0x9808_1800,
            ],
            0x1000_0288,
        );
        assert_eq!(insns[1].note, Note::Compare { reg: 4, imm: 6 });
        assert_eq!(insns[3].note, Note::Copy { reg: 3, src: 4 });
        assert_eq!(
            insns[8].note,
            Note::Load {
                reg: 3,
                mem: Mem {
                    base: None,
                    index: Some(3),
                    scale: 4,
                    disp: 0x1002_f768,
                },
                size: 4,
                signed: false,
            }
        );
        assert_eq!(insns[9].flow, Flow::JumpRegister(3));
    }

    #[test]
    fn little_endian() {
        let code = 0xb9f4_0040_u32
            .to_le_bytes()
            .into_iter()
            .chain(0x8000_0000_u32.to_le_bytes())
            .collect::<Vec<_>>();
        let insn = decode(&mut State::default(), &code, 0x1000, false);
        assert_eq!((insn.len, insn.flow), (8, Flow::Call(0x1040)));
    }

    #[test]
    fn frames() {
        assert!(starts_frame(&0x3021_ffe0_u32.to_be_bytes(), true));
        assert!(starts_frame(&0xf9e1_0000_u32.to_le_bytes(), false));
        assert!(!starts_frame(&0x3021_0020_u32.to_be_bytes(), true));
    }
}
