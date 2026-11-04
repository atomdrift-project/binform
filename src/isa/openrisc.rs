//! OpenRISC 1000 (or1k, 32-bit, big-endian): control flow only.
//! Instructions are 32 bits; every transfer has a delay slot, which runs
//! before the target.
//!
//! Transfers are `l.j`, `l.jal` (which links `r9`), `l.bf`/`l.bnf` (on the
//! flag an `l.sf*` compare sets), `l.jr` (`l.jr r9` returns) and `l.jalr`.
//! Addresses are built `l.movhi rD, hi; l.ori rD, rD, lo` (or `l.addi`).
//! Start-up code calls over a data word and reads it through the link
//! register (`l.jal 1f; l.nop; .word x; 1: l.lwz r4, 0(r9)`), which reads
//! as a jump, as PowerPC's `bl` over data does.
//!
//! GCC's jump tables bound the case value with an unsigned compare
//! (`l.sfgtui r3, 19; l.bf default`), scale it (`l.slli r3, r3, 2`), add
//! the table's address and load the absolute entry (`l.lwz r3, 0(r3);
//! l.jr r3`).

use crate::isa::{Decode, Extend, Flow, Insn, Mem, Note, Regs, relative, sext, u32_at};

/// The OpenRISC decoder, and what earlier instructions left that a later
/// one needs.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Decoder {
    /// The constant in each register.
    regs: Regs<u64, 32>,
    /// A register holding another shifted left, and by how much.
    scaled: Option<(u32, u8)>,
    /// A register holding a base plus a scaled register.
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

/// The link register.
const LR: u32 = 9;
/// The registers a call may change: the link register, the arguments
/// (`r3`-`r8`), the return values (`r11`, `r12`) and the odd temporaries.
const VOLATILE: u32 = 0xaaaa_bbf8;

fn word_at(bytes: &[u8], at: usize) -> Option<u32> {
    u32_at(bytes, at, true)
}

impl Decode for Decoder {
    fn decode(&mut self, bytes: &[u8], addr: u64) -> Insn {
        let Some(word) = word_at(bytes, 0) else {
            return Insn::new(4, Flow::Invalid);
        };
        let mut cx = Cx { state: self, addr };
        let insn = cx.single(word);
        // Only transfers have a delay slot, and L.TRAP and L.RFE none.
        if matches!(insn.flow, Flow::Next | Flow::Invalid | Flow::Stop)
            || (insn.flow == Flow::Return && word >> 26 == 0x09)
        {
            return insn;
        }
        let slot = word_at(bytes, 4);
        // A call to just past its slot, which only reads the PC, or over
        // one word of data, whose address the code reads from the link
        // register: a jump, leaving that address in the link register.
        if let Flow::Call(to) = insn.flow
            && word >> 26 == 0x01
            && matches!(to.wrapping_sub(addr) & 0xffff_ffff, 8 | 12)
        {
            let Some(slot) = slot else {
                return Insn::new(4, Flow::Invalid);
            };
            cx.step(slot);
            let link = addr.wrapping_add(8) & 0xffff_ffff;
            return Insn {
                note: Note::Value {
                    reg: LR,
                    value: link,
                },
                ..Insn::new(8, Flow::Jump(to))
            };
        }
        insn.with_slot(slot.map(|slot| cx.single(slot)))
    }

    fn reset(&mut self) {
        *self = Self::default();
    }

    fn call(&mut self) {
        self.loaded = None;
        self.scaled = None;
        self.indexed = None;
        self.regs.forget(u64::from(VOLATILE));
    }

    /// The stack pointer lowered (`l.addi r1, r1, -n`) or a register saved
    /// below it (`l.sw -n(r1), rX`) among the first three instructions.
    fn starts_frame(&self, bytes: &[u8]) -> bool {
        (0..12).step_by(4).any(|at| {
            word_at(bytes, at).is_some_and(|word| {
                // L.SW's immediate is split, its sign in bit 25.
                (word >> 16 == 0x9c21 && word & 0x8000 != 0)
                    || (word >> 26 == 0x35 && (word >> 16) & 0x1f == 1 && (word >> 25) & 1 == 1)
            })
        })
    }
}

struct Cx<'a> {
    state: &'a mut Decoder,
    addr: u64,
}

impl Cx<'_> {
    fn get(&self, reg: u32) -> Option<u64> {
        if reg == 0 {
            return Some(0);
        }
        self.state.regs.get(reg)
    }

    fn set(&mut self, reg: u32, value: Option<u64>) {
        if reg != 0 {
            self.state
                .regs
                .set(reg, value.map(|value| value & 0xffff_ffff));
        }
    }

    /// `word` alone: a transfer without its slot, or what any other
    /// instruction does to registers.
    fn single(&mut self, word: u32) -> Insn {
        if let Some(flow) = self.transfer(word) {
            return Insn::new(4, flow);
        }
        match self.step(word) {
            Some(note) => Insn {
                pad: word >> 24 == 0x15,
                ..Insn::note(4, note)
            },
            None => Insn::new(4, Flow::Invalid),
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

    /// `rd = value`, an integer that is no pointer by itself: an
    /// immediate, the high part of an address a later instruction
    /// completes, or the PC.
    fn value(&mut self, rd: u32, value: u64) -> Note {
        match self.constant(rd, value) {
            Note::Address { reg, addr } => Note::Value { reg, value: addr },
            note => note,
        }
    }

    /// Where control goes after `word`, if it is a transfer.
    fn transfer(&self, word: u32) -> Option<Flow> {
        let rb = (word >> 11) & 0x1f;
        let disp = || relative(self.addr, word & 0x03ff_ffff, 26, 4) & 0xffff_ffff;
        Some(match word >> 26 {
            0x00 => Flow::Jump(disp()),
            0x01 => Flow::Call(disp()),
            0x03 | 0x04 => Flow::Branch(disp()),
            // L.TRAP
            0x08 if word >> 16 == 0x2100 => Flow::Stop,
            // L.RFE
            0x09 => Flow::Return,
            0x11 if rb == LR => Flow::Return,
            0x11 => match (self.get(rb).filter(|_| rb != 0), self.state.loaded) {
                (Some(target), _) => Flow::Jump(target),
                (None, Some((reg, slot))) if reg == rb => Flow::JumpSlot(slot),
                _ => Flow::JumpRegister(rb),
            },
            0x12 => match (self.get(rb).filter(|_| rb != 0), self.state.loaded) {
                (Some(target), _) => Flow::Call(target),
                (None, Some((reg, slot))) if reg == rb => Flow::CallSlot(slot),
                _ => Flow::CallRegister(rb),
            },
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
        let simm = sext(word & 0xffff, 16);
        let uimm = u64::from(word & 0xffff);
        let scaled = self.state.scaled.take();
        let indexed = self.state.indexed.take();
        let loaded = self.state.loaded.take();
        let note = match word >> 26 {
            // L.ADRP: a page, PC-relative.
            0x02 => {
                let page = relative(self.addr & !0x1fff, word & 0x1f_ffff, 21, 0x2000);
                self.value(rd, page)
            }
            // L.NOP
            0x05 => Note::None,
            // L.MOVHI, L.MACRC
            0x06 if word & 0x1_0000 == 0 => self.value(rd, uimm << 16),
            0x06 => self.clobber(rd),
            // L.SYS, L.MSYNC, L.PSYNC, L.CSYNC
            0x08 if word >> 16 == 0x2000
                || matches!(word, 0x2200_0000 | 0x2280_0000 | 0x2300_0000) =>
            {
                Note::None
            }
            // Vector (ORVDX64), L.MACI, MAC, L.MTSPR, stores.
            0x0a | 0x13 | 0x30 | 0x31 | 0x33..=0x37 => Note::None,
            // L.LWA, L.ADDIC, L.MULI, L.MFSPR, floating point (in the
            // integer registers).
            0x1b | 0x28 | 0x2c | 0x2d | 0x32 => self.clobber(rd),
            // L.LD, L.LWZ, L.LWS, L.LBZ, L.LBS, L.LHZ, L.LHS
            op @ 0x20..=0x26 => {
                let shape = match op {
                    0x20 => (8, false),
                    0x21 => (4, false),
                    0x22 => (4, true),
                    0x23 => (1, false),
                    0x24 => (1, true),
                    0x25 => (2, false),
                    _ => (2, true),
                };
                self.load(rd, ra, simm, shape, indexed)
            }
            // L.ADDI
            0x27 => self.add_imm(rd, ra, simm),
            // L.ANDI, L.ORI, L.XORI
            0x29 => self.derive(rd, ra, |v| v & uimm),
            0x2a if uimm == 0 => self.copy(rd, ra),
            0x2a => self.derive(rd, ra, |v| v | uimm),
            0x2b => self.derive(rd, ra, |v| v ^ simm.cast_unsigned()),
            // L.SLLI, L.SRLI, L.SRAI, L.RORI
            0x2e => {
                let shift = word & 0x3f;
                if (word >> 6) & 3 == 0 && (1..=3).contains(&shift) && rd != 0 {
                    self.set(rd, None);
                    self.state.scaled = Some((rd, u8::try_from(shift).unwrap_or(0)));
                    Note::Copy { reg: rd, src: ra }
                } else {
                    self.clobber(rd)
                }
            }
            // L.SFxxI: an unsigned compare with a constant bounds a case.
            0x2f => self.compare(rd, ra, Some(simm.cast_unsigned() & 0xffff_ffff), None),
            // The register ALU operations.
            0x38 => {
                let op = word & 0xf;
                let high = (word >> 8) & 3;
                match (op, high) {
                    // L.ADD
                    (0, 0) => self.add(rd, ra, rb, scaled),
                    // L.SUB
                    (2, 0) => {
                        self.set(rd, None);
                        if rd == 0 {
                            Note::None
                        } else {
                            Note::Sub {
                                reg: rd,
                                base: ra,
                                index: rb,
                            }
                        }
                    }
                    // L.OR with r0: a copy.
                    (4, 0) if ra == 0 || rb == 0 => self.copy(rd, ra | rb),
                    _ => self.clobber(rd),
                }
            }
            // L.SFxx
            0x39 => self.compare(rd, ra, None, Some(rb)),
            _ => return None,
        };
        // What this instruction did not overwrite lasts.
        let written = if matches!(note, Note::Compare { .. }) {
            0
        } else {
            note.writes()
        } | self.state.indexed.map_or(0, |indexed| 1 << indexed.sum);
        if self.state.scaled.is_none()
            && let Some((reg, _)) = scaled
            && written >> reg & 1 == 0
        {
            self.state.scaled = scaled;
        }
        if self.state.indexed.is_none()
            && let Some(Indexed {
                sum, base, index, ..
            }) = indexed
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
        Some(note)
    }

    fn copy(&mut self, rd: u32, src: u32) -> Note {
        if rd == 0 {
            return Note::None;
        }
        if src == 0 {
            return self.value(rd, 0);
        }
        let value = self.get(src);
        self.set(rd, value);
        Note::Copy { reg: rd, src }
    }

    /// An immediate from `r0` is an integer: addresses are `l.movhi`'s.
    fn derive(&mut self, rd: u32, ra: u32, f: impl Fn(u64) -> u64) -> Note {
        match self.get(ra) {
            Some(value) if ra == 0 => self.value(rd, f(value)),
            Some(value) => self.constant(rd, f(value)),
            None => self.clobber(rd),
        }
    }

    fn add_imm(&mut self, rd: u32, ra: u32, imm: i64) -> Note {
        if rd == 0 {
            return Note::None;
        }
        if imm == 0 {
            return self.copy(rd, ra);
        }
        match self.get(ra) {
            Some(base) if ra == 0 => self.value(rd, base.wrapping_add_signed(imm)),
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
        if let Some((reg, shift)) = scaled
            && (reg == ra || reg == rb)
        {
            let base = if reg == ra { rb } else { ra };
            self.set(rd, None);
            self.state.indexed = Some(Indexed {
                sum: rd,
                base,
                index: reg,
                shift,
            });
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

    fn load(
        &mut self,
        rd: u32,
        ra: u32,
        imm: i64,
        (size, signed): (u8, bool),
        indexed: Option<Indexed>,
    ) -> Note {
        if rd == 0 {
            return Note::None;
        }
        let base_value = self.get(ra);
        self.set(rd, None);
        if let Some(Indexed {
            sum,
            base,
            index,
            shift,
        }) = indexed
            && sum == ra
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
            signed,
        }
    }

    /// `l.sf<cond> rA, rB` or `l.sf<cond>i rA, imm`: the unsigned
    /// conditions bound whichever operand is not a constant.
    fn compare(&self, cond: u32, ra: u32, imm: Option<u64>, rb: Option<u32>) -> Note {
        let constant = |reg: u32| self.get(reg).filter(|_| reg != 0);
        let (reg, n, reversed) = match (constant(ra), imm.or_else(|| rb.and_then(constant))) {
            (None, Some(n)) => (ra, n, false),
            (Some(n), None) => match rb {
                Some(rb) => (rb, n, true),
                None => return Note::None,
            },
            _ => return Note::None,
        };
        // gtu, geu, ltu, leu, with the constant on the right: in range up
        // to n (gtu, leu) or n - 1 (geu, ltu); on the left, the reverse.
        let inclusive = match cond {
            0x2 | 0x5 => !reversed,
            0x3 | 0x4 => reversed,
            _ => return Note::None,
        };
        match (inclusive, n) {
            (true, n) => Note::Compare { reg, imm: n },
            (false, 0) => Note::None,
            (false, n) => Note::Compare {
                reg,
                imm: n.wrapping_sub(1),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(words: &[u32], addr: u64) -> Vec<Insn> {
        let code: Vec<u8> = words.iter().flat_map(|w| w.to_be_bytes()).collect();
        let mut decoder = Decoder::default();
        let mut at = 0;
        let mut insns = Vec::new();
        while at < code.len() {
            let insn = decoder.decode(&code[at..], addr + at as u64);
            at += insn.len as usize;
            insns.push(insn);
        }
        insns
    }

    #[test]
    fn transfers() {
        let flows: Vec<(u32, Flow)> = run(
            &[
                0x0400_0010,
                0x1500_0000, // l.jal +0x40; l.nop
                0x0000_0004,
                0x1500_0000, // l.j +0x10
                0x1000_0009,
                0x1500_0000, // l.bf +0x24
                0x4400_4800,
                0x1500_0000, // l.jr r9
                0x4400_8800,
                0x1500_0000, // l.jr r17
                0x4800_1800,
                0x1500_0000, // l.jalr r3
                0x2100_0000, // l.trap 0
                0x1500_0000, // l.nop
                0xffff_da68, // data
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
                (8, Flow::Branch(0x1034)),
                (8, Flow::Return),
                (8, Flow::JumpRegister(17)),
                (8, Flow::CallRegister(3)),
                (4, Flow::Stop),
                (4, Flow::Next),
                (4, Flow::Invalid),
            ]
        );
    }

    /// A transfer in a delay slot, or a slot that does not decode, makes
    /// the pair no instruction.
    #[test]
    fn slots_hold_no_transfer() {
        assert_eq!(run(&[0x0000_0004, 0x0000_0004], 0)[0].flow, Flow::Invalid);
        assert_eq!(run(&[0x0000_0004, 0xffff_da68], 0)[0].flow, Flow::Invalid);
        assert_eq!(run(&[0x0000_0004], 0)[0].flow, Flow::Invalid);
    }

    /// uClibc's `_start`: `l.jal 1f; l.ori r3, r1, 0; .word x; 1: l.lwz
    /// r4, 0(r9)`.
    #[test]
    fn call_over_data() {
        let insns = run(&[0x0400_0003, 0xa861_0000], 0x2590);
        assert_eq!(insns[0].flow, Flow::Jump(0x259c));
        assert_eq!(
            insns[0].note,
            Note::Value {
                reg: 9,
                value: 0x2598
            }
        );
        // `l.jal 1f; l.movhi r2, 0; 1:`, for the PC alone.
        let insns = run(&[0x0400_0002, 0x1840_0000], 0x25b0);
        assert_eq!(insns[0].flow, Flow::Jump(0x25b8));
    }

    /// `l.movhi r17, 0x3; l.ori r17, r17, 0xc0bc; l.jalr r17`.
    #[test]
    fn register_calls() {
        let insns = run(
            &[0x1a20_0003, 0xaa31_c0bc, 0x4800_8800, 0x1500_0000],
            0x1000,
        );
        assert_eq!(
            insns[1].note,
            Note::Address {
                reg: 17,
                addr: 0x3_c0bc
            }
        );
        assert_eq!(insns[2].flow, Flow::Call(0x3_c0bc));
    }

    /// `l.sfgtui r3, 19; l.bf default; l.slli r3, r3, 2; l.movhi r17, 2;
    /// l.ori r17, r17, 0x7c94; l.add r3, r3, r17; l.lwz r3, 0(r3); l.jr r3;
    /// l.nop`.
    #[test]
    fn switch_notes() {
        let insns = run(
            &[
                0xbc43_0013,
                0x1000_0010,
                0xb863_0002,
                0x1a20_0002,
                0xaa31_7c94,
                0xe063_8800,
                0x8463_0000,
                0x4400_1800,
                0x1500_0000,
            ],
            0x1000,
        );
        assert_eq!(insns[0].note, Note::Compare { reg: 3, imm: 19 });
        assert_eq!(insns[1].note, Note::Copy { reg: 3, src: 3 });
        assert_eq!(
            insns[5].note,
            Note::Load {
                reg: 3,
                mem: Mem {
                    base: Some(17),
                    index: Some(3),
                    scale: 4,
                    disp: 0,
                },
                size: 4,
                signed: false,
            }
        );
        assert_eq!(insns[6].flow, Flow::JumpRegister(3));
    }

    #[test]
    fn frames() {
        let decoder = Decoder::default();
        assert!(decoder.starts_frame(&0x9c21_fff0_u32.to_be_bytes()));
        assert!(!decoder.starts_frame(&0x9c21_0010_u32.to_be_bytes()));
    }
}
