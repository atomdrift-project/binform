//! MIPS (32- and 64-bit, either byte order): control flow only. A branch,
//! jump, call or return and the instruction in its delay slot, which runs
//! before control moves, decode as one 8-byte instruction, so a call
//! returns past the slot and a block ends after it.
//!
//! Position-independent code calls through `$t9`, loaded from the GOT at an
//! offset from `_gp` (`lw $t9, n($gp); jalr $t9`): the decoder follows the
//! load, so the call reads as one through that GOT slot.
//!
//! For jump tables the decoder notes what GCC's `switch` computes: the
//! bound (`sltiu $at, $a0, n; beqz $at, default`), the table's address
//! (`lui; addiu`, or a GOT page entry and `addiu`), the scaled index added
//! to it and loaded (`sll; addu; lw`, fused into one indexed load), and a
//! GOT-relative entry (`addu $v0, $v0, $gp; jr $v0`). Other instructions
//! write the registers they name. A branch's delay slot runs on both
//! paths, so its note is the branch's.
//!
//! Release 6 adds compact branches, jumps and calls, which have no delay
//! slot (`bc`, `balc`, `beqzc`, `jic`, `jialc`, `bnec`, ...), in opcodes
//! earlier releases gave `addi`, `daddi`, the branch-likely instructions
//! and coprocessor 2's loads and stores.

use std::sync::Arc;

use crate::isa::{
    Decode, Extend, Flow, Insn, Mem, Memory, Note, Regs, relative, sext, u32_at, uint,
};

/// `$zero`.
const ZERO: u32 = 0;
/// `$t9`, which a position-independent call goes through.
const T9: u32 = 25;
/// The stack and frame pointers, `$sp` and `$fp`.
const SP: u32 = 29;
const FP: u32 = 30;
/// The global pointer, `$gp`.
const GP: u32 = 28;
/// The return-address register, `$ra`.
const RA: u32 = 31;

/// The MIPS decoder: its byte order, word size, release, and the GOT
/// around the address `_gp` stands for.
#[derive(Clone, Debug)]
pub(crate) struct Decoder {
    big: bool,
    wide: bool,
    /// Release 6, with compact branches in opcodes it reuses.
    r6: bool,
    got: Got,
    state: State,
}

/// What earlier instructions left that a later one needs.
#[derive(Clone, Copy, Debug, Default)]
struct State {
    /// The GOT slot `$t9` was loaded from.
    t9: Option<u64>,
    /// The address in `$t9`: a local GOT entry (a page) plus its low bits
    /// (`ld $t9, %got_page(f)($gp); daddiu $t9, $t9, %got_ofst(f)`).
    target: Option<u64>,
    /// A register holding another shifted left, and by how much.
    scaled: Option<(u32, u8)>,
    /// A register holding a base plus a scaled index: the address the load
    /// after it reads from (destination, base, index, shift).
    indexed: Option<(u32, u32, u32, u8)>,
    /// Registers other than `$gp` holding `_gp`'s address, as a mask.
    gp_regs: u32,
    /// A register on its way to `_gp`'s address (`lui rX, %hi; addu rX,
    /// rX, $t9; addiu rX, rX, %lo`), and whether `$t9` is added yet.
    hi: Option<(u32, bool)>,
    /// Small constants in registers (`li $s3, 10`): the bound a Release 6
    /// compact branch compares an index against.
    small: Regs<u16, 32>,
}

/// The GOT as the file holds it, around the address `_gp` stands for: its
/// local entries hold the addresses of pages and of local data.
#[derive(Clone, Debug, Default)]
pub(crate) struct Got {
    pub(crate) gp: Option<u64>,
    /// The other values `$gp` takes in a binary linked with several GOTs,
    /// as the known functions' `$gp` setups compute them; none is recorded.
    others: Arc<[u64]>,
    /// The bytes of each segment within `$gp`'s reach, by address.
    pieces: Arc<[(u64, Box<[u8]>)]>,
}

impl Decoder {
    pub(crate) fn new(image: &crate::Binary<'_>, arch: crate::Arch) -> Self {
        let big = arch.big_endian();
        let entries = image.seeds.iter().map(|seed| seed.addr);
        let starts = image.extents.iter().map(|range| range.start);
        let memory = Memory::new(&image.segments);
        let got = Got::new(image.got, &memory);
        Self {
            big,
            wide: arch.address_width() == 8,
            r6: arch.mips_r6(),
            got: got.learn(big, entries.chain(starts), &memory),
            state: State::default(),
        }
    }

    /// The word at `bytes[at..]`.
    fn word(&self, bytes: &[u8], at: usize) -> Option<u32> {
        u32_at(bytes, at, self.big)
    }

    /// An address, cut to the word size.
    const fn wrap(&self, value: u64) -> u64 {
        if self.wide {
            value
        } else {
            value & 0xffff_ffff
        }
    }
}

impl Decode for Decoder {
    fn decode(&mut self, bytes: &[u8], addr: u64) -> Insn {
        let Some(word) = self.word(bytes, 0) else {
            return Insn::new(4, Flow::Invalid);
        };
        if !self.r6 && reserved(word) {
            return Insn::new(4, Flow::Invalid);
        }
        let Some((flow, compact)) = self.flow(word, addr) else {
            let mut insn = Insn::note(4, self.step(word));
            // `nop` (`sll $0, $0, 0`) and `ssnop`, which write only `$0`.
            insn.pad = word == 0 || word == 0x40;
            return insn;
        };
        // A trap has no slot.
        if flow == Flow::Stop {
            return Insn::new(4, flow);
        }
        // `jr $t9`, `jalr $t9`, or Release 6's `jrc $t9` and `jalrc $t9`
        // (`jic $t9, 0`, `jialc $t9, 0`).
        let through_t9 = (word >> 26 == 0 && (word >> 21) & 0x1f == T9)
            || (self.r6 && matches!(word >> 26, 0x36 | 0x3e) && word & 0x03ff_ffff == T9 << 16);
        let flow = match (flow, self.state.t9, self.state.target) {
            (Flow::CallIndirect, _, Some(to)) if through_t9 => Flow::Call(to),
            (Flow::JumpRegister(T9), _, Some(to)) => Flow::Jump(to),
            (Flow::CallIndirect, Some(slot), _) if through_t9 => Flow::CallSlot(slot),
            (Flow::JumpRegister(T9), Some(slot), _) => Flow::JumpSlot(slot),
            _ => flow,
        };
        if compact {
            let mut insn = Insn::new(4, flow);
            insn.note = self.bound(word);
            return insn;
        }
        // The slot runs before the target: GCC puts a table's low address
        // bits there (`jalr $t9; daddiu $a3, $a3, %got_ofst(table)`).
        let at = addr.wrapping_add(4);
        let slot = self.word(bytes, 4).map(|slot| {
            if (!self.r6 && reserved(slot)) || self.flow(slot, at).is_some() {
                Insn::new(4, Flow::Invalid)
            } else {
                Insn::note(4, self.step(slot))
            }
        });
        Insn::new(4, flow).with_slot(slot)
    }

    fn reset(&mut self) {
        self.state = State::default();
    }

    /// A callee changes `$t9` and the other caller-saved registers; `_gp`
    /// stays in the saved ones (`$s0`-`$s7`, `$fp`).
    fn call(&mut self) {
        self.state = State {
            gp_regs: self.state.gp_regs & 0x40ff_0000,
            ..State::default()
        };
    }

    fn starts_frame(&self, bytes: &[u8]) -> bool {
        starts_frame(self.big, bytes)
    }

    fn entry_of(&self, bytes: &[u8], addr: u64) -> Option<u64> {
        gp_entry(self.big, self.wide, self.got.gps(), bytes, addr)
    }
}

impl Got {
    /// The GOT `$gp` reaches, from the segments, when `gp` is known.
    /// Overlapping segments are read as `memory` reads them, so the copy is
    /// never more than the 64 KiB `$gp` reaches, however many a file stacks.
    pub(crate) fn new(gp: Option<u64>, memory: &Memory<'_>) -> Self {
        let Some(gp) = gp else {
            return Self::default();
        };
        let (start, end) = (gp.saturating_sub(0x8000), gp.saturating_add(0x8000));
        let pieces = memory
            .within(start, end)
            .map(|(from, bytes)| (from, bytes.into()))
            .collect();
        Self {
            gp: Some(gp),
            others: Arc::default(),
            pieces,
        }
    }

    /// The values of `$gp` the `$gp` setups of the functions at `entries`
    /// compute (`entry + d`), other than `gp`, that two or more agree on: a
    /// multi-GOT binary's secondary GOTs, which no header records.
    pub(crate) fn learn(
        mut self,
        big: bool,
        entries: impl Iterator<Item = u64>,
        memory: &Memory<'_>,
    ) -> Self {
        let mut counts: std::collections::HashMap<u64, u32> = std::collections::HashMap::new();
        for entry in entries {
            let Some(code) = memory.code(entry) else {
                continue;
            };
            // The setup is within the first eight instructions.
            let setup = (0..32)
                .step_by(4)
                .find_map(|at| gp_setup(big, code.get(at..)?));
            if let Some((d, _)) = setup {
                let count = counts.entry(entry.wrapping_add_signed(d)).or_default();
                *count = count.saturating_add(1);
            }
        }
        let mut others: Vec<(u64, u32)> = counts
            .into_iter()
            .filter(|&(gp, n)| n >= 2 && Some(gp) != self.gp)
            .collect();
        others.sort_unstable_by_key(|&(gp, n)| (std::cmp::Reverse(n), gp));
        self.others = others.into_iter().take(8).map(|(gp, _)| gp).collect();
        self
    }

    /// Every value `$gp` is known to take.
    pub(crate) fn gps(&self) -> impl Iterator<Item = u64> + '_ {
        self.gp.into_iter().chain(self.others.iter().copied())
    }

    /// The `size`-byte word at `gp + offset`.
    fn word(&self, offset: i64, size: usize, big: bool) -> Option<u64> {
        self.read(self.gp?.wrapping_add_signed(offset), size, big)
    }

    /// The `size`-byte word at `addr`, within `$gp`'s reach.
    fn read(&self, addr: u64, size: usize, big: bool) -> Option<u64> {
        let raw = self.pieces.iter().find_map(|(start, bytes)| {
            let at = usize::try_from(addr.checked_sub(*start)?).ok()?;
            bytes.get(at..at.checked_add(size)?)
        })?;
        uint(raw, big)
    }
}

impl Decoder {
    /// The bound a Release 6 unsigned compact branch puts on an index, when it
    /// compares it with a small constant: `bltuc $s3, $v0, default` with `$s3`
    /// 10 leaves `$v0` at most 10, `bgeuc $v0, $s3, default` at most 9.
    fn bound(&self, word: u32) -> Note {
        let (rs, rt) = ((word >> 21) & 0x1f, (word >> 16) & 0x1f);
        if rs == 0 || rt == 0 || rs == rt || !matches!(word >> 26, 0x06 | 0x07) {
            return Note::None;
        }
        let value = |reg: u32| self.state.small.get(reg).map(u64::from);
        // BLTUC rs, rt and BGEUC rs, rt: the constant is the bound on the other
        // register when it comes first, one past it when second.
        match (value(rs), value(rt)) {
            (Some(imm), None) => Note::Compare { reg: rt, imm },
            (None, Some(imm)) if imm > 0 => Note::Compare {
                reg: rs,
                imm: imm.saturating_sub(1),
            },
            _ => Note::None,
        }
    }

    /// What `word`, which transfers nowhere, tells a jump-table tracker, and
    /// which registers it leaves holding `_gp`'s address: position-independent
    /// code computes it from `$t9`, the function's own address, into `$gp` or
    /// another register.
    fn step(&mut self, word: u32) -> Note {
        self.track(word);
        let opcode = word >> 26;
        let (rs, rt, rd) = (
            (word >> 21) & 0x1f,
            (word >> 16) & 0x1f,
            (word >> 11) & 0x1f,
        );
        let gp_regs = self.state.gp_regs | 1 << GP;
        let mut note = self.note(word, gp_regs);
        let (mut hi, mut set_hi, mut gp_dest) = (self.state.hi, false, None);
        match opcode {
            // Release 6's AUI rX, $t9, %hi: `lui` and `addu` in one.
            0x0f if rs == T9 => (hi, set_hi) = (Some((rt, true)), true),
            0x0f if rs != 0 => {}
            // LUI
            0x0f => (hi, set_hi) = (Some((rt, false)), true),
            // ADDU, DADDU rX, rX, $t9
            0 if matches!(word & 0x3f, 0x21 | 0x2d)
                && rd == rs
                && rt == T9
                && hi == Some((rd, false)) =>
            {
                (hi, set_hi) = (Some((rd, true)), true);
                note = Note::Clobber(1 << rd);
            }
            // ADDIU, DADDIU rX, rX, %lo
            0x09 | 0x19 if rs == rt && hi == Some((rt, true)) => {
                gp_dest = Some(rt);
                note = self
                    .got
                    .gp
                    .map_or(Note::Clobber(1 << rt), |addr| Note::Address {
                        reg: rt,
                        addr,
                    });
            }
            _ => {}
        }
        if let Note::Copy { reg, src } = note
            && gp_regs >> src & 1 != 0
        {
            gp_dest = Some(reg);
        }
        let written = writes(word, note) | self.state.indexed.map_or(0, |(sum, ..)| 1 << sum);
        let written = u32::try_from(written & 0xffff_ffff).unwrap_or(u32::MAX);
        self.state.gp_regs &= !written;
        self.state.small.forget(u64::from(written));
        if let Note::Value { reg, value } = note
            && let Ok(value) = u16::try_from(value)
        {
            self.state.small.set(reg, Some(value));
        }
        if let Some(reg) = gp_dest {
            self.state.gp_regs |= 1 << reg;
        }
        if !set_hi && hi.is_some_and(|(reg, _)| written >> reg & 1 != 0) {
            hi = None;
        }
        self.state.hi = hi;
        note
    }

    /// What `word` tells a jump-table tracker, with `gp_regs` the registers
    /// holding `_gp`'s address.
    fn note(&mut self, word: u32, gp_regs: u32) -> Note {
        let is_gp = |reg: u32| gp_regs >> reg & 1 != 0;
        let opcode = word >> 26;
        let (rs, rt, rd) = (
            (word >> 21) & 0x1f,
            (word >> 16) & 0x1f,
            (word >> 11) & 0x1f,
        );
        let imm = sext(word, 16);
        let wide = self.wide;
        let wrap = |value: u64| if wide { value } else { value & 0xffff_ffff };
        let clobber = |reg: u32| {
            if reg == 0 {
                Note::None
            } else {
                Note::Clobber(1 << reg)
            }
        };
        let (scaled, indexed) = (self.state.scaled, self.state.indexed.take());
        let note = match opcode {
            // AUI rX, rY, imm
            0x0f if rs != 0 => clobber(rt),
            // LUI: the high half of an address, no address by itself.
            0x0f => Note::Value {
                reg: rt,
                value: wrap((imm << 16).cast_unsigned()),
            },
            // ADDIU, DADDIU from $zero: `li`.
            0x09 | 0x19 if rs == 0 => Note::Value {
                reg: rt,
                value: wrap(imm.cast_unsigned()),
            },
            0x09 | 0x19 => Note::Offset {
                reg: rt,
                src: rs,
                imm: imm.cast_unsigned(),
            },
            // SLTIU $at, $x, n: `beqz $at` past it takes the cases from n up.
            // The result may replace the value compared: `andi $v0, $a1, 0xff;
            // sltiu $v0, $v0, n` bounds `$a1` all the same.
            0x0b if imm > 0 => Note::Compare {
                reg: rs,
                imm: imm.cast_unsigned().wrapping_sub(1),
            },
            // LW, LWU, LD
            0x23 | 0x27 | 0x37 => {
                let (size, signed) = match opcode {
                    0x23 => (4, true),
                    0x27 => (4, false),
                    _ => (8, false),
                };
                match indexed {
                    // A GOT entry: a fixed address.
                    _ if is_gp(rs) => self.got.word(imm, usize::from(size), self.big).map_or(
                        clobber(rt),
                        |value| {
                            let value = if signed {
                                sext(value, 32).cast_unsigned()
                            } else {
                                value
                            };
                            Note::Address {
                                reg: rt,
                                addr: wrap(value),
                            }
                        },
                    ),
                    Some((sum, base, index, shift)) if sum == rs => Note::Load {
                        reg: rt,
                        mem: Mem {
                            base: Some(base),
                            index: Some(index),
                            scale: 1 << shift,
                            disp: imm.cast_unsigned(),
                        },
                        size,
                        signed: signed && self.wide,
                    },
                    _ => clobber(rt),
                }
            }
            0 => match word & 0x3f {
                // SLL, DSLL by 1-3: a scaled copy.
                0x00 | 0x38 if (1..=3).contains(&((word >> 6) & 0x1f)) && rd != 0 => {
                    self.state.scaled = Some((rd, u8::try_from((word >> 6) & 0x1f).unwrap_or(0)));
                    return Note::Copy { reg: rd, src: rt };
                }
                // Release 6's LSA, DLSA rd, rs, rt, n: rt plus rs shifted left
                // by n, the address a table entry is loaded from.
                0x05 | 0x15 if rd != 0 => {
                    let shift = u8::try_from((word >> 6) & 3).unwrap_or(0).wrapping_add(1);
                    self.state.indexed = Some((rd, rt, rs, shift));
                    return Note::None;
                }
                // ADDU, DADDU, OR with $zero: a copy.
                0x21 | 0x2d | 0x25 if rt == 0 => Note::Copy { reg: rd, src: rs },
                0x21 | 0x2d | 0x25 if rs == 0 => Note::Copy { reg: rd, src: rt },
                // ADDU, DADDU
                0x21 | 0x2d => match scaled {
                    Some((reg, shift)) if reg == rs || reg == rt => {
                        let base = if reg == rs { rt } else { rs };
                        self.state.indexed = Some((rd, base, reg, shift));
                        return Note::None;
                    }
                    _ if is_gp(rt) || is_gp(rs) => match self.got.gp {
                        Some(gp) => Note::Offset {
                            reg: rd,
                            src: if is_gp(rt) { rs } else { rt },
                            imm: gp,
                        },
                        None => clobber(rd),
                    },
                    _ => Note::Add {
                        reg: rd,
                        base: rs,
                        index: rt,
                        shift: 0,
                        extend: Extend::None,
                    },
                },
                _ => clobber(rd),
            },
            // ANDI with a byte or halfword mask: a case value narrowed, still
            // below any bound it had.
            0x0c if matches!(word & 0xffff, 0xff | 0xffff) => Note::Copy { reg: rt, src: rs },
            0x1c => clobber(rd),
            0x1f => Note::Clobber((1 << rd | 1 << rt) & !1),
            // Stores, CACHE, PREF, and the floating-point loads and stores;
            // SC and SCD write their success.
            0x38 | 0x3c => clobber(rt),
            0x28..=0x2f | 0x31 | 0x33 | 0x35 | 0x39 | 0x3d => Note::None,
            // Coprocessor moves to a general register.
            0x10..=0x12 if rs < 4 => clobber(rt),
            0x10..=0x12 => Note::None,
            _ => clobber(rt),
        };
        // A scaled index stays until its register is written.
        if let Some((reg, _)) = self.state.scaled
            && writes(word, note) & (1 << reg) != 0
        {
            self.state.scaled = None;
        }
        note
    }

    /// Follow what `word`, which transfers nowhere, does to `$t9`: a load from
    /// a fixed offset off a register other than the stack's is a GOT load
    /// (whichever register holds `_gp`); anything else that may write `$t9`
    /// forgets it.
    fn track(&mut self, word: u32) {
        let gp = self.got.gp;
        let opcode = word >> 26;
        let (rs, rt, rd) = (
            (word >> 21) & 0x1f,
            (word >> 16) & 0x1f,
            (word >> 11) & 0x1f,
        );
        // LW, LD
        if matches!(opcode, 0x23 | 0x37) && rt == T9 {
            self.state.t9 = gp
                .filter(|_| !matches!(rs, ZERO | SP | FP))
                .map(|gp| self.wrap(gp.wrapping_add_signed(sext(word, 16))));
            self.state.target = None;
            return;
        }
        // ADDIU, DADDIU $t9, $t9: a local GOT entry's page plus the offset.
        if matches!(opcode, 0x09 | 0x19) && rs == T9 && rt == T9 {
            let size = if self.wide { 8 } else { 4 };
            self.state.target = self
                .state
                .t9
                .and_then(|slot| self.got.read(slot, size, self.big))
                .filter(|&page| page != 0)
                .map(|page| self.wrap(page.wrapping_add_signed(sext(word, 16))));
            self.state.t9 = None;
            return;
        }
        let writes = match opcode {
            // SPECIAL, SPECIAL2
            0 | 0x1c => rd == T9,
            // SPECIAL3 writes either.
            0x1f => rd == T9 || rt == T9,
            // Stores, CACHE, PREF.
            0x28..=0x2f | 0x38..=0x3f => false,
            _ => rt == T9,
        };
        if writes {
            self.state.t9 = None;
            self.state.target = None;
        }
    }

    /// Where control goes after the transfer at `addr` and its slot; `None`
    /// for an instruction that is no transfer. Release 6's compact transfers
    /// come with `true`: they have no slot.
    fn flow(&self, word: u32, addr: u64) -> Option<(Flow, bool)> {
        let opcode = word >> 26;
        let rs = (word >> 21) & 0x1f;
        let rt = (word >> 16) & 0x1f;
        let slot = addr.wrapping_add(4);
        // A word offset of `bits` bits from the slot (compact branches count
        // from the next instruction, the same address).
        let offset = |bits: u32| self.wrap(relative(slot, word, bits, 4));
        let branch = offset(16);
        if self.r6 {
            let compact = match opcode {
                // BLEZALC, BGEZALC, BGTZALC, BLTZALC; BGEUC, BLTUC. With rt
                // zero, BLEZ and BGTZ, which have slots.
                0x06 | 0x07 if rt != 0 && (rs == 0 || rs == rt) => Flow::Call(branch),
                0x06 | 0x07 if rt != 0 => Flow::Branch(branch),
                // BEQZALC, BNEZALC; BEQC, BNEC, BOVC, BNVC.
                0x08 | 0x18 if rs == 0 && rt != 0 => Flow::Call(branch),
                0x08 | 0x18 => Flow::Branch(branch),
                // BLEZC, BGEZC, BGEC; BGTZC, BLTZC, BLTC.
                0x16 | 0x17 => Flow::Branch(branch),
                // BC, BALC
                0x32 => Flow::Jump(offset(26)),
                0x3a => Flow::Call(offset(26)),
                // BEQZC, BNEZC
                0x36 | 0x3e if rs != 0 => Flow::Branch(offset(21)),
                // JIC (`jrc` at offset 0), JIALC (`jalrc`): to a register plus
                // an offset.
                0x36 if word & 0xffff == 0 && rt == RA => Flow::Return,
                0x36 if word & 0xffff == 0 => Flow::JumpRegister(rt),
                0x36 => Flow::JumpIndirect,
                0x3e => Flow::CallIndirect,
                // BEQL, BNEL are gone.
                0x14 | 0x15 => Flow::Invalid,
                // BC1EQZ, BC1NEZ, BC2EQZ, BC2NEZ: with slots.
                0x11 | 0x12 if rs == 0x09 || rs == 0x0d => {
                    return Some((Flow::Branch(branch), false));
                }
                _ => Flow::Next,
            };
            if compact != Flow::Next {
                return Some((compact, true));
            }
        }
        Some((
            match opcode {
                0 => match word & 0x3f {
                    // JR, JR.HB
                    0x08 if rs == RA => Flow::Return,
                    0x08 => Flow::JumpRegister(rs),
                    // JALR $zero, which Release 6 writes `jr` as.
                    0x09 if (word >> 11) & 0x1f == 0 && rs == RA => Flow::Return,
                    0x09 if (word >> 11) & 0x1f == 0 => Flow::JumpRegister(rs),
                    // JALR
                    0x09 => Flow::CallIndirect,
                    // BREAK
                    0x0d => Flow::Stop,
                    _ => return None,
                },
                // REGIMM: BLTZ, BGEZ and their likely and linking forms.
                1 => match rt {
                    0x00..=0x03 => Flow::Branch(branch),
                    // BLTZAL, BGEZAL (`bal` on $zero) and their likely forms.
                    0x10..=0x13 => Flow::Call(branch),
                    _ => return None,
                },
                // J, JAL: the low 28 bits of the slot's region.
                2 | 3 => {
                    let target =
                        self.wrap((slot & !0x0fff_ffff) | u64::from(word & 0x03ff_ffff) << 2);
                    if opcode == 2 {
                        Flow::Jump(target)
                    } else {
                        Flow::Call(target)
                    }
                }
                // BEQ $x, $x is `b`, always taken.
                4 if rs == rt => Flow::Jump(branch),
                // BEQ, BNE, BLEZ, BGTZ and their likely forms.
                4..=7 | 0x14..=0x17 => Flow::Branch(branch),
                // BC1F, BC1T and their likely forms.
                0x11 if rs == 8 => Flow::Branch(branch),
                _ => return None,
            },
            false,
        ))
    }
}

/// The `$gp` setup at the start of `bytes`: `lui $gp, %hi(d)` then, in some
/// order within three instructions, `(d)addu $gp, $gp, $t9` and `(d)addiu
/// $gp, $gp, %lo(d)`, or Release 6's `aui $gp, $t9, %hi(d)` and the `addiu`.
/// It computes `$gp` from `$t9`, the function's own address: `d = _gp -
/// entry`. Returns `d`, and whether it is o32's `.cpload` (`lui; addiu;
/// addu`, in that order), which is a function's first instruction.
fn gp_setup(big: bool, bytes: &[u8]) -> Option<(i64, bool)> {
    let first = u32_at(bytes, 0, big)?;
    let aui = first >> 16 == 0x3f3c;
    if first >> 16 != 0x3c1c && !aui {
        return None;
    }
    let addiu = |w: u32| w >> 16 == 0x279c || w >> 16 == 0x679c;
    let add_t9 = |w: u32| w == 0x0399_e021 || w == 0x0399_e02d;
    // A missing word leaves the ones after it missing too.
    let rest = [4, 8, 12].map(|at| u32_at(bytes, at, big));
    let low = rest.iter().flatten().copied().find(|&w| addiu(w))?;
    if !aui && !rest.iter().flatten().copied().any(add_t9) {
        return None;
    }
    let cpload = !aui && matches!(rest, [Some(second), Some(0x0399_e021), _] if addiu(second));
    let (hi, lo) = (sext(first << 16, 32), sext(low, 16));
    Some((hi.wrapping_add(lo), cpload))
}

/// The entry of the position-independent function whose `$gp` setup (see
/// [`gp_setup`]) starts at `addr`. o32's `.cpload` is its own entry,
/// whatever `_gp` is. n64 and Release 6 code set `$gp` a few instructions
/// in, after the frame, so their entry is the one `d` names from one of the
/// values `$gp` is known to take (`gps`). Such functions are often reached
/// only through pointers (callbacks, vtables, local GOT entries), so the
/// sweep seeds them.
pub(crate) fn gp_entry(
    big: bool,
    wide: bool,
    gps: impl Iterator<Item = u64>,
    bytes: &[u8],
    addr: u64,
) -> Option<u64> {
    let (d, cpload) = gp_setup(big, bytes)?;
    if cpload {
        return Some(addr);
    }
    let mask = if wide { u64::MAX } else { 0xffff_ffff };
    gps.map(|gp| gp.wrapping_sub_signed(d) & mask)
        .find(|&entry| entry <= addr && addr.wrapping_sub(entry) <= 32 && entry.is_multiple_of(4))
}

/// The registers `word` writes, by the `note` it left: those the note
/// names, but for SLTIU, whose note is the bound it puts on `rs` and which
/// writes `rt`.
fn writes(word: u32, note: Note) -> u64 {
    if word >> 26 == 0x0b {
        1 << ((word >> 16) & 0x1f)
    } else {
        note.writes()
    }
}

/// Whether `word` is an encoding releases before 6 leave reserved, or an
/// instruction with a field they require to be zero set: data, which a
/// walk into the literals and tables GCC and Go place in `.text` would
/// otherwise decode on through. Release 6 reassigns much of this space, and
/// MSA (opcode `0x1e`) and the DSP and MIPS-3D extensions are left alone.
fn reserved(word: u32) -> bool {
    let rs = (word >> 21) & 0x1f;
    let rt = (word >> 16) & 0x1f;
    let sa = (word >> 6) & 0x1f;
    match word >> 26 {
        // SPECIAL
        0x00 => match word & 0x3f {
            // (0x05 and 0x15 are MSA's `lsa` and `dlsa`.)
            0x0e | 0x28 | 0x29 | 0x35 | 0x37 | 0x39 | 0x3d => true,
            // sll, sra, dsll, dsra, dsll32, dsra32 take no `rs`; srl and
            // the doubleword right shifts only `rs` 1, as rotations.
            0x00 | 0x03 | 0x38 | 0x3b | 0x3c | 0x3f => rs != 0,
            0x02 | 0x3a | 0x3e => rs > 1,
            // The three-register ALU operations take no shift amount.
            0x20..=0x2f => sa != 0,
            _ => false,
        },
        // REGIMM
        0x01 => matches!(rt, 0x04..=0x07 | 0x0d | 0x0f | 0x14..=0x1b | 0x1d),
        // COP1: the formats and moves with no assignment, and MIPS-3D's
        // `bc1any2` and `bc1any4`, which no current core has.
        0x11 => matches!(rs, 0x09..=0x0f | 0x12 | 0x13 | 0x17..=0x1f),
        0x3b => true,
        _ => false,
    }
}

/// Whether `bytes` begin a frame: `(d)addiu $sp, $sp, -n`.
pub(crate) fn starts_frame(big: bool, bytes: &[u8]) -> bool {
    u32_at(bytes, 0, big).is_some_and(|w| matches!(w >> 15, 0x4f7b | 0xcf7b) && w & 3 == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A decoder of big-endian 32-bit code, of Release 6 when `r6`.
    fn decoder(r6: bool, got: &Got) -> Decoder {
        Decoder {
            big: true,
            wide: false,
            r6,
            got: got.clone(),
            state: State::default(),
        }
    }

    #[test]
    fn pic_entries() {
        let be =
            |words: &[u32]| -> Vec<u8> { words.iter().flat_map(|w| w.to_be_bytes()).collect() };
        let le =
            |words: &[u32]| -> Vec<u8> { words.iter().flat_map(|w| w.to_le_bytes()).collect() };
        // o32 at 0xac124: lui gp, 0x8e; addiu gp, gp, -0x1da4; addu gp, gp, t9,
        // with _gp = 0xac124 + 0x8e0000 - 0x1da4.
        let o32 = [0x3c1c_008e, 0x279c_e25c, 0x0399_e021];
        let gp = 0xac124 + 0x8e_0000 - 0x1da4;
        assert_eq!(
            gp_entry(true, false, Some(gp).into_iter(), &be(&o32), 0xac124),
            Some(0xac124)
        );
        assert_eq!(
            gp_entry(false, false, Some(gp).into_iter(), &le(&o32), 0xac124),
            Some(0xac124)
        );
        // A `.cpload` is its function's entry whatever `_gp` is: a multi-GOT
        // executable has several.
        assert_eq!(
            gp_entry(true, false, Some(gp).into_iter(), &be(&o32), 0xac200),
            Some(0xac200)
        );
        // Without _gp, o32's order at the start.
        assert_eq!(
            gp_entry(true, false, None.into_iter(), &be(&o32), 0x1000),
            Some(0x1000)
        );
        assert_eq!(
            gp_entry(false, false, None.into_iter(), &be(&o32), 0x1000),
            None
        );
        // n64, 8 bytes after the entry 0x17ee8: lui gp, 2; daddu gp, gp, t9;
        // daddiu gp, gp, 0x7f18 (d = _gp - entry = 0x2_7f18 - 0x1_0000).
        let n64 = [0x3c1c_0002, 0x0399_e02d, 0x679c_7f18];
        let gp = 0x17ee8 + 0x2_7f18;
        assert_eq!(
            gp_entry(true, true, Some(gp).into_iter(), &be(&n64), 0x17ef0),
            Some(0x17ee8)
        );
        // ... but not when no _gp names the entry.
        assert_eq!(
            gp_entry(true, true, None.into_iter(), &be(&n64), 0x17ef0),
            None
        );
        // A lui of another register is none.
        assert_eq!(
            gp_entry(
                true,
                false,
                None.into_iter(),
                &be(&[0x3c04_008e, 0x279c_e25c, 0x0399_e021]),
                0
            ),
            None
        );
    }

    fn one(words: &[u32], addr: u64) -> Insn {
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_be_bytes()).collect();
        decoder(false, &Got::default()).decode(&bytes, addr)
    }

    /// Each instruction of `words` at `addr` on, as Release 6 code.
    fn r6(words: &[u32], addr: u64) -> Vec<(Flow, u32)> {
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_be_bytes()).collect();
        let mut decoder = decoder(true, &Got::default());
        let mut out = Vec::new();
        let mut at = 0;
        while at < bytes.len() {
            let insn = decoder.decode(&bytes[at..], addr + at as u64);
            out.push((insn.flow, insn.len));
            at += insn.len as usize;
        }
        out
    }

    /// `sltiu $s3, $a0, 5` bounds `$a0` and writes `$s3`: the constant `li`
    /// left in `$s3` is gone, and bounds no `bltuc` after it.
    #[test]
    fn sltiu_writes_its_target() {
        let bytes: Vec<u8> = [0x2413_000a_u32, 0x2c93_0005, 0x1e62_0004]
            .iter()
            .flat_map(|w| w.to_be_bytes())
            .collect();
        let mut decoder = decoder(true, &Got::default());
        let notes: Vec<Note> = (0..3)
            .map(|i| decoder.decode(&bytes[4 * i..], 0x1000 + 4 * i as u64).note)
            .collect();
        assert_eq!(notes[1], Note::Compare { reg: 4, imm: 4 });
        assert_eq!(notes[2], Note::None);
    }

    /// `sll $v0, $a0, 2` scales `$a0`; `sltiu $v0, $a1, 5` overwrites the
    /// scaled copy, so `addu $v1, $v0, $a2; lw $t0, 0($v1)` reads no
    /// entry of a table `$a0` indexes.
    #[test]
    fn sltiu_ends_a_scaled_index() {
        let notes = insns(
            &[0x0004_1080, 0x2ca2_0005, 0x0046_1821, 0x8c68_0000],
            0x1000,
            &Got::default(),
        );
        assert_eq!(notes[3].note, Note::Clobber(1 << 8));
    }

    #[test]
    fn release_6() {
        let flows = r6(
            &[
                0xc800_0010, // bc +0x40
                0xe800_0001, // balc +4
                0xd880_0002, // beqzc $a0, +8
                0xd81f_0000, // jrc $ra
                0xf819_0000, // jalrc $t9
                0x6085_0001, // bnec $a0, $a1, +4
                0x2005_0001, // beqzalc $a1, +4
                0x1880_0003, // blez $a0, +12, with a slot
                0,
                0x03e0_0009, // jalr $zero, $ra: jr $ra
                0,
            ],
            0x1000,
        );
        assert_eq!(
            flows,
            [
                (Flow::Jump(0x1044), 4),
                (Flow::Call(0x100c), 4),
                (Flow::Branch(0x1014), 4),
                (Flow::Return, 4),
                (Flow::CallIndirect, 4),
                (Flow::Branch(0x101c), 4),
                (Flow::Call(0x1020), 4),
                (Flow::Branch(0x102c), 8),
                (Flow::Return, 8),
            ]
        );
        // Before Release 6, 0x2005_0001 is `addi $a1, $zero, 1`.
        assert_eq!(one(&[0x2005_0001], 0x1000).flow, Flow::Next);
        // li $s3, 10; bltuc $s3, $v0, default: $v0 at most 10. With the
        // operands swapped, bgeuc $v0, $s3: at most 9.
        for (branch, imm) in [(0x1e62_0004, 10), (0x1853_0004, 9)] {
            let bytes: Vec<u8> = [0x2413_000a_u32, branch]
                .iter()
                .flat_map(|w| w.to_be_bytes())
                .collect();
            let mut decoder = decoder(true, &Got::default());
            decoder.decode(&bytes, 0x1000);
            let insn = decoder.decode(&bytes[4..], 0x1004);
            assert_eq!(insn.note, Note::Compare { reg: 2, imm });
        }
        // lsa $v0, $a0, $v1, 2; lw $v0, 0($v0): a table entry's load.
        let notes = insns(&[0x0083_1045, 0x8c42_0000], 0x1000, &Got::default());
        assert_eq!(
            notes[1].note,
            Note::Load {
                reg: 2,
                mem: Mem {
                    base: Some(3),
                    index: Some(4),
                    scale: 4,
                    disp: 0
                },
                size: 4,
                signed: false
            }
        );
    }

    /// Each instruction of `words` at `addr` on, in order, with `got`.
    fn insns(words: &[u32], addr: u64, got: &Got) -> Vec<Insn> {
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_be_bytes()).collect();
        let mut decoder = decoder(false, got);
        let mut out = Vec::new();
        let mut at = 0;
        while at < bytes.len() {
            let insn = decoder.decode(&bytes[at..], addr + at as u64);
            out.push(insn);
            at += insn.len as usize;
        }
        out
    }

    /// The flows of `words` at `addr` on, with `_gp` at `gp`.
    fn run(words: &[u32], addr: u64, gp: u64) -> Vec<Flow> {
        let got = Got {
            gp: Some(gp),
            ..Got::default()
        };
        insns(words, addr, &got)
            .iter()
            .map(|insn| insn.flow)
            .collect()
    }

    #[test]
    fn frames() {
        let starts = |w: u32| starts_frame(true, &w.to_be_bytes());
        // addiu $sp, $sp, -32; daddiu $sp, $sp, -64
        assert!(starts(0x27bd_ffe0));
        assert!(starts(0x67bd_ffc0));
        // addiu $sp, $sp, 32 (an epilogue) is not.
        assert!(!starts(0x27bd_0020));
    }

    #[test]
    fn reserved_encodings_are_no_code() {
        // A data word in `.text` that reads as COP1 format 0x0a.
        assert_eq!(one(&[0x454f_3090], 0x1000).flow, Flow::Invalid);
        // sll with an `rs`; addu with a shift amount; REGIMM rt 0x14.
        assert_eq!(one(&[0x0021_0800], 0x1000).flow, Flow::Invalid);
        assert_eq!(one(&[0x0043_0861], 0x1000).flow, Flow::Invalid);
        assert_eq!(one(&[0x0414_0001], 0x1000).flow, Flow::Invalid);
        // rotr (srl with `rs` 1), ehb, and a plain addu are code.
        assert_eq!(one(&[0x0021_0842], 0x1000).flow, Flow::Next);
        assert_eq!(one(&[0x0000_00c0], 0x1000).flow, Flow::Next);
        assert_eq!(one(&[0x0043_0821], 0x1000).flow, Flow::Next);
    }

    #[test]
    fn switch_notes() {
        let gp = 0x2_7ff0;
        let got = Got {
            gp: Some(gp),
            pieces: vec![(gp - 0x7ff0, vec![0, 1, 0, 0].into())].into(),
            others: Arc::default(),
        };
        let code = [
            0x2c81_0010, // sltiu $at, $a0, 16
            0x1020_0010, // beqz $at, default
            0x0004_1080, // sll $v0, $a0, 2
            0x8f83_8010, // lw $v1, -0x7ff0($gp)
            0x2463_0100, // addiu $v1, $v1, 0x100
            0x0043_1021, // addu $v0, $v0, $v1
            0x8c42_0000, // lw $v0, 0($v0)
            0x005c_1021, // addu $v0, $v0, $gp
            0x0040_0008, // jr $v0
            0,
        ];
        let notes: Vec<Note> = insns(&code, 0x1000, &got)
            .iter()
            .map(|insn| insn.note)
            .collect();
        assert_eq!(notes[0], Note::Compare { reg: 4, imm: 15 });
        assert_eq!(notes[1], Note::Copy { reg: 2, src: 4 });
        assert_eq!(
            notes[2],
            Note::Address {
                reg: 3,
                addr: 0x1_0000
            }
        );
        assert_eq!(
            notes[3],
            Note::Offset {
                reg: 3,
                src: 3,
                imm: 0x100
            }
        );
        assert_eq!(notes[4], Note::None);
        assert_eq!(
            notes[5],
            Note::Load {
                reg: 2,
                mem: Mem {
                    base: Some(3),
                    index: Some(2),
                    scale: 4,
                    disp: 0
                },
                size: 4,
                signed: false
            }
        );
        assert_eq!(
            notes[6],
            Note::Offset {
                reg: 2,
                src: 2,
                imm: gp
            }
        );
    }

    #[test]
    fn calls_through_the_got() {
        // lw $t9, -0x7fd8($s0); jalr $t9; nop
        let flows = run(&[0x8e19_8028, 0x0320_f809, 0], 0x1000, 0x2_7ff0);
        assert_eq!(flows, [Flow::Next, Flow::CallSlot(0x2_0018)]);
        // lw $t9, -0x7fd8($gp); addiu $t9, $t9, 8; jalr $t9; nop
        let flows = run(
            &[0x8f99_8028, 0x2739_0008, 0x0320_f809, 0],
            0x1000,
            0x2_7ff0,
        );
        assert_eq!(flows[2], Flow::CallIndirect);
        // The same with the GOT entry known: a page, so a direct call.
        let got = Got {
            gp: Some(0x2_7ff0),
            pieces: vec![(0x2_0018, vec![0, 1, 0, 0].into())].into(),
            others: Arc::default(),
        };
        let words = [0x8f99_8028, 0x2739_0008, 0x0320_f809, 0];
        let calls: Vec<Flow> = insns(&words, 0x1000, &got)
            .iter()
            .map(|insn| insn.flow)
            .collect();
        assert_eq!(calls[2], Flow::Call(0x1_0008));
        // lw $t9, 16($sp): a spilled pointer, not a GOT slot.
        let flows = run(&[0x8fb9_0010, 0x0320_f809, 0], 0x1000, 0x2_7ff0);
        assert_eq!(flows[1], Flow::CallIndirect);
        // lw $t9, -0x7fd8($gp); jr $t9; nop: a tail call.
        let flows = run(&[0x8f99_8028, 0x0320_0008, 0], 0x1000, 0x2_7ff0);
        assert_eq!(flows[1], Flow::JumpSlot(0x2_0018));
        // A call forgets `$t9`, but not `_gp` in a saved register.
        let mut decoder = decoder(false, &Got::default());
        decoder.state.t9 = Some(1);
        decoder.state.gp_regs = 1 << 16 | 1 << 4;
        decoder.call();
        assert_eq!((decoder.state.t9, decoder.state.gp_regs), (None, 1 << 16));
    }

    #[test]
    fn transfers_take_their_slot() {
        // jal 0x400100; nop
        let call = one(&[0x0c10_0040, 0], 0x40_0000);
        assert_eq!((call.len, call.flow), (8, Flow::Call(0x40_0100)));
        // jr $ra; nop
        assert_eq!(one(&[0x03e0_0008, 0], 0x1000).flow, Flow::Return);
        // jr $t9
        assert_eq!(one(&[0x0320_0008, 0], 0x1000).flow, Flow::JumpRegister(25));
        // beq $a0, $zero, -4 words from the slot
        let back = one(&[0x1080_fffc, 0], 0x1010);
        assert_eq!(back.flow, Flow::Branch(0x1004));
        // b +2 words
        assert_eq!(one(&[0x1000_0002, 0], 0x1000).flow, Flow::Jump(0x100c));
        // bal
        assert_eq!(one(&[0x0411_0001, 0], 0x1000).flow, Flow::Call(0x1008));
        // jalr $t9
        assert_eq!(one(&[0x0320_f809, 0], 0x1000).flow, Flow::CallIndirect);
    }

    #[test]
    fn others_fall_through() {
        let nop = one(&[0], 0x1000);
        assert_eq!((nop.len, nop.flow, nop.pad), (4, Flow::Next, true));
        // addiu $sp, $sp, -32
        assert_eq!(one(&[0x27bd_ffe0], 0x1000).flow, Flow::Next);
        // break
        assert_eq!(one(&[0x0000_000d], 0x1000).flow, Flow::Stop);
        // A jump with no slot, with a reserved word in it, or with a
        // transfer in it.
        assert_eq!(one(&[0x0800_0000], 0x1000).flow, Flow::Invalid);
        assert_eq!(one(&[0x0800_0000, 0x454f_3090], 0x1000).flow, Flow::Invalid);
        assert_eq!(one(&[0x0800_0000, 0x03e0_0008], 0x1000).flow, Flow::Invalid);
        // li $a0, 5; lui $a1, 0x40: integers, not addresses.
        assert_eq!(
            one(&[0x2404_0005], 0x1000).note,
            Note::Value { reg: 4, value: 5 }
        );
        assert_eq!(
            one(&[0x3c05_0040], 0x1000).note,
            Note::Value {
                reg: 5,
                value: 0x40_0000
            }
        );
    }

    #[test]
    fn little_endian_and_64_bit() {
        let bytes: Vec<u8> = [0x0c10_0040_u32, 0]
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect();
        let mut decoder = Decoder {
            big: false,
            wide: true,
            ..decoder(false, &Got::default())
        };
        let call = decoder.decode(&bytes, 0x1_2000_0000);
        assert_eq!(call.flow, Flow::Call(0x1_2040_0100));
    }
}
