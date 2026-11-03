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

use crate::Segment;
use crate::isa::{Extend, Flow, Insn, Mem, Note};

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

/// What earlier instructions left that a later one needs.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct State {
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
    /// Small constants in registers (`li $s3, 10`), as a mask and values:
    /// the bound a Release 6 compact branch compares an index against.
    small: u32,
    values: [u16; 32],
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

impl Got {
    /// The GOT `$gp` reaches, from the segments, when `gp` is known.
    pub(crate) fn new(gp: Option<u64>, segments: &[Segment<'_>]) -> Self {
        let Some(gp) = gp else {
            return Self::default();
        };
        let (start, end) = (gp.saturating_sub(0x8000), gp.saturating_add(0x8000));
        let pieces = segments
            .iter()
            .filter_map(|segment| {
                let len = u64::try_from(segment.bytes.len()).ok()?;
                let from = start.max(segment.addr);
                let to = end.min(segment.addr.checked_add(len)?);
                let at = usize::try_from(from.checked_sub(segment.addr)?).ok()?;
                let n = usize::try_from(to.checked_sub(from)?).ok()?;
                let bytes = segment.bytes.get(at..at.checked_add(n)?)?;
                (n > 0).then(|| (from, bytes.into()))
            })
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
        segments: &[Segment<'_>],
    ) -> Self {
        let mut counts: std::collections::HashMap<u64, u32> = std::collections::HashMap::new();
        for entry in entries {
            let Some(code) = segments.iter().filter(|s| s.executable).find_map(|s| {
                let at = usize::try_from(entry.checked_sub(s.addr)?).ok()?;
                s.bytes.get(at..)
            }) else {
                continue;
            };
            // The setup is within the first eight instructions.
            if let Some(d) = (0..8).find_map(|i| gp_setup(big, code.get(i * 4..)?).map(|(d, _)| d)) {
                *counts.entry(entry.wrapping_add_signed(d)).or_default() += 1;
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
        let fold = |value: u64, &byte: &u8| value << 8 | u64::from(byte);
        Some(if big {
            raw.iter().fold(0, fold)
        } else {
            raw.iter().rev().fold(0, fold)
        })
    }
}

/// The instruction at `addr`, with the GOT its code reaches through `$gp`.
pub(crate) fn decode(
    state: &mut State,
    got: &Got,
    (big, wide, r6): (bool, bool, bool),
    bytes: &[u8],
    addr: u64,
) -> Insn {
    let Some(word) = read_word(big, bytes) else {
        return Insn::new(4, Flow::Invalid);
    };
    if !r6 && reserved(word) {
        return Insn::new(4, Flow::Invalid);
    }
    let Some((flow, compact)) = flow(word, addr, wide, r6) else {
        track(state, word, got, (big, wide));
        let mut insn = Insn::new(4, Flow::Next);
        // `nop` (`sll $0, $0, 0`) and `ssnop`.
        insn.pad = word == 0 || word == 0x40;
        if !insn.pad {
            insn.note = note(state, word, got, big, wide);
        }
        return insn;
    };
    // A trap has no slot.
    if flow == Flow::Stop {
        return Insn::new(4, flow);
    }
    // `jr $t9`, `jalr $t9`, or Release 6's `jrc $t9` and `jalrc $t9`
    // (`jic $t9, 0`, `jialc $t9, 0`).
    let through_t9 = (word >> 26 == 0 && (word >> 21) & 0x1f == T9)
        || (r6 && matches!(word >> 26, 0x36 | 0x3e) && word & 0x03ff_ffff == T9 << 16);
    let flow = match (flow, state.t9, state.target) {
        (Flow::CallIndirect, _, Some(to)) if through_t9 => Flow::Call(to),
        (Flow::JumpRegister(T9), _, Some(to)) => Flow::Jump(to),
        (Flow::CallIndirect, Some(slot), _) if through_t9 => Flow::CallSlot(slot),
        (Flow::JumpRegister(T9), Some(slot), _) => Flow::JumpSlot(slot),
        _ => flow,
    };
    if compact {
        let mut insn = Insn::new(4, flow);
        insn.note = bound(state, word);
        settle(state, flow);
        return insn;
    }
    // A transfer with no slot after it is cut short: the slot is not code.
    let Some(slot) = bytes
        .get(4..8)
        .and_then(|slot| read_word(big, slot))
        .filter(|&slot| r6 || !reserved(slot))
    else {
        return Insn::new(4, Flow::Invalid);
    };
    // The slot runs before the target: GCC puts a table's low address
    // bits there (`jalr $t9; daddiu $a3, $a3, %got_ofst(table)`).
    let mut insn = Insn::new(8, flow);
    track(state, slot, got, (big, wide));
    insn.note = note(state, slot, got, big, wide);
    settle(state, flow);
    insn
}

/// The bound a Release 6 unsigned compact branch puts on an index, when it
/// compares it with a small constant: `bltuc $s3, $v0, default` with `$s3`
/// 10 leaves `$v0` at most 10, `bgeuc $v0, $s3, default` at most 9.
fn bound(state: &State, word: u32) -> Note {
    let (rs, rt) = ((word >> 21) & 0x1f, (word >> 16) & 0x1f);
    if rs == 0 || rt == 0 || rs == rt || !matches!(word >> 26, 0x06 | 0x07) {
        return Note::None;
    }
    let value = |reg: u32| {
        (state.small >> reg & 1 != 0)
            .then(|| state.values.get(reg as usize).copied())
            .flatten()
            .map(u64::from)
    };
    // BLTUC rs, rt and BGEUC rs, rt: the constant is the bound on the other
    // register when it comes first, one past it when second.
    match (value(rs), value(rt)) {
        (Some(imm), None) => Note::Compare { reg: rt, imm },
        (None, Some(imm)) if imm > 0 => Note::Compare {
            reg: rs,
            imm: imm - 1,
        },
        _ => Note::None,
    }
}

/// What a transfer leaves of `state`.
fn settle(state: &mut State, flow: Flow) {
    // A callee changes `$t9` and the other caller-saved registers; `_gp`
    // stays in the saved ones (`$s0`-`$s7`, `$fp`).
    if matches!(flow, Flow::Call(_) | Flow::CallSlot(_) | Flow::CallIndirect) {
        *state = State {
            gp_regs: state.gp_regs & 0x40ff_0000,
            ..State::default()
        };
    }
    // Past a transfer that does not fall through, code is reached from
    // elsewhere: what the slot left (`b out; ld $t9, ...`) is not there.
    if !matches!(
        flow,
        Flow::Next | Flow::Branch(_) | Flow::Call(_) | Flow::CallSlot(_) | Flow::CallIndirect
    ) {
        *state = State::default();
    }
}

/// What `word`, which transfers nowhere, tells a jump-table tracker, and
/// which registers it leaves holding `_gp`'s address: position-independent
/// code computes it from `$t9`, the function's own address, into `$gp` or
/// another register.
fn note(state: &mut State, word: u32, got: &Got, big: bool, wide: bool) -> Note {
    let opcode = word >> 26;
    let (rs, rt, rd) = (
        (word >> 21) & 0x1f,
        (word >> 16) & 0x1f,
        (word >> 11) & 0x1f,
    );
    let gp_regs = state.gp_regs | 1 << GP;
    let mut note = note_of(state, word, got, (big, wide), gp_regs);
    let (mut hi, mut set_hi, mut gp_dest) = (state.hi, false, None);
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
            note = got.gp.map_or(Note::Clobber(1 << rt), |addr| Note::Address {
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
    let written = note.writes() | state.indexed.map_or(0, |(sum, ..)| 1 << sum);
    let written = u32::try_from(written & 0xffff_ffff).unwrap_or(u32::MAX);
    state.gp_regs &= !written;
    state.small &= !written;
    if let Note::Address { reg, addr } = note
        && let Some(slot) = state.values.get_mut(reg as usize)
        && let Ok(value) = u16::try_from(addr)
    {
        *slot = value;
        state.small |= 1 << reg;
    }
    if let Some(reg) = gp_dest {
        state.gp_regs |= 1 << reg;
    }
    if !set_hi && hi.is_some_and(|(reg, _)| written >> reg & 1 != 0) {
        hi = None;
    }
    state.hi = hi;
    note
}

/// What `word` tells a jump-table tracker, with `gp_regs` the registers
/// holding `_gp`'s address.
fn note_of(
    state: &mut State,
    word: u32,
    got: &Got,
    (big, wide): (bool, bool),
    gp_regs: u32,
) -> Note {
    let is_gp = |reg: u32| gp_regs >> reg & 1 != 0;
    let opcode = word >> 26;
    let (rs, rt, rd) = (
        (word >> 21) & 0x1f,
        (word >> 16) & 0x1f,
        (word >> 11) & 0x1f,
    );
    let imm = (i64::from(word & 0xffff) ^ 0x8000) - 0x8000;
    let wrap = |value: u64| if wide { value } else { value & 0xffff_ffff };
    let clobber = |reg: u32| {
        if reg == 0 {
            Note::None
        } else {
            Note::Clobber(1 << reg)
        }
    };
    let (scaled, indexed) = (state.scaled, state.indexed.take());
    let note = match opcode {
        // AUI rX, rY, imm
        0x0f if rs != 0 => clobber(rt),
        // LUI
        0x0f => Note::Address {
            reg: rt,
            addr: wrap((imm << 16).cast_unsigned()),
        },
        // ADDIU, DADDIU
        0x09 | 0x19 if rs == 0 => Note::Address {
            reg: rt,
            addr: wrap(imm.cast_unsigned()),
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
            imm: imm.cast_unsigned() - 1,
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
                _ if is_gp(rs) => {
                    got.word(imm, usize::from(size), big)
                        .map_or(clobber(rt), |value| {
                            let value = if signed {
                                i64::from(u32::try_from(value).unwrap_or(0).cast_signed())
                                    .cast_unsigned()
                            } else {
                                value
                            };
                            Note::Address {
                                reg: rt,
                                addr: wrap(value),
                            }
                        })
                }
                Some((sum, base, index, shift)) if sum == rs => Note::Load {
                    reg: rt,
                    mem: Mem {
                        base: Some(base),
                        index: Some(index),
                        scale: 1 << shift,
                        disp: imm.cast_unsigned(),
                    },
                    size,
                    signed: signed && wide,
                },
                _ => clobber(rt),
            }
        }
        0 => match word & 0x3f {
            // SLL, DSLL by 1-3: a scaled copy.
            0x00 | 0x38 if (1..=3).contains(&((word >> 6) & 0x1f)) && rd != 0 => {
                state.scaled = Some((rd, u8::try_from((word >> 6) & 0x1f).unwrap_or(0)));
                return Note::Copy { reg: rd, src: rt };
            }
            // Release 6's LSA, DLSA rd, rs, rt, n: rt plus rs shifted left
            // by n, the address a table entry is loaded from.
            0x05 | 0x15 if rd != 0 => {
                let shift = u8::try_from((word >> 6) & 3).unwrap_or(0) + 1;
                state.indexed = Some((rd, rt, rs, shift));
                return Note::None;
            }
            // ADDU, DADDU, OR with $zero: a copy.
            0x21 | 0x2d | 0x25 if rt == 0 => Note::Copy { reg: rd, src: rs },
            0x21 | 0x2d | 0x25 if rs == 0 => Note::Copy { reg: rd, src: rt },
            // ADDU, DADDU
            0x21 | 0x2d => match scaled {
                Some((reg, shift)) if reg == rs || reg == rt => {
                    let base = if reg == rs { rt } else { rs };
                    state.indexed = Some((rd, base, reg, shift));
                    return Note::None;
                }
                _ if is_gp(rt) || is_gp(rs) => match got.gp {
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
    if let Some((reg, _)) = state.scaled
        && note.writes() & (1 << reg) != 0
    {
        state.scaled = None;
    }
    note
}

/// Follow what `word`, which transfers nowhere, does to `$t9`: a load from
/// a fixed offset off a register other than the stack's is a GOT load
/// (whichever register holds `_gp`); anything else that may write `$t9`
/// forgets it.
fn track(state: &mut State, word: u32, got: &Got, (big, wide): (bool, bool)) {
    let gp = got.gp;
    let opcode = word >> 26;
    let (rs, rt, rd) = (
        (word >> 21) & 0x1f,
        (word >> 16) & 0x1f,
        (word >> 11) & 0x1f,
    );
    // LW, LD
    if matches!(opcode, 0x23 | 0x37) && rt == T9 {
        let offset = (i64::from(word & 0xffff) ^ 0x8000) - 0x8000;
        state.t9 = gp
            .filter(|_| !matches!(rs, ZERO | SP | FP))
            .map(|gp| gp.wrapping_add_signed(offset))
            .map(|slot| if wide { slot } else { slot & 0xffff_ffff });
        state.target = None;
        return;
    }
    // ADDIU, DADDIU $t9, $t9: a local GOT entry's page plus the offset.
    if matches!(opcode, 0x09 | 0x19) && rs == T9 && rt == T9 {
        let offset = (i64::from(word & 0xffff) ^ 0x8000) - 0x8000;
        let size = if wide { 8 } else { 4 };
        state.target = state
            .t9
            .and_then(|slot| got.read(slot, size, big))
            .filter(|&page| page != 0)
            .map(|page| page.wrapping_add_signed(offset))
            .map(|to| if wide { to } else { to & 0xffff_ffff });
        state.t9 = None;
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
        state.t9 = None;
        state.target = None;
    }
}

/// The `$gp` setup at the start of `bytes`: `lui $gp, %hi(d)` then, in some
/// order within three instructions, `(d)addu $gp, $gp, $t9` and `(d)addiu
/// $gp, $gp, %lo(d)`, or Release 6's `aui $gp, $t9, %hi(d)` and the `addiu`.
/// It computes `$gp` from `$t9`, the function's own address: `d = _gp -
/// entry`. Returns `d`, and whether it is o32's `.cpload` (`lui; addiu;
/// addu`, in that order), which is a function's first instruction.
fn gp_setup(big: bool, bytes: &[u8]) -> Option<(i64, bool)> {
    let word = |i: usize| bytes.get(i * 4..).and_then(|rest| read_word(big, rest));
    let first = word(0)?;
    let aui = first >> 16 == 0x3f3c;
    if first >> 16 != 0x3c1c && !aui {
        return None;
    }
    let addiu = |w: u32| w >> 16 == 0x279c || w >> 16 == 0x679c;
    let add_t9 = |w: u32| w == 0x0399_e021 || w == 0x0399_e02d;
    let rest: Vec<u32> = (1..4).filter_map(word).collect();
    let low = rest.iter().copied().find(|&w| addiu(w))?;
    if !aui && !rest.iter().copied().any(add_t9) {
        return None;
    }
    let cpload = !aui
        && matches!(rest.as_slice(), [second, third, ..] if addiu(*second) && *third == 0x0399_e021);
    let hi = i64::from(((first & 0xffff) << 16).cast_signed());
    let lo = i64::from((low & 0xffff) as u16 as i16);
    Some((hi + lo, cpload))
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
        .find(|&entry| entry <= addr && addr - entry <= 32 && entry.is_multiple_of(4))
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

fn read_word(big: bool, bytes: &[u8]) -> Option<u32> {
    let bytes: [u8; 4] = bytes.get(..4)?.try_into().ok()?;
    Some(if big {
        u32::from_be_bytes(bytes)
    } else {
        u32::from_le_bytes(bytes)
    })
}

/// Where control goes after the transfer at `addr` and its slot; `None`
/// for an instruction that is no transfer. Release 6's compact transfers
/// come with `true`: they have no slot.
fn flow(word: u32, addr: u64, wide: bool, r6: bool) -> Option<(Flow, bool)> {
    let opcode = word >> 26;
    let rs = (word >> 21) & 0x1f;
    let rt = (word >> 16) & 0x1f;
    let slot = addr.wrapping_add(4);
    let wrap = |target: u64| if wide { target } else { target & 0xffff_ffff };
    // A word offset of `bits` bits from the slot (compact branches count
    // from the next instruction, the same address).
    let relative = |bits: u32| {
        let sign = 1_i64 << (bits - 1);
        let field = i64::from(word) & ((1 << bits) - 1);
        wrap(slot.wrapping_add_signed(((field ^ sign) - sign) << 2))
    };
    let branch = relative(16);
    if r6 {
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
            0x32 => Flow::Jump(relative(26)),
            0x3a => Flow::Call(relative(26)),
            // BEQZC, BNEZC
            0x36 | 0x3e if rs != 0 => Flow::Branch(relative(21)),
            // JIC (`jrc` at offset 0), JIALC (`jalrc`): to a register plus
            // an offset.
            0x36 if word & 0xffff == 0 && rt == RA => Flow::Return,
            0x36 if word & 0xffff == 0 => Flow::JumpRegister(rt),
            0x36 => Flow::JumpIndirect,
            0x3e => Flow::CallIndirect,
            // BEQL, BNEL are gone.
            0x14 | 0x15 => Flow::Invalid,
            // BC1EQZ, BC1NEZ, BC2EQZ, BC2NEZ: with slots.
            0x11 | 0x12 if rs == 0x09 || rs == 0x0d => return Some((Flow::Branch(branch), false)),
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
                let target = wrap((slot & !0x0fff_ffff) | u64::from(word & 0x03ff_ffff) << 2);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pic_entries() {
        let be = |words: &[u32]| -> Vec<u8> { words.iter().flat_map(|w| w.to_be_bytes()).collect() };
        let le = |words: &[u32]| -> Vec<u8> { words.iter().flat_map(|w| w.to_le_bytes()).collect() };
        // o32 at 0xac124: lui gp, 0x8e; addiu gp, gp, -0x1da4; addu gp, gp, t9,
        // with _gp = 0xac124 + 0x8e0000 - 0x1da4.
        let o32 = [0x3c1c_008e, 0x279c_e25c, 0x0399_e021];
        let gp = 0xac124 + 0x8e_0000 - 0x1da4;
        assert_eq!(gp_entry(true, false, Some(gp).into_iter(), &be(&o32), 0xac124), Some(0xac124));
        assert_eq!(gp_entry(false, false, Some(gp).into_iter(), &le(&o32), 0xac124), Some(0xac124));
        // A `.cpload` is its function's entry whatever `_gp` is: a multi-GOT
        // executable has several.
        assert_eq!(gp_entry(true, false, Some(gp).into_iter(), &be(&o32), 0xac200), Some(0xac200));
        // Without _gp, o32's order at the start.
        assert_eq!(gp_entry(true, false, None.into_iter(), &be(&o32), 0x1000), Some(0x1000));
        assert_eq!(gp_entry(false, false, None.into_iter(), &be(&o32), 0x1000), None);
        // n64, 8 bytes after the entry 0x17ee8: lui gp, 2; daddu gp, gp, t9;
        // daddiu gp, gp, 0x7f18 (d = _gp - entry = 0x2_7f18 - 0x1_0000).
        let n64 = [0x3c1c_0002, 0x0399_e02d, 0x679c_7f18];
        let gp = 0x17ee8 + 0x2_7f18;
        assert_eq!(gp_entry(true, true, Some(gp).into_iter(), &be(&n64), 0x17ef0), Some(0x17ee8));
        // ... but not when no _gp names the entry.
        assert_eq!(gp_entry(true, true, None.into_iter(), &be(&n64), 0x17ef0), None);
        // A lui of another register is none.
        assert_eq!(gp_entry(true, false, None.into_iter(), &be(&[0x3c04_008e, 0x279c_e25c, 0x0399_e021]), 0), None);
    }

    fn one(words: &[u32], addr: u64) -> Insn {
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_be_bytes()).collect();
        decode(
            &mut State::default(),
            &Got::default(),
            (true, false, false),
            &bytes,
            addr,
        )
    }

    /// Each instruction of `words` at `addr` on, as Release 6 code.
    fn r6(words: &[u32], addr: u64) -> Vec<(Flow, u32)> {
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_be_bytes()).collect();
        let mut state = State::default();
        let mut out = Vec::new();
        let mut at = 0;
        while at < bytes.len() {
            let insn = decode(
                &mut state,
                &Got::default(),
                (true, false, true),
                &bytes[at..],
                addr + at as u64,
            );
            out.push((insn.flow, insn.len));
            at += insn.len as usize;
        }
        out
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
            let mut state = State::default();
            let got = Got::default();
            decode(&mut state, &got, (true, false, true), &bytes, 0x1000);
            let insn = decode(&mut state, &got, (true, false, true), &bytes[4..], 0x1004);
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
        let mut state = State::default();
        let mut out = Vec::new();
        let mut at = 0;
        while at < bytes.len() {
            let insn = decode(
                &mut state,
                got,
                (true, false, false),
                &bytes[at..],
                addr + at as u64,
            );
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
    fn reserved_encodings_are_no_code() {
        // A word of the data frida keeps in `.text`: COP1 format 0x0a.
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
        // A jump with no slot.
        assert_eq!(one(&[0x0800_0000], 0x1000).flow, Flow::Invalid);
    }

    #[test]
    fn little_endian_and_64_bit() {
        let bytes: Vec<u8> = [0x0c10_0040_u32, 0]
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect();
        let call = decode(
            &mut State::default(),
            &Got::default(),
            (false, true, false),
            &bytes,
            0x1_2000_0000,
        );
        assert_eq!(call.flow, Flow::Call(0x1_2040_0100));
    }
}
