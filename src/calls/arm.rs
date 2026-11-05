//! 32-bit Arm value tracking, A32 and Thumb. Instruction length and control
//! flow come from binform's Arm decoder; this layer adds what registers and
//! frame bytes an instruction leaves. It models the instructions a call or
//! syscall sequence builds its arguments with: moves, `movw`/`movt`, `add`
//! and `sub` of an immediate, `adr`, literal loads, `rev16`, and loads and
//! stores of one or several registers. Any other instruction clears the
//! registers it writes, or, where the encoding does not say which, every
//! register but the stack pointer.
//!
//! An instruction that may not run (an A32 condition, a Thumb `it` block)
//! leaves only what holds whether it runs or not.
//!
//! The Linux Arm syscall ABI takes the number in `r7` and arguments in
//! `r0..r6`; a call takes arguments in `r0..r3`.

use super::state::{State, Val, rev16, word};
use super::{Step, Tracker, flow};
use crate::Binary;
use crate::isa::Decoder;

const SP: u32 = 13;
const PC: u32 = 15;
/// What a call may change: `r0..r3`, `r12` and the link register.
const CLOBBERED: &[u32] = &[0, 1, 2, 3, 12, 14];

pub(crate) struct Arm<'a> {
    decoder: Decoder<'a>,
    code: &'a [u8],
    /// Instructions left in the current Thumb `it` block.
    it: u32,
}

impl<'a> Arm<'a> {
    pub(crate) fn new(bin: &'a Binary<'_>) -> Self {
        Self {
            decoder: Decoder::new(bin, crate::Arch::Arm),
            code: &[],
            it: 0,
        }
    }
}

impl<'a> Tracker<'a> for Arm<'a> {
    fn sp(&self) -> u32 {
        SP
    }

    fn pointer(&self) -> u8 {
        4
    }

    fn begin(&mut self, code: &'a [u8], _start: u64) {
        self.code = code;
    }

    fn reset(&mut self) {
        self.decoder.reset();
        self.it = 0;
    }

    fn step(&mut self, state: &mut State<'_>, at: usize, addr: u64) -> Step {
        let Some(bytes) = self.code.get(at..) else {
            return Step::stop(1);
        };
        let insn = self.decoder.decode(bytes, addr);
        let thumb = addr & 1 != 0;
        let conditional = if thumb {
            let inside = self.it > 0;
            let left = self.it.saturating_sub(1);
            // An `it` makes up to four instructions after it conditional,
            // as many as its mask has bits above the lowest set one.
            self.it = half(bytes)
                .filter(|h| h & 0xff00 == 0xbf00 && h & 0xf != 0)
                .map_or(left, |h| 4_u32.saturating_sub((h & 0xf).trailing_zeros()));
            inside
        } else {
            word(bytes).is_some_and(|w| w >> 28 < 0b1110)
        };

        // `svc #0`, the Linux EABI syscall: the comment is zero, and the
        // number is in `r7`. Any other comment is no Linux EABI syscall. A32
        // `svc` is `cond 1111 imm24` with a real condition (`1111` is no
        // condition); Thumb `svc` is `1101 1111 imm8`.
        let svc = if thumb {
            half(bytes) == Some(0xdf00)
        } else {
            word(bytes).is_some_and(|w| w & 0x0fff_ffff == 0x0f00_0000 && w >> 28 != 0b1111)
        };
        if svc {
            let step = Step::syscall(insn.len, state.get(7), (0..=6).map(|r| state.value(r)));
            // The kernel returns in r0; r1..r7 survive.
            state.clear(0);
            return step;
        }
        if let Some(step) = flow(state, &insn, 0..=3, CLOBBERED) {
            return step;
        }

        // The PC an instruction reads: its address plus 4 in Thumb, 8 in A32.
        let pc = (addr & !1).wrapping_add(if thumb { 4 } else { 8 });
        let track = |state: &mut State<'_>| match (thumb, insn.len) {
            (false, _) => {
                if let Some(w) = word(bytes) {
                    a32(state, w, pc);
                }
            }
            (true, 4) => {
                if let (Some(first), Some(second)) = (half(bytes), bytes.get(2..).and_then(half)) {
                    t32(state, first, second, pc);
                }
            }
            (true, _) => {
                if let Some(h) = half(bytes) {
                    t16(state, h, pc);
                }
            }
        };
        if conditional {
            state.maybe(track);
        } else {
            track(state);
        }
        Step::go(insn.len)
    }
}

/// A little-endian 16-bit halfword, widened.
fn half(bytes: &[u8]) -> Option<u32> {
    bytes
        .first_chunk::<2>()
        .map(|&b| u32::from(u16::from_le_bytes(b)))
}

/// What register `r` reads: the PC reads as `pc`.
fn reg(state: &State<'_>, r: u32, pc: u64) -> Val {
    if r == PC { Val::Int(pc) } else { state.get(r) }
}

/// `rd = rn + delta`, with the PC read word-aligned, as `adr` and literal
/// loads read it.
fn add(state: &mut State<'_>, rd: u32, rn: u32, delta: i64, pc: u64) {
    state.set(rd, reg(state, rn, pc & !3).plus(delta).low32());
}

/// How a load or store addresses memory and writes its base back.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Index {
    /// At base plus offset; the base is unchanged.
    Offset,
    /// At base plus offset, which the base becomes.
    Pre,
    /// At the base, which then moves by the offset.
    Post,
}

impl Index {
    /// The A32 and T32 `P` and `W` bits' meaning. An unprivileged access
    /// (`P` clear, `W` set) indexes as a post-indexed one.
    const fn of(p: bool, w: bool) -> Self {
        match (p, w) {
            (true, false) => Self::Offset,
            (true, true) => Self::Pre,
            (false, _) => Self::Post,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Store,
    Load,
    /// A sign-extending load, whose value the walk does not follow.
    Signed,
}

/// Where a load or store goes: base register `rn` plus `offset`, which is
/// `None` when a register the walk does not know chooses it.
#[derive(Clone, Copy)]
struct At {
    rn: u32,
    offset: Option<i64>,
    index: Index,
}

/// A load or store of `regs` (one register, or a dual's two), `width` bytes
/// each.
fn access(state: &mut State<'_>, at: At, regs: &[u32], width: u8, kind: Kind, pc: u64) {
    let At { rn, offset, index } = at;
    let base = reg(state, rn, pc & !3);
    let Some(offset) = offset else {
        if kind == Kind::Store && matches!(base, Val::Stack(_)) {
            state.forget_frame();
        }
        if index != Index::Offset {
            state.clear(rn);
        }
        if kind != Kind::Store {
            for &r in regs {
                state.clear(r);
            }
        }
        return;
    };
    let addr = if index == Index::Post {
        base
    } else {
        base.plus(offset)
    };
    let mut loaded = [Val::Unknown; 2];
    for ((&r, value), delta) in regs
        .iter()
        .zip(&mut loaded)
        .zip((0_i64..).step_by(width.into()))
    {
        match (kind, addr.plus(delta)) {
            (Kind::Store, Val::Stack(off)) => state.store(off, reg(state, r, pc), width),
            (Kind::Load, Val::Stack(off)) => *value = state.load(off, width),
            // A literal: constant data next to the code.
            (Kind::Load, Val::Int(lit)) if rn == PC => *value = state.read(lit, width),
            _ => {}
        }
    }
    if index != Index::Offset {
        state.set(rn, base.plus(offset));
    }
    if kind != Kind::Store {
        for (&r, &value) in regs.iter().zip(&loaded) {
            state.set(r, value);
        }
    }
}

/// A load or store of the registers in `list` (bit n for `rn`), in words
/// ascending from the lowest address: `ldm`/`stm` and so `push`/`pop`.
/// `before` and `up` are the `P` and `U` bits.
fn multiple(
    state: &mut State<'_>,
    rn: u32,
    list: u32,
    load: bool,
    before: bool,
    up: bool,
    writeback: bool,
) {
    let base = state.get(rn);
    let bytes = i64::from(list.count_ones()).wrapping_mul(4);
    let low = match (up, before) {
        (true, false) => base,
        (true, true) => base.plus(4),
        (false, false) => base.plus(4_i64.wrapping_sub(bytes)),
        (false, true) => base.plus(bytes.wrapping_neg()),
    };
    let regs = (0..16).filter(|r| list >> r & 1 != 0);
    let mut loaded = [Val::Unknown; 16];
    for (r, at) in regs.clone().zip((0..).step_by(4)) {
        match (load, low.plus(at)) {
            (false, Val::Stack(off)) => state.store(off, state.get(r), 4),
            (true, Val::Stack(off)) => {
                if let Some(value) = loaded.get_mut(r as usize) {
                    *value = state.load(off, 4);
                }
            }
            _ => {}
        }
    }
    if writeback {
        state.set(rn, base.plus(if up { bytes } else { bytes.wrapping_neg() }));
    }
    if load {
        for r in regs {
            state.set(r, loaded.get(r as usize).copied().unwrap_or(Val::Unknown));
        }
    }
}

/// A coprocessor load or store (`vldr`, `vstr`, `vpush`, `vpop`), as A32
/// encodes it: `cond 110 P U D W L Rn Vd coproc imm8`. Only core registers
/// are tracked, so a load changes only a written-back base; a store forgets
/// the frame bytes it covers.
fn coprocessor(state: &mut State<'_>, w: u32) {
    let rn = w >> 16 & 0xf;
    let (p, u, writeback, load) = (
        w & 1 << 24 != 0,
        w & 1 << 23 != 0,
        w & 1 << 21 != 0,
        w & 1 << 20 != 0,
    );
    if !p && !writeback {
        // `mrrc` (or an unindexed transfer) may write core registers.
        state.clear_all();
        return;
    }
    let words = i64::from(w & 0xff).wrapping_mul(4);
    let delta = if u { words } else { words.wrapping_neg() };
    let base = state.get(rn);
    if !load {
        // `vstr` stores one register at base plus offset; `vstm` its list
        // up from the base, or down from it with `vpush`.
        let (start, bytes) = match (p, writeback) {
            (true, false) => (base.plus(delta), if w & 0x100 != 0 { 8 } else { 4 }),
            (true, true) => (base.plus(delta), words),
            (false, _) => (base, words),
        };
        if let Val::Stack(off) = start {
            state.forget(off, u16::try_from(bytes).unwrap_or(u16::MAX));
        }
    }
    if writeback {
        state.set(rn, base.plus(delta));
    }
}

/// `ror(imm8, 2 * rotate)`: an A32 data-processing immediate.
fn a32_imm(w: u32) -> i64 {
    i64::from((w & 0xff).rotate_right(w >> 7 & 0x1e))
}

fn a32(state: &mut State<'_>, w: u32, pc: u64) {
    let rn = w >> 16 & 0xf;
    let rd = w >> 12 & 0xf;
    let rm = w & 0xf;
    let bit = |n: u32| w & 1 << n != 0;

    // The unconditional space: hints, barriers, `pld`, and Advanced SIMD,
    // which writes no core register but may store into the frame.
    if w >> 28 == 0b1111 {
        if w & 0xff10_0000 == 0xf400_0000 {
            simd_access(state, rn, rm, !bit(21));
        }
        return;
    }
    // REV16: `cond 0110 1011 1111 Rd 1111 1011 Rm`.
    if w & 0x0fff_0ff0 == 0x06bf_0fb0 {
        state.set(rd, rev16_32(state.get(rm)));
        return;
    }
    let media = w & 0x0e00_0010 == 0x0600_0010;
    // Load/store word or byte: `cond 01 I P U B W L Rn Rt offset`.
    if w & 0x0c00_0000 == 0x0400_0000 && !media {
        let offset = if bit(25) {
            // A register offset, unshifted.
            match state.get(rm) {
                Val::Int(n) if w & 0xff0 == 0 => Some((n & 0xffff_ffff).cast_signed()),
                _ => None,
            }
        } else {
            Some(i64::from(w & 0xfff))
        };
        let offset = offset.map(|n| if bit(23) { n } else { n.wrapping_neg() });
        let kind = if bit(20) { Kind::Load } else { Kind::Store };
        let at = At {
            rn,
            offset,
            index: Index::of(bit(24), bit(21)),
        };
        access(state, at, &[rd], if bit(22) { 1 } else { 4 }, kind, pc);
        return;
    }
    // Extra load/store: `cond 000 P U I W L Rn Rt imm4 1 S H 1 imm4`.
    if w & 0x0e00_0090 == 0x0000_0090 && w & 0x60 != 0 {
        let offset = if bit(22) {
            Some(i64::from((w >> 4 & 0xf0) | (w & 0xf)))
        } else {
            match state.get(rm) {
                Val::Int(n) => Some((n & 0xffff_ffff).cast_signed()),
                _ => None,
            }
        };
        let offset = offset.map(|n| if bit(23) { n } else { n.wrapping_neg() });
        let index = Index::of(bit(24), bit(21));
        let pair = [rd, rd.wrapping_add(1)];
        let (regs, width, kind): (&[u32], u8, Kind) = match (bit(20), w >> 5 & 3) {
            (false, 1) => (&pair[..1], 2, Kind::Store), // strh
            (true, 1) => (&pair[..1], 2, Kind::Load),   // ldrh
            (true, 2) => (&pair[..1], 1, Kind::Signed), // ldrsb
            (true, _) => (&pair[..1], 2, Kind::Signed), // ldrsh
            (false, 2) => (&pair, 4, Kind::Load),       // ldrd
            (false, _) => (&pair, 4, Kind::Store),      // strd
        };
        access(state, At { rn, offset, index }, regs, width, kind, pc);
        return;
    }
    // Load/store multiple: `cond 100 P U S W L Rn list`.
    if w & 0x0e00_0000 == 0x0800_0000 {
        multiple(state, rn, w & 0xffff, bit(20), bit(24), bit(23), bit(21));
        return;
    }
    // Coprocessor load/store: `cond 110 ...`.
    if w & 0x0e00_0000 == 0x0c00_0000 {
        coprocessor(state, w);
        return;
    }
    // Coprocessor register transfer: `mrc` and `vmov` to a core register
    // (`L` and bit 4 set) write Rt.
    if w & 0x0f00_0000 == 0x0e00_0000 {
        if bit(20) && bit(4) {
            state.clear(rd);
        }
        return;
    }
    // An `svc` of another ABI: the kernel returns in r0.
    if w & 0x0f00_0000 == 0x0f00_0000 {
        state.clear(0);
        return;
    }
    // MOVW / MOVT: `cond 0011 0x00 imm4 Rd imm12`.
    if w & 0x0fb0_0000 == 0x0300_0000 {
        let imm16 = u64::from((w >> 4 & 0xf000) | (w & 0xfff));
        let value = if bit(22) {
            // MOVT sets the high half, keeping the low half of a known value.
            match state.get(rd) {
                Val::Int(low) => Val::Int((low & 0xffff) | imm16 << 16),
                _ => Val::Unknown,
            }
        } else {
            Val::Int(imm16)
        };
        state.set(rd, value);
        return;
    }
    // Data processing: register form `cond 000 op S Rn Rd shift Rm`,
    // immediate form `cond 001 op S Rn Rd rot imm8`.
    let imm = w & 0x0e00_0000 == 0x0200_0000;
    if imm || w & 0x0e00_0010 == 0 {
        match (w >> 21 & 0xf, imm) {
            // TST, TEQ, CMP, CMN set flags only; without `S`, the space
            // holds other instructions, which may write anything.
            (0b1000..=0b1011, _) if bit(20) => {}
            (0b1000..=0b1011, _) => state.clear_all(),
            (0b1101, true) => state.set(rd, Val::Int(a32_imm(w).cast_unsigned())),
            (0b1111, true) => state.set(rd, Val::Int(!a32_imm(w).cast_unsigned() & 0xffff_ffff)),
            (0b1101, false) if w & 0xff0 == 0 => state.set(rd, reg(state, rm, pc)),
            (0b0100, true) => add(state, rd, rn, a32_imm(w), pc),
            (0b0010, true) => add(state, rd, rn, a32_imm(w).wrapping_neg(), pc),
            _ => state.clear(rd),
        }
        return;
    }
    // Multiplies, media and the rest write registers the walk does not
    // decode.
    state.clear_all();
}

/// An Advanced SIMD element or structure load or store with base `rn`,
/// which writes no core register: a store forgets the frame it may cover,
/// and the base moves unless `rm` is 15.
fn simd_access(state: &mut State<'_>, rn: u32, rm: u32, store: bool) {
    if store && matches!(state.get(rn), Val::Stack(_)) {
        state.forget_frame();
    }
    if rm != PC {
        state.clear(rn);
    }
}

/// `rev16` of a 32-bit register.
fn rev16_32(v: Val) -> Val {
    match v {
        Val::Int(n) => Val::Int(rev16(n) & 0xffff_ffff),
        _ => Val::Unknown,
    }
}

/// A 16-bit Thumb instruction.
fn t16(state: &mut State<'_>, h: u32, pc: u64) {
    let low = h & 7;
    let mid = h >> 3 & 7;
    let high = h >> 8 & 7;
    let imm8 = i64::from(h & 0xff);
    let imm5 = i64::from(h >> 6 & 0x1f);
    let load = h & 0x800 != 0;
    let kind = if load { Kind::Load } else { Kind::Store };
    match h >> 11 {
        // LSL, LSR, ASR immediate.
        0b00000..=0b00010 => state.clear(low),
        // ADD, SUB: register, or a 3-bit immediate.
        0b00011 => {
            if h & 0x400 != 0 {
                let imm3 = i64::from(h >> 6 & 7);
                let delta = if h & 0x200 != 0 {
                    imm3.wrapping_neg()
                } else {
                    imm3
                };
                state.set(low, state.get(mid).plus(delta).low32());
            } else {
                state.clear(low);
            }
        }
        0b00100 => state.set(high, Val::Int(imm8.cast_unsigned())), // MOVS
        0b00101 => {}                                               // CMP
        0b00110 => state.set(high, state.get(high).plus(imm8).low32()), // ADDS
        0b00111 => state.set(high, state.get(high).plus(imm8.wrapping_neg()).low32()), // SUBS
        0b01000 if h & 0x400 == 0 => {
            // Data processing, register: TST, CMP and CMN write nothing.
            if !matches!(h >> 6 & 0xf, 0b1000 | 0b1010 | 0b1011) {
                state.clear(low);
            }
        }
        0b01000 => {
            // ADD, CMP, MOV with high registers; BX and BLX are flow.
            let rd = (h >> 4 & 8) | low;
            match h >> 8 & 3 {
                0 => state.clear(rd),
                2 => state.set(rd, reg(state, h >> 3 & 0xf, pc)),
                _ => {}
            }
        }
        // LDR literal.
        0b01001 => access(
            state,
            At {
                rn: PC,
                offset: Some(imm8.wrapping_mul(4)),
                index: Index::Offset,
            },
            &[high],
            4,
            Kind::Load,
            pc,
        ),
        // Load/store with a register offset.
        0b01010 | 0b01011 => {
            let offset = match state.get(h >> 6 & 7) {
                Val::Int(n) => Some(n.cast_signed()),
                _ => None,
            };
            let (width, kind) = match h >> 9 & 7 {
                0 => (4, Kind::Store),
                1 => (2, Kind::Store),
                2 => (1, Kind::Store),
                3 => (1, Kind::Signed),
                4 => (4, Kind::Load),
                5 => (2, Kind::Load),
                6 => (1, Kind::Load),
                _ => (2, Kind::Signed),
            };
            access(
                state,
                At {
                    rn: mid,
                    offset,
                    index: Index::Offset,
                },
                &[low],
                width,
                kind,
                pc,
            );
        }
        // LDR/STR word, then byte, with a 5-bit immediate.
        0b01100 | 0b01101 => access(
            state,
            At {
                rn: mid,
                offset: Some(imm5.wrapping_mul(4)),
                index: Index::Offset,
            },
            &[low],
            4,
            kind,
            pc,
        ),
        0b01110 | 0b01111 => access(
            state,
            At {
                rn: mid,
                offset: Some(imm5),
                index: Index::Offset,
            },
            &[low],
            1,
            kind,
            pc,
        ),
        // LDRH/STRH immediate.
        0b10000 | 0b10001 => access(
            state,
            At {
                rn: mid,
                offset: Some(imm5.wrapping_mul(2)),
                index: Index::Offset,
            },
            &[low],
            2,
            kind,
            pc,
        ),
        // LDR/STR, SP-relative.
        0b10010 | 0b10011 => access(
            state,
            At {
                rn: SP,
                offset: Some(imm8.wrapping_mul(4)),
                index: Index::Offset,
            },
            &[high],
            4,
            kind,
            pc,
        ),
        // ADR.
        0b10100 => add(state, high, PC, imm8.wrapping_mul(4), pc),
        // ADD Rd, SP, #imm.
        0b10101 => add(state, high, SP, imm8.wrapping_mul(4), pc),
        0b10110 | 0b10111 => t16_misc(state, h),
        // STMIA / LDMIA, which writes back unless it loads its base.
        0b11000 | 0b11001 => {
            let list = h & 0xff;
            multiple(
                state,
                high,
                list,
                load,
                false,
                true,
                !load || list >> high & 1 == 0,
            );
        }
        // An `svc` of another ABI: the kernel returns in r0.
        0b11011 if h & 0xff00 == 0xdf00 => state.clear(0),
        // Branches and `udf` are flow.
        _ => {}
    }
}

/// The 16-bit miscellaneous space, `1011 ....`.
fn t16_misc(state: &mut State<'_>, h: u32) {
    let low = h & 7;
    if h & 0xff00 == 0xb000 {
        // ADD/SUB SP, SP, #imm7 * 4.
        let imm = i64::from(h & 0x7f).wrapping_mul(4);
        let delta = if h & 0x80 != 0 {
            imm.wrapping_neg()
        } else {
            imm
        };
        state.set(SP, state.get(SP).plus(delta));
    } else if h & 0xfe00 == 0xb400 {
        // PUSH {list, lr}.
        multiple(
            state,
            SP,
            (h & 0xff) | (h & 0x100) << 6,
            false,
            true,
            false,
            true,
        );
    } else if h & 0xfe00 == 0xbc00 {
        // POP {list}; with the PC it is a return.
        multiple(state, SP, h & 0xff, true, false, true, true);
    } else if h & 0xffc0 == 0xba40 {
        state.set(low, rev16_32(state.get(h >> 3 & 7)));
    } else if h & 0xff00 == 0xb200 || h & 0xff00 == 0xba00 {
        // Extends, and the other byte reversals.
        state.clear(low);
    }
    // `cbz`/`cbnz` are flow; `it`, hints, `cps`, `bkpt` write no register.
}

/// Thumb's modified immediate: `i:imm3:imm8` expanded to 32 bits.
fn t32_imm(imm12: u32) -> u32 {
    let imm8 = imm12 & 0xff;
    if imm12 >> 10 != 0 {
        return (0x80 | imm8 & 0x7f).rotate_right(imm12 >> 7);
    }
    match imm12 >> 8 & 3 {
        0 => imm8,
        1 => imm8 << 16 | imm8,
        2 => imm8 << 24 | imm8 << 8,
        _ => imm8 << 24 | imm8 << 16 | imm8 << 8 | imm8,
    }
}

/// A 32-bit Thumb instruction, its halfwords `first` and `second`.
fn t32(state: &mut State<'_>, first: u32, second: u32, pc: u64) {
    let rn = first & 0xf;
    let rd = second >> 8 & 0xf;
    let rt = second >> 12 & 0xf;
    let bit = |n: u32| first & 1 << n != 0;
    let imm12 = (first >> 10 & 1) << 11 | (second >> 12 & 7) << 8 | (second & 0xff);

    // Data processing, plain binary immediate: `11110 i 1 op Rn | 0 imm3 Rd imm8`.
    if first & 0xfa00 == 0xf200 && second & 0x8000 == 0 {
        match first & 0xfbf0 {
            0xf240 => state.set(rd, Val::Int(u64::from((first & 0xf) << 12 | imm12))), // MOVW
            0xf2c0 => {
                // MOVT sets the high half, keeping the low half of a known value.
                let value = match state.get(rd) {
                    Val::Int(low) => {
                        Val::Int((low & 0xffff) | u64::from((first & 0xf) << 12 | imm12) << 16)
                    }
                    _ => Val::Unknown,
                };
                state.set(rd, value);
            }
            0xf200 => add(state, rd, rn, imm12.into(), pc), // ADDW, and ADR
            0xf2a0 => add(state, rd, rn, i64::from(imm12).wrapping_neg(), pc), // SUBW, and ADR
            _ => state.clear(rd),
        }
        return;
    }
    // Data processing, modified immediate: `11110 i 0 op S Rn | 0 imm3 Rd imm8`.
    if first & 0xfa00 == 0xf000 && second & 0x8000 == 0 {
        let imm = t32_imm(imm12);
        match first >> 5 & 0xf {
            // With Rd the PC these are TST, TEQ, CMN, CMP: flags only.
            _ if rd == PC => {}
            0b1000 => add(state, rd, rn, imm.into(), pc),
            0b1101 => add(state, rd, rn, i64::from(imm).wrapping_neg(), pc),
            0b0010 if rn == PC => state.set(rd, Val::Int(imm.into())), // MOV
            0b0011 if rn == PC => state.set(rd, Val::Int((!imm).into())), // MVN
            _ => state.clear(rd),
        }
        return;
    }
    // Advanced SIMD element or structure load/store: `1111 1001 xxx0`.
    if first & 0xff10 == 0xf900 {
        simd_access(state, rn, second & 0xf, !bit(5));
        return;
    }
    // Load/store single: `1111 100 S size L Rn | Rt ...`.
    if first & 0xfe00 == 0xf800 {
        let width = 1_u8 << (first >> 5 & 3);
        let kind = match (bit(4), bit(8)) {
            (false, _) => Kind::Store,
            (true, false) => Kind::Load,
            (true, true) => Kind::Signed,
        };
        let (offset, index) = if rn == PC || bit(7) {
            // A 12-bit offset: up from the base, or either way from the PC.
            let imm = i64::from(second & 0xfff);
            (
                Some(if rn == PC && !bit(7) {
                    imm.wrapping_neg()
                } else {
                    imm
                }),
                Index::Offset,
            )
        } else if second & 0x800 != 0 {
            // An 8-bit offset: `1 P U W imm8`.
            let imm = i64::from(second & 0xff);
            let imm = if second & 0x200 != 0 {
                imm
            } else {
                imm.wrapping_neg()
            };
            (
                Some(imm),
                Index::of(second & 0x400 != 0, second & 0x100 != 0),
            )
        } else if second & 0xfc0 == 0 {
            // A register offset, shifted left by 0 to 3.
            let offset = match state.get(second & 0xf) {
                Val::Int(n) => Some(n.cast_signed().wrapping_shl(second >> 4 & 3)),
                _ => None,
            };
            (offset, Index::Offset)
        } else {
            (None, Index::Offset)
        };
        access(state, At { rn, offset, index }, &[rt], width, kind, pc);
        return;
    }
    // Load/store multiple, increment after or decrement before:
    // `1110 100 op 0 W L Rn | list`.
    if first & 0xfe40 == 0xe800 && matches!(first >> 7 & 3, 1 | 2) {
        let before = first >> 7 & 3 == 2;
        multiple(state, rn, second, bit(4), before, !before, bit(5));
        return;
    }
    // Load/store dual: `1110 100 P U 1 W L Rn | Rt Rt2 imm8`, with P or W set.
    if first & 0xfe40 == 0xe840 && first & 0x0120 != 0 {
        let imm = i64::from(second & 0xff).wrapping_mul(4);
        let offset = if bit(7) { imm } else { imm.wrapping_neg() };
        let kind = if bit(4) { Kind::Load } else { Kind::Store };
        let at = At {
            rn,
            offset: Some(offset),
            index: Index::of(bit(8), bit(5)),
        };
        access(state, at, &[rt, rd], 4, kind, pc);
        return;
    }
    // Coprocessor load/store: A32's encoding, with condition 1110.
    if first & 0xee00 == 0xec00 {
        coprocessor(state, 0xe000_0000 | (first & 0x0fff) << 16 | second);
        return;
    }
    // Coprocessor register transfer, and Advanced SIMD data processing.
    if first & 0xef00 == 0xee00 {
        if bit(4) && second & 0x10 != 0 {
            state.clear(rt);
        }
        return;
    }
    if first & 0xef00 == 0xef00 {
        return;
    }
    // Data processing, register, and multiplies: Rd in `second`.
    if first & 0xfe00 == 0xea00 || first & 0xff00 == 0xfa00 || first & 0xff80 == 0xfb00 {
        // MOV.W Rd, Rm is ORR with Rn the PC and no shift.
        if first & 0xffef == 0xea4f && second & 0x70f0 == 0 {
            state.set(rd, reg(state, second & 0xf, pc));
        } else if rd != PC {
            state.clear(rd);
        }
        return;
    }
    // Long multiplies and divides: Rd, or RdLo and RdHi.
    if first & 0xff80 == 0xfb80 {
        state.clear(rt);
        state.clear(rd);
        return;
    }
    // Branches and miscellaneous control: only MRS writes a register.
    if first & 0xf800 == 0xf000 && second & 0x8000 != 0 {
        if first & 0xffe0 == 0xf3e0 {
            state.clear(rd);
        }
        return;
    }
    // Exclusives, table branches and the rest.
    state.clear_all();
}
