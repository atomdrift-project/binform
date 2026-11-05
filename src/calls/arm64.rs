//! AArch64 value tracking. Instructions are four bytes and control flow
//! comes from binform's arm64 decoder; this layer adds the constants and
//! frame bytes a call or syscall sequence leaves: `movz`/`movn`/`movk`,
//! `mov`, `add`/`sub` of an immediate, `adr`/`adrp`, `rev16`, literal loads,
//! and loads and stores of one register or a pair. Any other instruction
//! clears the register it writes.
//!
//! Register 31 is the stack pointer as a base and as the destination of
//! `add`/`sub` immediate, and the zero register elsewhere; the model numbers
//! the stack pointer 31.
//!
//! The Linux AArch64 syscall ABI takes the number in `x8` and arguments in
//! `x0..x5`; a call takes arguments in `x0..x7`.

use super::state::{State, Val, rev16, word};
use super::{Step, Tracker, flow};
use crate::Binary;
use crate::isa::{Decoder, sext};

const SP: u32 = 31;
/// What a call may change: `x0..x18` and the link register.
const CLOBBERED: &[u32] = &[
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 30,
];

pub(crate) struct Arm64<'a> {
    decoder: Decoder,
    code: &'a [u8],
}

impl Arm64<'_> {
    pub(crate) fn new(bin: &Binary<'_>) -> Self {
        Self {
            decoder: Decoder::new(bin, crate::Arch::Arm64),
            code: &[],
        }
    }
}

impl<'a> Tracker<'a> for Arm64<'a> {
    fn sp(&self) -> u32 {
        SP
    }

    fn pointer(&self) -> u8 {
        8
    }

    fn begin(&mut self, code: &'a [u8], _start: u64) {
        self.code = code;
    }

    fn reset(&mut self) {
        self.decoder.reset();
    }

    fn step(&mut self, state: &mut State<'_>, at: usize, addr: u64) -> Step {
        let Some(bytes) = self.code.get(at..) else {
            return Step::stop(1);
        };
        let insn = self.decoder.decode(bytes, addr);
        let Some(w) = word(bytes) else {
            return Step::stop(insn.len);
        };
        // `svc #0`, the Linux syscall: any other comment is no Linux
        // syscall. The number is in x8.
        if w == 0xd400_0001 {
            let step = Step::syscall(insn.len, state.get(8), (0..=5).map(|r| state.value(r)));
            state.clear(0); // the kernel returns in x0.
            return step;
        }
        if let Some(step) = flow(state, &insn, 0..=7, CLOBBERED) {
            return step;
        }
        track(state, w, addr);
        Step::go(insn.len)
    }
}

/// Read register `r` where 31 is the zero register.
fn zr(state: &State<'_>, r: u32) -> Val {
    if r == 31 { Val::Int(0) } else { state.get(r) }
}

/// Write register `r` where 31 is the zero register, which discards it.
fn set_zr(state: &mut State<'_>, r: u32, value: Val) {
    if r != 31 {
        state.set(r, value);
    }
}

/// A result as an operand of width `sf` leaves it: a 32-bit operation keeps
/// the low half of a constant, and cannot hold a stack pointer.
fn sized(value: Val, sf: bool) -> Val {
    match value {
        _ if sf => value,
        Val::Int(_) => value.low32(),
        _ => Val::Unknown,
    }
}

fn track(state: &mut State<'_>, w: u32, addr: u64) {
    let rd = w & 0x1f;
    let rn = w >> 5 & 0x1f;
    let sf = w & 0x8000_0000 != 0;

    // Move wide: `sf opc 100101 hw imm16 Rd`.
    if w & 0x1f80_0000 == 0x1280_0000 {
        let imm16 = u64::from(w >> 5 & 0xffff);
        let shift = w >> 17 & 0x30; // hw * 16
        let value = match w >> 29 & 3 {
            0b00 => Val::Int(!(imm16 << shift)), // MOVN
            0b10 => Val::Int(imm16 << shift),    // MOVZ
            0b11 => match zr(state, rd) {
                // MOVK
                Val::Int(v) => Val::Int((v & !(0xffff << shift)) | imm16 << shift),
                _ => Val::Unknown,
            },
            _ => Val::Unknown,
        };
        set_zr(state, rd, sized(value, sf));
        return;
    }
    // ADD/SUB immediate: `sf op S 100010 sh imm12 Rn Rd`. Rn is the stack
    // pointer; so is Rd, unless `S` sets flags (`cmp`, `cmn`).
    if w & 0x1f80_0000 == 0x1100_0000 {
        let imm12 = i64::from(w >> 10 & 0xfff);
        let imm = if w & 1 << 22 != 0 {
            imm12.wrapping_shl(12)
        } else {
            imm12
        };
        let delta = if w & 1 << 30 != 0 {
            imm.wrapping_neg()
        } else {
            imm
        };
        let value = sized(state.get(rn).plus(delta), sf);
        if w & 1 << 29 != 0 {
            set_zr(state, rd, value);
        } else {
            state.set(rd, value);
        }
        return;
    }
    // ADR / ADRP: `op immlo 10000 immhi Rd`, a 21-bit signed immediate.
    if w & 0x1f00_0000 == 0x1000_0000 {
        let imm = sext(w >> 5, 19).wrapping_shl(2) | i64::from(w >> 29 & 3);
        let value = if w & 0x8000_0000 != 0 {
            (addr & !0xfff).wrapping_add_signed(imm.wrapping_shl(12))
        } else {
            addr.wrapping_add_signed(imm)
        };
        set_zr(state, rd, Val::Int(value));
        return;
    }
    // ORR (shifted register) of the zero register, unshifted: `mov Rd, Rm`.
    if w & 0x7fe0_ffe0 == 0x2a00_03e0 {
        set_zr(state, rd, sized(zr(state, w >> 16 & 0x1f), sf));
        return;
    }
    // REV16: `sf 1 0 11010110 00000 000001 Rn Rd`.
    if w & 0x7fff_fc00 == 0x5ac0_0400 {
        let value = match zr(state, rn) {
            Val::Int(v) => sized(Val::Int(rev16(v)), sf),
            _ => Val::Unknown,
        };
        set_zr(state, rd, value);
        return;
    }
    // Loads and stores: `op0 1 op1 0 ...`.
    if w & 0x0a00_0000 == 0x0800_0000 {
        load_store(state, w, addr);
        return;
    }
    // Branches, exceptions and system instructions: of those that go on,
    // only MRS and SYSL write a register.
    if w & 0x1c00_0000 == 0x1400_0000 {
        if w & 0xffe0_0000 == 0xd520_0000 {
            set_zr(state, rd, Val::Unknown);
        }
        return;
    }
    // Data processing writes Rd: the zero register, except in the forms
    // whose Rd may be the stack pointer (logical immediate, and add/sub
    // extended register or with tags, without `S`).
    let sp_rd = (w & 0x1f80_0000 == 0x1200_0000 && w >> 29 & 3 != 3)
        || w & 0x3fe0_0000 == 0x0b20_0000
        || w & 0x3f80_0000 == 0x1180_0000;
    if sp_rd {
        state.clear(rd);
    } else {
        set_zr(state, rd, Val::Unknown);
    }
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

fn load_store(state: &mut State<'_>, w: u32, addr: u64) {
    let rt = w & 0x1f;
    let rt2 = w >> 10 & 0x1f;
    let rn = w >> 5 & 0x1f;
    let simd = w & 1 << 26 != 0;
    let size = w >> 30;
    let opc = w >> 22 & 3;

    // LDR (literal): `opc 011 V 00 imm19 Rt`, word or doubleword.
    if w & 0x3b00_0000 == 0x1800_0000 {
        if !simd && size < 2 {
            let at = addr.wrapping_add_signed(sext(w >> 5, 19).wrapping_mul(4));
            set_zr(state, rt, state.read(at, if size == 0 { 4 } else { 8 }));
        } else if !simd && size == 2 {
            set_zr(state, rt, Val::Unknown); // LDRSW
        }
        return;
    }
    // One register: `size 111 V 0 1 opc imm12 Rn Rt` with an unsigned
    // scaled offset, or `size 111 V 0 0 opc 0 imm9 idx Rn Rt` with a signed
    // one, unscaled or pre- or post-indexed.
    // 128-bit SIMD (Q) registers, else `1 << size` bytes.
    let width = if simd && opc & 2 != 0 {
        16
    } else {
        1_u8 << size
    };
    let single = if w & 0x3b00_0000 == 0x3900_0000 {
        Some((
            i64::from(w >> 10 & 0xfff).wrapping_mul(width.into()),
            Index::Offset,
            width,
        ))
    } else if w & 0x3b20_0000 == 0x3800_0000 {
        let index = match w >> 10 & 3 {
            1 => Index::Post,
            3 => Index::Pre,
            _ => Index::Offset,
        };
        Some((sext(w >> 12, 9), index, width))
    } else {
        None
    };
    if let Some((offset, index, width)) = single {
        let base = state.get(rn);
        let at = if index == Index::Post {
            base
        } else {
            base.plus(offset)
        };
        // opc: 00 store, 01 load, 1x a sign-extending load (or with
        // size 11, a prefetch); for SIMD registers, bit 0 is load.
        let (store, load) = if simd {
            (opc & 1 == 0, false)
        } else {
            (opc == 0, opc == 1)
        };
        let loaded = match at {
            Val::Stack(off) if load => state.load(off, width),
            _ => Val::Unknown,
        };
        if let (true, Val::Stack(off)) = (store, at) {
            if simd {
                state.forget(off, width.into());
            } else {
                state.store(off, zr(state, rt), width);
            }
        }
        if index != Index::Offset {
            state.set(rn, base.plus(offset));
        }
        if !simd && !store && !(size == 3 && opc == 2) {
            set_zr(state, rt, loaded);
        }
        return;
    }
    // A pair: `opc 101 V 0 idx L imm7 Rt2 Rn Rt`.
    if w & 0x3a00_0000 == 0x2800_0000 {
        let load = w & 1 << 22 != 0;
        let width: u8 = match (simd, size) {
            (false, 0 | 1) => 4,
            (false, _) => 8,
            (true, _) => 4 << size.min(2),
        };
        let index = match w >> 23 & 3 {
            1 => Index::Post,
            3 => Index::Pre,
            _ => Index::Offset,
        };
        let offset = sext(w >> 15, 7).wrapping_mul(width.into());
        let base = state.get(rn);
        let at = if index == Index::Post {
            base
        } else {
            base.plus(offset)
        };
        // LDPSW (opc 01) sign-extends.
        let follows = !simd && size != 1;
        let mut loaded = [Val::Unknown; 2];
        for (value, delta) in loaded.iter_mut().zip([0, i64::from(width)]) {
            if let (true, Val::Stack(off)) = (load && follows, at.plus(delta)) {
                *value = state.load(off, width);
            }
        }
        if let (false, Val::Stack(off)) = (load, at) {
            if simd || size == 1 {
                // SIMD registers, or STGP's two doublewords and tags.
                let bytes = if simd {
                    u16::from(width).wrapping_mul(2)
                } else {
                    16
                };
                state.forget(off, bytes);
            } else {
                state.store(off, zr(state, rt), width);
                state.store(off.wrapping_add(width.into()), zr(state, rt2), width);
            }
        }
        if index != Index::Offset {
            state.set(rn, base.plus(offset));
        }
        if load && !simd {
            let [first, second] = loaded;
            set_zr(state, rt, first);
            set_zr(state, rt2, second);
        }
        return;
    }
    // Register offsets, exclusives, atomics, SIMD structures: may store
    // anywhere in a frame the base points into, and may write the registers
    // the Rt, Rt2 and Rs fields name.
    if matches!(state.get(rn), Val::Stack(_)) {
        state.forget_frame();
    }
    if !simd {
        set_zr(state, rt, Val::Unknown);
        set_zr(state, rt2, Val::Unknown);
        set_zr(state, w >> 16 & 0x1f, Val::Unknown);
    }
}
