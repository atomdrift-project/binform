//! 32-bit Arm value tracking, for `connect(2)` and its kin built in registers
//! and on the stack before an `svc`. Instruction length and control flow come
//! from binform's Arm decoder, which already handles A32, Thumb and `it`
//! blocks; this layer adds what registers and stack bytes an instruction
//! leaves, for the value-producing instructions a syscall sequence uses
//! (`mov`, `movw`/`movt`, `add`/`sub`, the stores, `rev16`). An instruction it
//! does not model clears what it could have written, so a later read never
//! trusts a stale value.
//!
//! The Linux Arm syscall ABI takes the number in `r7` and arguments in
//! `r0..r6`; a `bl`/`blx` call takes arguments in `r0..r3`.

use super::state::{State, Val};
use super::{RawTarget, Site, Step};
use crate::isa::{Decoder, Flow};

/// The stack pointer.
const SP: u32 = 13;
/// The link register and PC: caller-saved across a call, with `r0..r3` and
/// `r12`.
const CALLER_SAVED: &[u32] = &[0, 1, 2, 3, 12, 14];

pub(crate) fn step(state: &mut State<'_>, decoder: &mut Decoder, bytes: &[u8], addr: u64) -> Step {
    let insn = decoder.decode(bytes, addr);
    let len = insn.len.max(1);
    let thumb = addr & 1 != 0;

    // A syscall takes its operands from the registers as they stand; read
    // them before anything else touches the state. The number is in r7.
    if is_svc(bytes, thumb) {
        let args = (0..=6).map(|r| state.value(r)).collect();
        let number = match state.get(7) {
            Val::Int(n) => n,
            _ => u64::MAX, // an unresolved number still marks the site.
        };
        let site = Site {
            raw: RawTarget::Syscall(number),
            args,
        };
        // The kernel returns in r0; r1..r6 and r7 survive.
        state.clear(0);
        return Step {
            len,
            site: Some(site),
            barrier: false,
        };
    }

    match insn.flow {
        Flow::Call(to) => {
            let site = call_site(state, RawTarget::Call(to));
            clobber(state);
            Step { len, site: Some(site), barrier: false }
        }
        Flow::CallSlot(slot) => {
            let site = call_site(state, RawTarget::Call(slot));
            clobber(state);
            Step { len, site: Some(site), barrier: false }
        }
        Flow::CallIndirect | Flow::CallRegister(_) => {
            let site = call_site(state, RawTarget::Indirect);
            clobber(state);
            Step { len, site: Some(site), barrier: false }
        }
        Flow::Jump(_) | Flow::JumpSlot(_) | Flow::JumpMemory(_) | Flow::JumpRegister(_)
        | Flow::JumpIndirect | Flow::JumpAdd { .. } | Flow::JumpTable { .. }
        | Flow::Return | Flow::Stop | Flow::Invalid => Step::stop(len),
        Flow::Branch(_) => {
            // Conditional, falling through: registers are unchanged.
            Step::go(len)
        }
        Flow::Next => {
            if thumb {
                track_thumb(state, bytes, len);
            } else {
                track_a32(state, bytes);
            }
            Step::go(len)
        }
    }
}

fn call_site(state: &State<'_>, raw: RawTarget) -> Site {
    Site {
        raw,
        args: (0..=3).map(|r| state.value(r)).collect(),
    }
}

/// Forget the registers a call may change.
fn clobber(state: &mut State<'_>) {
    for &reg in CALLER_SAVED {
        state.clear(reg);
    }
}

/// Whether `bytes` begin a syscall instruction: A32 `svc` is `cond 1111
/// imm24`, Thumb `svc` is `1101 1111 imm8`. The immediate is the SVC comment,
/// which Linux ignores; the number is in `r7`.
fn is_svc(bytes: &[u8], thumb: bool) -> bool {
    if thumb {
        // Thumb `svc` is `1101 1111 imm8`: a high byte of 0xdf.
        half(bytes).is_some_and(|h| h >> 8 == 0xdf)
    } else {
        word(bytes).is_some_and(|w| w & 0x0f00_0000 == 0x0f00_0000)
    }
}

/// A little-endian 32-bit word.
fn word(bytes: &[u8]) -> Option<u32> {
    bytes.first_chunk::<4>().map(|&b| u32::from_le_bytes(b))
}

/// A little-endian 16-bit halfword.
fn half(bytes: &[u8]) -> Option<u16> {
    bytes.first_chunk::<2>().map(|&b| u16::from_le_bytes(b))
}

/// `ror(imm8, 2 * rotate)`: an A32 data-processing immediate.
fn expand_imm(word: u32) -> u64 {
    let imm8 = word & 0xff;
    let rotate = (word >> 8 & 0xf) * 2;
    u64::from(imm8.rotate_right(rotate))
}

fn track_a32(state: &mut State<'_>, bytes: &[u8]) {
    let Some(w) = word(bytes) else {
        return;
    };
    let cond = w >> 28;
    // NV (0b1111) space is not data processing; AL (0b1110) is unconditional.
    // A conditional instruction may not run, so it can only clear.
    let runs = cond == 0b1110;

    let rn = w >> 16 & 0xf;
    let rd = w >> 12 & 0xf;
    let rm = w & 0xf;

    // Media instructions (`cond 011 ..... ....1 ....`) share the load/store
    // major space but set bit 4; REV16 is one, and the port of a sockaddr is
    // byte-swapped with it.
    if w & 0x0fff_0ff0 == 0x06bf_0fb0 {
        if let (true, Val::Int(v)) = (runs, state.get(rm)) {
            state.set_int(rd, rev16(v));
        } else {
            clear(state, rd, runs);
        }
        return;
    }
    let media = w & 0x0e00_0010 == 0x0600_0010;

    // Load/store word or byte: `cond 01I PUBWL Rn Rt ...`.
    if w & 0x0c00_0000 == 0x0400_0000 && !media {
        let load = w & 0x0010_0000 != 0;
        let byte = w & 0x0040_0000 != 0;
        let register_offset = w & 0x0200_0000 != 0;
        if load {
            clear(state, rd, runs);
        } else if !register_offset {
            store(state, w, rn, rd, if byte { 1 } else { 4 }, w & 0xfff, runs);
        } else {
            // A register offset the walk does not resolve: the base may be
            // written back, so forget it.
            if w & 0x0020_0000 != 0 {
                clear(state, rn, runs);
            }
        }
        return;
    }

    // Extra load/store (halfword): `cond 000 PUIWL Rn Rt iiii 1SH1 iiii`.
    if w & 0x0e00_0090 == 0x0000_0090 && w & 0x60 != 0 {
        let load = w & 0x0010_0000 != 0;
        let half = w & 0x60 == 0x20;
        if load {
            clear(state, rd, runs);
        } else if half {
            let imm = (w >> 4 & 0xf0) | (w & 0xf);
            store(state, w, rn, rd, 2, imm, runs);
        }
        return;
    }

    // MOVW / MOVT: `cond 0011 0x00 imm4 Rd imm12`.
    if w & 0x0fb0_0000 == 0x0300_0000 {
        let imm16 = u64::from((w >> 4 & 0xf000) | (w & 0xfff));
        let top = w & 0x0040_0000 != 0;
        if !runs {
            clear(state, rd, false);
        } else if top {
            // MOVT sets the high half, keeping the low half of a known value.
            match state.get(rd) {
                Val::Int(low) => state.set_int(rd, (low & 0xffff) | (imm16 << 16)),
                _ => state.clear(rd),
            }
        } else {
            state.set_int(rd, imm16);
        }
        return;
    }

    // Data processing. Register form `cond 000 op S Rn Rd shift Rm`, immediate
    // form `cond 001 op S Rn Rd rot imm8`. Only the opcodes a sequence uses
    // are modelled; the rest clear Rd.
    let dp_imm = w & 0x0e00_0000 == 0x0200_0000;
    let dp_reg = w & 0x0e00_0010 == 0x0000_0000;
    if dp_imm || dp_reg {
        let opcode = w >> 21 & 0xf;
        if !runs {
            clear(state, rd, false);
            return;
        }
        match (opcode, dp_imm) {
            // MOV immediate.
            (0b1101, true) => state.set_int(rd, expand_imm(w)),
            // MOV register (no shift): a copy.
            (0b1101, false) if w & 0xff0 == 0 => state.set(rd, state.get(rm)),
            // ADD immediate.
            (0b0100, true) => set_offset(state, rd, rn, expand_imm(w) as i64),
            // SUB immediate.
            (0b0010, true) => set_offset(state, rd, rn, -(expand_imm(w) as i64)),
            _ => state.clear(rd),
        }
        return;
    }

    // Anything else that writes a general register writes Rd in the common
    // encodings; clearing it is safe, clearing nothing would risk a stale read.
    clear(state, rd, runs);
}

/// `reg = base's value + imm`, following a stack pointer so a frame stays
/// addressable; a known integer base keeps its arithmetic.
fn set_offset(state: &mut State<'_>, reg: u32, base: u32, imm: i64) {
    let value = match base_val(state, base) {
        Val::Stack(off) => Val::Stack(off.wrapping_add(imm)),
        Val::Int(n) => Val::Int((n as i64).wrapping_add(imm) as u64),
        Val::Unknown => Val::Unknown,
    };
    state.set(reg, value);
}

/// A register's value, reading the stack pointer as the frame base when
/// nothing is tracked for it.
fn base_val(state: &State<'_>, reg: u32) -> Val {
    match state.get(reg) {
        Val::Unknown if reg == SP => Val::Stack(0),
        other => other,
    }
}

/// Store `count` bytes of Rt at `[Rn, #imm]`, when Rn addresses the frame.
fn store(state: &mut State<'_>, w: u32, rn: u32, rt: u32, count: u8, imm: u32, runs: bool) {
    // Pre-indexed with a positive or negative offset, no writeback modelled
    // beyond the frame pointer itself.
    let up = w & 0x0080_0000 != 0;
    let Val::Stack(base) = base_val(state, rn) else {
        return;
    };
    let off = if up {
        base.wrapping_add(i64::from(imm))
    } else {
        base.wrapping_sub(i64::from(imm))
    };
    if !runs {
        state.forget_stack(off, count);
        return;
    }
    match state.get(rt) {
        Val::Int(v) => state.store_stack(off, v, count),
        _ => state.forget_stack(off, count),
    }
}

/// Clear `reg` when the instruction runs; a conditional write may still leave
/// the old value, but reporting the old value would be wrong, so clear either
/// way.
fn clear(state: &mut State<'_>, reg: u32, _runs: bool) {
    state.clear(reg);
}

/// Swap the bytes of each halfword of a 32-bit value: Arm `rev16`, used to put
/// a port in network order.
fn rev16(v: u64) -> u64 {
    let v = v & 0xffff_ffff;
    ((v & 0x00ff_00ff) << 8 | (v & 0xff00_ff00) >> 8) & 0xffff_ffff
}

fn track_thumb(state: &mut State<'_>, bytes: &[u8], len: u32) {
    let Some(first) = half(bytes) else {
        return;
    };
    if len == 4 {
        let Some(second) = bytes.get(2..).and_then(half) else {
            return;
        };
        track_t32(state, first, second);
        return;
    }
    let first = u32::from(first);
    let rd3 = first & 0x7;
    match first >> 11 {
        // MOVS Rd, #imm8  (00100 Rd imm8).
        0b00100 => state.set_int((first >> 8) & 0x7, u64::from(first & 0xff)),
        _ => match first >> 8 {
            // MOV Rd, Rm (hi registers): 01000110 D Rm Rd.
            0b0100_0110 => {
                let rd = ((first >> 7 & 1) << 3) | (first & 0x7);
                let rm = (first >> 3) & 0xf;
                state.set(rd, state.get(rm));
            }
            _ => match first >> 6 {
                // REV16 Rd, Rm: 1011101001 Rm Rd.
                0b10_1110_1001 => match state.get((first >> 3) & 0x7) {
                    Val::Int(v) => state.set_int(rd3, rev16(v)),
                    _ => state.clear(rd3),
                },
                _ => thumb_clobber(state, first),
            },
        },
    }
}

/// A Thumb instruction the walk does not model: clear the low register it most
/// likely writes, and when that cannot be told, clear every argument register
/// so no stale value is read.
fn thumb_clobber(state: &mut State<'_>, first: u32) {
    // Forms that do not touch tracked data (compare, branch, `it`, `nop`,
    // `push`/`pop` of saved registers) are common and harmless to data
    // registers; clearing the low destination covers the arithmetic and load
    // forms that encode Rd in bits 2:0 or 10:8.
    match first >> 11 {
        0b00000..=0b00111 => {
            state.clear(first & 0x7);
            state.clear((first >> 8) & 0x7);
        }
        _ => {
            for r in 0..=3 {
                state.clear(r);
            }
        }
    }
}

fn track_t32(state: &mut State<'_>, first: u16, second: u16) {
    let first = u32::from(first);
    let second = u32::from(second);
    let rd = (second >> 8) & 0xf;
    // MOVW/MOVT: 11110 i 10 0x00 imm4 | 0 imm3 Rd imm8; MOVT sets bit 0x0080.
    if first & 0xfbf0 == 0xf240 || first & 0xfbf0 == 0xf2c0 {
        let imm16 = ((first & 0xf) << 12)
            | ((first >> 10 & 1) << 11)
            | ((second >> 12 & 0x7) << 8)
            | (second & 0xff);
        let top = first & 0x0080 != 0;
        if top {
            match state.get(rd) {
                Val::Int(low) => state.set_int(rd, (low & 0xffff) | (u64::from(imm16) << 16)),
                _ => state.clear(rd),
            }
        } else {
            state.set_int(rd, u64::from(imm16));
        }
        return;
    }
    // A modelled-miss T32 instruction: clear its destination register.
    state.clear(rd);
}
