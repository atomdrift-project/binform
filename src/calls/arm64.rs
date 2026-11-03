//! AArch64 value tracking. Instruction length is fixed at four bytes and
//! control flow comes from binform's arm64 decoder; this layer adds the
//! constants and stack stores a syscall or call sequence builds with `movz`/
//! `movk`, `mov`, `add`/`sub`, `adr`/`adrp` and the stores.
//!
//! The Linux AArch64 syscall ABI takes the number in `x8` and arguments in
//! `x0..x5`; a `bl` call takes arguments in `x0..x7`.

use super::state::{State, Val};
use super::{RawTarget, Site, Step};
use crate::isa::{Decoder, Flow};

/// The stack pointer / zero register number.
const SP: u32 = 31;

pub(crate) fn step(state: &mut State<'_>, decoder: &mut Decoder, bytes: &[u8], addr: u64) -> Step {
    let insn = decoder.decode(bytes, addr);
    let len = insn.len.max(1);
    let Some(w) = word(bytes) else {
        return Step::stop(len);
    };

    // SVC #0: `1101 0100 000 imm16 0 0001`. Linux issues `svc #0`, so the
    // imm16 comment is zero; a non-zero one is not a Linux syscall, and
    // requiring zero keeps data sharing the opcode from reading as one. The
    // number is in x8.
    if w == 0xd400_0001 {
        let args = (0..=5).map(|r| state.value(r)).collect();
        let number = match state.get(8) {
            Val::Int(n) => n,
            _ => u64::MAX,
        };
        state.clear(0); // the kernel returns in x0.
        return Step {
            len,
            site: Some(Site { raw: RawTarget::Syscall(number), args }),
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
        Flow::Branch(_) => Step::go(len),
        Flow::Next => {
            track(state, w, addr);
            Step::go(len)
        }
    }
}

fn call_site(state: &State<'_>, raw: RawTarget) -> Site {
    Site { raw, args: (0..=7).map(|r| state.value(r)).collect() }
}

/// Forget the registers a call may change: `x0..x18` and the link register.
fn clobber(state: &mut State<'_>) {
    for r in 0..=18 {
        state.clear(r);
    }
    state.clear(30);
}

fn word(bytes: &[u8]) -> Option<u32> {
    bytes.first_chunk::<4>().map(|&b| u32::from_le_bytes(b))
}

fn track(state: &mut State<'_>, w: u32, addr: u64) {
    let rd = w & 0x1f;
    let rn = (w >> 5) & 0x1f;
    let sf = w & 0x8000_0000 != 0; // 64-bit operand.

    // Move wide: MOVZ/MOVN/MOVK, `sf op 100101 hw(2) imm16 Rd`.
    if w & 0x1f80_0000 == 0x1280_0000 {
        let imm16 = u64::from((w >> 5) & 0xffff);
        let shift = ((w >> 21) & 0x3) * 16;
        let op = (w >> 29) & 0x3;
        let value = match op {
            0b10 => imm16 << shift,                       // MOVZ
            0b00 => !(imm16 << shift),                    // MOVN
            0b11 => match state.get(rd) {                 // MOVK: keep the rest
                Val::Int(v) => (v & !(0xffff << shift)) | (imm16 << shift),
                _ => {
                    state.clear(rd);
                    return;
                }
            },
            _ => {
                state.clear(rd);
                return;
            }
        };
        set(state, rd, Val::Int(mask(value, sf)));
        return;
    }

    // ADD/SUB immediate: `sf op 0 100010 sh imm12 Rn Rd`.
    if w & 0x1f00_0000 == 0x1100_0000 {
        let imm12 = (w >> 10) & 0xfff;
        let shifted = if w & 0x0040_0000 != 0 { imm12 << 12 } else { imm12 };
        let sub = w & 0x4000_0000 != 0;
        set_offset(state, rd, rn, i64::from(shifted), sub, sf);
        return;
    }

    // ADR / ADRP: `op immlo(2) 10000 immhi(19) Rd`.
    if w & 0x1f00_0000 == 0x1000_0000 {
        let imm = (i64::from((w >> 5) & 0x7ffff) << 2) | i64::from((w >> 29) & 0x3);
        let page = w & 0x8000_0000 != 0;
        let value = if page {
            let imm = imm << 12;
            (addr & !0xfff).wrapping_add_signed(imm)
        } else {
            addr.wrapping_add_signed(imm)
        };
        set(state, rd, Val::Int(value));
        return;
    }

    // ORR (shifted register) with Rn == XZR, no shift, is `mov Rd, Rm`.
    if w & 0x7fe0_ffe0 == 0x2a00_03e0 {
        let rm = (w >> 16) & 0x1f;
        set(state, rd, read(state, rm, sf));
        return;
    }

    // Store (unsigned offset): `size 111 0 01 00 imm12 Rn Rt`.
    if w & 0x3b00_0000 == 0x3900_0000 {
        let size = w >> 30; // 0=byte,1=half,2=word,3=dword
        let count = 1u8 << size;
        let imm12 = i64::from((w >> 10) & 0xfff);
        store(state, rn, rd, count, imm12 * i64::from(count));
        return;
    }

    // REV16 Rd, Rn (both widths): byte-swap within each halfword.
    if w & 0x7ffe_fc00 == 0x5ac0_0400 {
        match read(state, rn, sf) {
            Val::Int(v) => set(state, rd, Val::Int(mask(rev16(v), sf))),
            _ => state.clear(rd),
        }
        return;
    }

    // Any other instruction that writes Rd: clear it. Stores and branches
    // (Rt/no destination) are handled above or do not reach here.
    if writes_rd(w) {
        state.clear(rd);
    }
}

/// Whether the instruction's destination is the register in bits 4:0. Most
/// data-processing and load encodings write there; the store and compare
/// forms that do not are matched before this.
fn writes_rd(w: u32) -> bool {
    // Exclude the compare-and-branch / test-branch and unconditional branch
    // spaces, which encode no Rd. Everything else is cleared conservatively.
    w & 0x1c00_0000 != 0x1400_0000
}

fn read(state: &State<'_>, reg: u32, sf: bool) -> Val {
    match state.get(reg) {
        Val::Int(v) => Val::Int(mask(v, sf)),
        other => other,
    }
}

fn set(state: &mut State<'_>, reg: u32, value: Val) {
    // Writes to the zero register are discarded; writes to the stack pointer
    // keep it a frame pointer.
    if reg == SP {
        if let Val::Stack(_) = value {
            state.set(reg, value);
        }
        return;
    }
    state.set(reg, value);
}

/// `reg = base ± imm`, following the stack pointer.
fn set_offset(state: &mut State<'_>, reg: u32, base: u32, imm: i64, sub: bool, sf: bool) {
    let delta = if sub { -imm } else { imm };
    let value = match base_val(state, base) {
        Val::Stack(off) => Val::Stack(off.wrapping_add(delta)),
        Val::Int(n) => Val::Int(mask((n as i64).wrapping_add(delta) as u64, sf)),
        Val::Unknown => Val::Unknown,
    };
    set(state, reg, value);
}

fn base_val(state: &State<'_>, reg: u32) -> Val {
    match state.get(reg) {
        Val::Unknown if reg == SP => Val::Stack(0),
        other => other,
    }
}

fn store(state: &mut State<'_>, rn: u32, rt: u32, count: u8, imm: i64) {
    let Val::Stack(base) = base_val(state, rn) else {
        return;
    };
    let off = base.wrapping_add(imm);
    match state.get(rt) {
        Val::Int(v) => state.store_stack(off, v, count),
        _ => state.forget_stack(off, count),
    }
}

/// Keep the low 32 bits of a 32-bit operand's result.
fn mask(value: u64, sf: bool) -> u64 {
    if sf { value } else { value & 0xffff_ffff }
}

fn rev16(v: u64) -> u64 {
    (v & 0x00ff_00ff_00ff_00ff) << 8 | (v & 0xff00_ff00_ff00_ff00) >> 8
}
