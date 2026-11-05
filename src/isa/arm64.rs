//! A64. Control flow is decoded, plus the `adrp`/`add`/`ldr` sequence that
//! stubs load a slot's address with, and for jump tables the compares,
//! addresses, loads and adds that build a target. Every other instruction
//! falls through, forgetting the registers it may write.

use crate::isa::{Extend, Flow, Insn, Mem, Note, Regs, relative, sext, u32_at};

/// What the instructions since the last reset left in each general register.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct State {
    /// A known address held in the register.
    value: Regs<u64, 32>,
    /// The register was loaded from this fixed address.
    loaded: Regs<u64, 32>,
}

/// The registers a call may change: `x0`-`x18` and the link register.
const VOLATILE: u64 = 0x4007_ffff;

pub(crate) fn decode(state: &mut State, bytes: &[u8], addr: u64) -> Insn {
    let Some(word) = u32_at(bytes, 0, false) else {
        return Insn::new(4, Flow::Invalid);
    };
    let flow = flow(state, word, addr);
    let note = if flow == Flow::Next {
        let tracked = track(state, word, addr);
        let note = note(state, word);
        // What any other instruction writes is no longer known.
        if !tracked {
            state.value.forget(note.writes());
            state.loaded.forget(note.writes());
        }
        note
    } else {
        Note::None
    };
    Insn {
        note,
        // NOP, BTI, PACIASP and the rest of the hint space.
        pad: word & 0xffff_f01f == 0xd503_201f,
        ..Insn::new(4, flow)
    }
}

/// `stp x29, x30, [sp, ...]`, saving the frame record, after at most two of
/// `bti c`, `paciasp` and `sub sp, sp, #n`.
pub(crate) fn starts_frame(bytes: &[u8]) -> bool {
    for &word in bytes.as_chunks::<4>().0.iter().take(3) {
        let word = u32::from_le_bytes(word);
        // Pre-indexed or signed-offset, at any offset.
        let pair = word & 0xffc0_7fff;
        if pair == 0xa980_7bfd || pair == 0xa900_7bfd {
            return true;
        }
        let prefix = word == 0xd503_245f // bti c
            || word == 0xd503_233f // paciasp
            || word & 0xff80_03ff == 0xd100_03ff; // sub sp, sp, #n
        if !prefix {
            return false;
        }
    }
    false
}

fn flow(state: &State, word: u32, addr: u64) -> Flow {
    let rn = (word >> 5) & 0x1f;
    if word & 0x7c00_0000 == 0x1400_0000 {
        // B, BL
        let target = relative(addr, word & 0x03ff_ffff, 26, 4);
        return if word & 0x8000_0000 == 0 {
            Flow::Jump(target)
        } else {
            Flow::Call(target)
        };
    }
    if word & 0xff00_0010 == 0x5400_0000 || word & 0x7e00_0000 == 0x3400_0000 {
        // B.cond, CBZ, CBNZ
        return Flow::Branch(relative(addr, (word >> 5) & 0x7_ffff, 19, 4));
    }
    if word & 0x7e00_0000 == 0x3600_0000 {
        // TBZ, TBNZ
        return Flow::Branch(relative(addr, (word >> 5) & 0x3fff, 14, 4));
    }
    if word & 0xfe00_0000 == 0xd600_0000 {
        // Branch to register: BR, BLR, RET, ERET, DRPS, and their
        // pointer-authenticating forms.
        let slot = state.loaded.get(rn);
        return match (word >> 21) & 0xf {
            0 | 8 => slot.map_or(Flow::JumpRegister(rn), Flow::JumpSlot),
            1 | 9 => slot.map_or(Flow::CallIndirect, Flow::CallSlot),
            2 | 4 | 5 => Flow::Return,
            _ => Flow::Stop,
        };
    }
    if word & 0xffe0_001f == 0xd420_0000 || word & 0xffe0_001f == 0xd440_0000 {
        // BRK, HLT
        return Flow::Stop;
    }
    if word >> 16 == 0 {
        // UDF: permanently undefined, what zeros decode as.
        return Flow::Invalid;
    }
    Flow::Next
}

/// Record the address or slot `word` at `addr` leaves in its register:
/// ADR, ADRP, and the ADD and LDR stubs build a slot's address with.
/// Whether it was one of those.
fn track(state: &mut State, word: u32, addr: u64) -> bool {
    let rd = word & 0x1f;
    let rn = (word >> 5) & 0x1f;
    if word & 0x1f00_0000 == 0x1000_0000 {
        // ADR, ADRP
        let imm = (((word >> 5) & 0x7_ffff) << 2) | ((word >> 29) & 0x3);
        let value = if word & 0x8000_0000 == 0 {
            addr.wrapping_add_signed(sext(imm, 21))
        } else {
            (addr & !0xfff).wrapping_add_signed(sext(imm, 21) << 12)
        };
        set(state, rd, Some(value), None);
    } else if word & 0xff80_0000 == 0x9100_0000 {
        // ADD (immediate, 64-bit)
        let shift = if word & 0x0040_0000 == 0 { 0 } else { 12 };
        let imm = u64::from((word >> 10) & 0xfff) << shift;
        let value = state.value.get(rn);
        set(state, rd, value.map(|value| value.wrapping_add(imm)), None);
    } else if word & 0xffc0_0000 == 0xf940_0000 {
        // LDR (immediate, unsigned offset, 64-bit)
        let offset = u64::from((word >> 10) & 0xfff) << 3;
        let base = state.value.get(rn);
        set(state, rd, None, base.map(|base| base.wrapping_add(offset)));
    } else {
        return false;
    }
    true
}

/// What the instruction tells a jump-table read, once [`track`] has updated
/// `state`.
fn note(state: &State, word: u32) -> Note {
    let reg = |shift: u32| (word >> shift) & 0x1f;
    let (rd, rn, rm) = (reg(0), reg(5), reg(16));
    if word & 0x1f00_0000 == 0x1000_0000 {
        // ADR, ADRP
        return match state.value.get(rd) {
            Some(addr) => Note::Address { reg: rd, addr },
            None => Note::Write(rd),
        };
    }
    if word & 0xff80_0000 == 0x9100_0000 {
        // ADD (immediate, 64-bit)
        let shift = if word & 0x0040_0000 == 0 { 0 } else { 12 };
        return Note::Offset {
            reg: rd,
            src: rn,
            imm: u64::from((word >> 10) & 0xfff) << shift,
        };
    }
    if word & 0x7f80_001f == 0x7100_001f {
        // CMP (immediate): SUBS to the zero register.
        let shift = if word & 0x0040_0000 == 0 { 0 } else { 12 };
        return Note::Compare {
            reg: rn,
            imm: u64::from((word >> 10) & 0xfff) << shift,
        };
    }
    if word & 0x7fe0_ffe0 == 0x2a00_03e0 {
        // MOV (register): ORR from the zero register.
        return Note::Copy { reg: rd, src: rm };
    }
    if word & 0xffe0_0000 == 0x8b00_0000 {
        // ADD (shifted register, 64-bit, LSL)
        let shift = (word >> 10) & 0x3f;
        return match u8::try_from(shift) {
            Ok(shift) if shift <= 4 => Note::Add {
                reg: rd,
                base: rn,
                index: rm,
                shift,
                extend: Extend::None,
            },
            _ => Note::Write(rd),
        };
    }
    if word & 0xffe0_0000 == 0x8b20_0000 && (word >> 10) & 7 <= 4 {
        // ADD (extended register, 64-bit)
        let extend = match (word >> 13) & 7 {
            0 => Extend::Zero(1),
            1 => Extend::Zero(2),
            2 => Extend::Zero(4),
            4 => Extend::Sign(1),
            5 => Extend::Sign(2),
            6 => Extend::Sign(4),
            _ => Extend::None,
        };
        return Note::Add {
            reg: rd,
            base: rn,
            index: rm,
            shift: ((word >> 10) & 7) as u8,
            extend,
        };
    }
    if word & 0x3f20_0c00 == 0x3820_0800 {
        // LDR, LDRB, LDRH, LDRS* (register offset); STR and PRFM.
        let size = (word >> 30) as u8;
        let opc = (word >> 22) & 3;
        if opc == 0 {
            return Note::None;
        }
        if (opc == 2 && size == 3) || (opc == 3 && size >= 2) {
            // PRFM, and unallocated encodings.
            return Note::Write(rd);
        }
        let shift = if word & 0x1000 == 0 { 0 } else { size };
        return Note::Load {
            reg: rd,
            mem: Mem {
                base: Some(rn),
                index: Some(rm),
                scale: 1 << shift,
                disp: 0,
            },
            size: 1 << size,
            signed: opc >= 2,
        };
    }
    if word & 0x0a00_0000 == 0x0800_0000 {
        return writes(load_store_writes(word));
    }
    if word & 0xffc0_0000 == 0xd500_0000 {
        // System: MRS and SYSL write their register; the rest write none.
        return if word & 0x0020_0000 == 0 {
            Note::None
        } else {
            Note::Write(rd)
        };
    }
    if word & 0xffe0_001f == 0xd400_0001 {
        // SVC: the kernel answers in x0.
        return Note::Write(0);
    }
    // Data processing, and SIMD and floating point. A vector destination
    // shares its number with a general register; forgetting that register
    // costs at most a table.
    if word & 0x1c00_0000 == 0x1000_0000
        || word & 0x0e00_0000 == 0x0a00_0000
        || word & 0x0e00_0000 == 0x0e00_0000
    {
        return Note::Write(rd);
    }
    Note::None
}

/// A note for an instruction that writes the registers in the mask.
fn writes(regs: u32) -> Note {
    match regs.count_ones() {
        0 => Note::None,
        1 => Note::Write(regs.trailing_zeros()),
        _ => Note::Clobber(regs),
    }
}

/// The general registers a load or store may write, as a mask: the loaded
/// registers, and the base register when the address is written back.
/// Forms not told apart here count every register they name.
fn load_store_writes(word: u32) -> u32 {
    let reg = |shift: u32| 1_u32 << ((word >> shift) & 0x1f);
    let (rt, rn, rt2, rs) = (reg(0), reg(5), reg(10), reg(16));
    let opc = (word >> 22) & 3;
    match (word >> 27) & 7 {
        // Pairs: offset, post-index, pre-index.
        0b101 => {
            let loads = word & 0x0040_0000 != 0;
            let writeback = matches!((word >> 23) & 3, 1 | 3);
            (if loads { rt | rt2 } else { 0 }) | (if writeback { rn } else { 0 })
        }
        // Literal loads.
        0b011 if word & 0x0100_0000 == 0 => rt,
        // One register.
        0b111 => {
            let low = (word >> 10) & 3;
            let (loads, writeback) = if word & 0x0100_0000 != 0 {
                // Unsigned offset.
                (opc != 0, false)
            } else if word & 0x0020_0000 == 0 {
                // Unscaled, post-index, unprivileged, pre-index.
                (opc != 0, low & 1 != 0)
            } else {
                match low {
                    0 => (true, false),     // atomic memory operations
                    2 => (opc != 0, false), // register offset
                    _ => (true, low == 3),  // pointer-authenticated
                }
            };
            (if loads { rt } else { 0 }) | (if writeback { rn } else { 0 })
        }
        _ => rt | rn | rt2 | rs,
    }
}

fn set(state: &mut State, reg: u32, value: Option<u64>, loaded: Option<u64>) {
    state.value.set(reg, value);
    state.loaded.set(reg, loaded);
}

/// The A64 decoder.
#[derive(Clone, Debug, Default)]
pub(crate) struct Decoder {
    state: State,
}

impl crate::isa::Decode for Decoder {
    fn decode(&mut self, bytes: &[u8], addr: u64) -> Insn {
        decode(&mut self.state, bytes, addr)
    }

    fn reset(&mut self) {
        self.state = State::default();
    }

    fn call(&mut self) {
        self.state.value.forget(VOLATILE);
        self.state.loaded.forget(VOLATILE);
    }

    fn starts_frame(&self, bytes: &[u8]) -> bool {
        starts_frame(bytes)
    }

    fn argument(&self, n: usize) -> Option<u32> {
        u32::try_from(n).ok().filter(|&n| n < 8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|word| word.to_le_bytes()).collect()
    }

    #[test]
    fn frames() {
        // stp x29, x30, [sp, #-16]!
        assert!(starts_frame(&words(&[0xa9bf_7bfd])));
        // paciasp; sub sp, sp, #0x40; stp x29, x30, [sp, #0x30]
        assert!(starts_frame(&words(&[
            0xd503_233f,
            0xd101_03ff,
            0xa903_7bfd
        ])));
        // ret
        assert!(!starts_frame(&words(&[0xd65f_03c0, 0xa9bf_7bfd])));
        assert!(!starts_frame(&[]));
    }

    fn one(word: u32, addr: u64) -> Flow {
        decode(&mut State::default(), &word.to_le_bytes(), addr).flow
    }

    #[test]
    fn branches() {
        assert_eq!(one(0x1400_0004, 0x1000), Flow::Jump(0x1010)); // b +16
        assert_eq!(one(0x17ff_ffff, 0x1000), Flow::Jump(0xffc)); // b -4
        assert_eq!(one(0x9400_0002, 0x1000), Flow::Call(0x1008)); // bl +8
        assert_eq!(one(0x5400_0040, 0x1000), Flow::Branch(0x1008)); // b.eq +8
        assert_eq!(one(0xb400_0060, 0x1000), Flow::Branch(0x100c)); // cbz x0, +12
        assert_eq!(one(0x3600_0080, 0x1000), Flow::Branch(0x1010)); // tbz w0, #0, +16
        assert_eq!(one(0xd65f_03c0, 0x1000), Flow::Return); // ret
        assert_eq!(one(0xd65f_0bff, 0x1000), Flow::Return); // retaa
        assert_eq!(one(0xd61f_0200, 0x1000), Flow::JumpRegister(16)); // br x16
        assert_eq!(one(0xd63f_0200, 0x1000), Flow::CallIndirect); // blr x16
        assert_eq!(one(0xd420_0000, 0x1000), Flow::Stop); // brk #0
        assert_eq!(one(0x0000_0000, 0x1000), Flow::Invalid); // udf #0
        assert_eq!(one(0xaa01_03e0, 0x1000), Flow::Next); // mov x0, x1
    }

    /// A Mach-O `__stubs` entry: `adrp x16, page; ldr x16, [x16, #off]; br x16`.
    #[test]
    fn stub_jumps_through_its_slot() {
        let mut state = State::default();
        let words = [0xb000_0010_u32, 0xf940_0610, 0xd61f_0200];
        let flows: Vec<Flow> = (0_u64..)
            .zip(words)
            .map(|(i, word)| decode(&mut state, &word.to_le_bytes(), 0x1_0000 + 4 * i).flow)
            .collect();
        // adrp x16, #0x1000 at 0x10000 is page 0x11000; the slot is 8 bytes in.
        assert_eq!(flows, [Flow::Next, Flow::Next, Flow::JumpSlot(0x1_1008)]);
    }

    /// A compare writes no register: `cmp x16, #0` between the load of a
    /// slot's pointer and the jump through it leaves the slot known.
    #[test]
    fn compares_keep_the_slot() {
        let mut state = State::default();
        let words = [0xb000_0010_u32, 0xf940_0610, 0xf100_021f, 0xd61f_0200];
        let flows: Vec<Flow> = (0_u64..)
            .zip(words)
            .map(|(i, word)| decode(&mut state, &word.to_le_bytes(), 0x1_0000 + 4 * i).flow)
            .collect();
        assert_eq!(flows[3], Flow::JumpSlot(0x1_1008));
    }

    /// A call forgets the slot a caller-saved register was loaded from,
    /// and keeps a callee-saved one's: `adrp x16, page; ldr x16, [x16,
    /// #8]`, the same into x19, `bl`, then `br` each.
    #[test]
    fn calls_forget_caller_saved_registers() {
        use crate::isa::Decode as _;
        let mut decoder = Decoder::default();
        let words = [
            0xb000_0010_u32,
            0xf940_0610,
            0xb000_0013,
            0xf940_0673,
            0x9400_0010,
        ];
        for (i, word) in (0_u64..).zip(words) {
            decoder.decode(&word.to_le_bytes(), 0x1_0000 + 4 * i);
        }
        decoder.call();
        let after = |word: u32| decoder.clone().decode(&word.to_le_bytes(), 0x1_0014).flow;
        assert_eq!(after(0xd61f_0200), Flow::JumpRegister(16)); // br x16
        assert_eq!(after(0xd61f_0260), Flow::JumpSlot(0x1_1008)); // br x19
    }

    fn notes(words: &[u32], addr: u64) -> Vec<Note> {
        let mut state = State::default();
        (0_u64..)
            .zip(words)
            .map(|(i, word)| decode(&mut state, &word.to_le_bytes(), addr + 4 * i).note)
            .collect()
    }

    /// GCC's sparse switch: byte entries, sign-extended and scaled as they
    /// are added to an anchor.
    #[test]
    fn switch_notes() {
        let words = [
            0x7100_241f, // cmp w0, #9
            0x9000_0001, // adrp x1, 0x10000
            0x9100_4021, // add x1, x1, #0x10
            0x3860_4821, // ldrb w1, [x1, w0, uxtw]
            0x1000_0082, // adr x2, +0x10
            0x8b21_8841, // add x1, x2, w1, sxtb #2
        ];
        assert_eq!(
            notes(&words, 0x1_0000),
            [
                Note::Compare { reg: 0, imm: 9 },
                Note::Address {
                    reg: 1,
                    addr: 0x1_0000
                },
                Note::Offset {
                    reg: 1,
                    src: 1,
                    imm: 0x10
                },
                Note::Load {
                    reg: 1,
                    mem: Mem {
                        base: Some(1),
                        index: Some(0),
                        scale: 1,
                        disp: 0
                    },
                    size: 1,
                    signed: false
                },
                Note::Address {
                    reg: 2,
                    addr: 0x1_0020
                },
                Note::Add {
                    reg: 1,
                    base: 2,
                    index: 1,
                    shift: 2,
                    extend: Extend::Sign(1)
                },
            ]
        );
    }

    #[test]
    fn writes_are_noted() {
        // ldp x19, x20, [sp], #16: two loads and the base written back.
        assert_eq!(
            notes(&[0xa8c1_53f3], 0),
            [Note::Clobber(1 << 19 | 1 << 20 | 1 << 31)]
        );
        // str x0, [sp, #8]: writes nothing.
        assert_eq!(notes(&[0xf900_07e0], 0), [Note::None]);
        // ldr x16, [x16, #8]; mov x0, x1; movz x3, #1
        assert_eq!(
            notes(&[0xf940_0610, 0xaa01_03e0, 0xd280_0023], 0),
            [
                Note::Write(16),
                Note::Copy { reg: 0, src: 1 },
                Note::Write(3)
            ]
        );
        // ldrsw x9, [x10, x9, lsl #2]
        assert_eq!(
            notes(&[0xb8a9_7949], 0),
            [Note::Load {
                reg: 9,
                mem: Mem {
                    base: Some(10),
                    index: Some(9),
                    scale: 4,
                    disp: 0
                },
                size: 4,
                signed: true
            }]
        );
    }

    #[test]
    fn hints_are_padding() {
        let pad = |word: u32| decode(&mut State::default(), &word.to_le_bytes(), 0).pad;
        assert!(pad(0xd503_201f)); // nop
        assert!(pad(0xd503_245f)); // bti c
        assert!(!pad(0xaa01_03e0)); // mov x0, x1
    }
}
