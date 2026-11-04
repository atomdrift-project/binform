//! C-SKY ABIv1 (CK510, CK610), little-endian: control flow, and the
//! constants calls and jumps through registers need. Instructions are 16
//! bits, without delay slots; the set descends from M*Core.
//!
//! `br`, `bt`, `bf` and `bsr` reach 1 KiB either way from the instruction
//! after them. Constants come from a literal pool after the function:
//! `lrw rz, [pool]` loads a word, `jmpi`/`jsri` jump or call through one.
//! The pool lies ahead of the instruction, so its words are read from the
//! bytes being decoded. Calls through a register are `jsr rx`, returns
//! `rts` (`jmp r15`). A branch beyond reach reads the PC with a `bsr` to
//! the next instruction and adds an offset from the pool (`bsr 1f; 1: lrw
//! r1, [offset]; addu r1, r15; ...; jmp r1`): no call, and a jump inside
//! the function.

use crate::isa::{Decode, Flow, Insn, Mem, Note, Regs, relative, u16_at, u32_at};

/// Where a constant in a register came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    /// An immediate.
    Imm,
    /// A literal pool, or the GOT base plus one: an address.
    Pool,
    /// The PC, or the PC plus an offset (a far branch's target).
    Pc,
    /// The GOT base position-independent code keeps in `r14`.
    Gb,
}

/// The decoder, and what earlier instructions left in each register: a
/// constant, and where it came from. The GOT base, once code computes it
/// (`bsr 1f; 1: lrw r14, [offset]; addu r14, r15`), is the same in every
/// function: each starts with it in `r14`, so a call to `r14` plus a pool
/// offset resolves.
#[derive(Clone, Debug, Default)]
pub(crate) struct Decoder {
    regs: Regs<(u32, Kind), 16>,
    gb: Option<u32>,
}

/// The register position-independent code keeps the GOT base in.
const GB: u32 = 14;
/// The link register.
const LR: u32 = 15;
/// The registers a call may change: `r1` to `r7` and the link register.
const VOLATILE: u32 = 0x80fe;

/// Addresses are 32 bits.
const MASK: u64 = 0xffff_ffff;

fn half(bytes: &[u8], at: usize) -> Option<u16> {
    u16_at(bytes, at, false)
}

/// The literal-pool slot an `lrw`, `jmpi` or `jsri` `h` at `addr` reads:
/// its word displacement from the next instruction, rounded down to a word.
fn pool(h: u32, addr: u64) -> u64 {
    addr.wrapping_add(2).wrapping_add(u64::from(h & 0xff) << 2) & !3 & MASK
}

impl Decoder {
    fn get(&self, reg: u32) -> Option<(u32, Kind)> {
        self.regs.get(reg)
    }

    fn set(&mut self, reg: u32, value: Option<(u32, Kind)>) {
        self.regs.set(reg, value);
    }

    fn clobber(&mut self, reg: u32) -> Note {
        self.set(reg, None);
        Note::Clobber(1 << (reg & 15))
    }

    /// `reg = value`: an address when it came from a literal pool.
    fn constant(&mut self, reg: u32, value: u32, kind: Kind) -> Note {
        self.set(reg, Some((value, kind)));
        let value = u64::from(value);
        if kind == Kind::Pool {
            Note::Address { reg, addr: value }
        } else {
            Note::Value { reg, value }
        }
    }
}

fn decode(state: &mut Decoder, bytes: &[u8], addr: u64) -> Insn {
    let Some(h) = half(bytes, 0) else {
        return Insn::new(2, Flow::Invalid);
    };
    let h = u32::from(h);
    let z = h & 15;
    let x = (h >> 4) & 15;
    let next = addr.wrapping_add(2) & MASK;
    let pool = pool(h, addr);
    // The pool lies ahead, within the bytes being decoded.
    let literal = || u32_at(bytes, usize::try_from(pool.checked_sub(addr)?).ok()?, false);
    let mut note = Note::None;
    let flow = match h >> 11 {
        // bt, bf
        0x1c | 0x1d => Flow::Branch(branch(next, h)),
        // br
        0x1e => Flow::Jump(branch(next, h)),
        // bsr: to the next instruction, it only reads the PC.
        0x1f => {
            let to = branch(next, h);
            if to == next {
                note = state.constant(LR, u32::try_from(next).unwrap_or(0), Kind::Pc);
                Flow::Next
            } else if to == addr {
                // `bsr .` (0xffff): GCC's trap, no call.
                Flow::Stop
            } else {
                Flow::Call(to)
            }
        }
        // lrw, jmpi, jsri
        0x0e | 0x0f => {
            let r = (h >> 8) & 15;
            match (r, literal()) {
                (0, Some(to)) if to != 0 => Flow::Jump(u64::from(to)),
                (0, _) => Flow::JumpSlot(pool),
                (15, Some(to)) if to != 0 => Flow::Call(u64::from(to)),
                (15, _) => Flow::CallSlot(pool),
                (_, Some(value)) => {
                    // An offset the next instruction adds to the PC (the
                    // GOT base's, a far branch's) is no address.
                    let offset = half(bytes, 2) == u16::try_from(0x1cf0 | r).ok();
                    let kind = if offset { Kind::Imm } else { Kind::Pool };
                    note = state.constant(r, value, kind);
                    Flow::Next
                }
                _ => {
                    state.set(r, None);
                    note = Note::Fetch {
                        reg: r,
                        mem: Mem {
                            base: None,
                            index: None,
                            scale: 1,
                            disp: pool,
                        },
                        size: 4,
                        signed: false,
                    };
                    Flow::Next
                }
            }
        }
        _ => match h {
            // bkpt: zeros, which literal pools are full of.
            0x0000 | 0x000e | 0x000f => Flow::Invalid,
            // rte, rfi
            0x0002 | 0x0003 => Flow::Return,
            // stop
            0x0004 => Flow::Stop,
            // rts
            0x00cf => Flow::Return,
            // jmp rx: a jump to a constant (a far branch), or a table.
            0x00c0..=0x00ce => match state.get(z) {
                Some((to, _)) => Flow::Jump(u64::from(to)),
                None => Flow::JumpRegister(z),
            },
            // jsr rx
            0x00d0..=0x00df => match state.get(z) {
                Some((to, _)) => Flow::Call(u64::from(to)),
                None => Flow::CallRegister(z),
            },
            _ => {
                note = step(state, h, z, x);
                Flow::Next
            }
        },
    };
    let mut insn = Insn::new(2, flow);
    insn.note = note;
    // mov r0, r0
    insn.pad = h == 0x1200;
    insn
}

/// A branch's target: an 11-bit halfword displacement from `next`.
fn branch(next: u64, h: u32) -> u64 {
    relative(next, h & 0x7ff, 11, 2) & MASK
}

/// What a non-transfer `h` does to registers.
fn step(state: &mut Decoder, h: u32, z: u32, x: u32) -> Note {
    let imm5 = (h >> 4) & 31;
    match h >> 8 {
        // sync, wait, doze, idly4, trap, mvtc, cprc, cpseti
        0x00 if h < 0x20 => Note::None,
        // mvc, mvcv
        0x00 if h < 0x40 => state.clobber(z),
        // ldq: r4-r7
        0x00 if h < 0x50 => {
            for reg in 4..8 {
                state.set(reg, None);
            }
            Note::Clobber(0xf0)
        }
        // stq, stm
        0x00 if h < 0x60 || (0x70..0x80).contains(&h) => Note::None,
        // ldm rz-r15, (r0)
        0x00 if h < 0x70 => {
            let mut mask = 0;
            for reg in z..16 {
                state.set(reg, None);
                mask |= 1 << reg;
            }
            Note::Clobber(mask)
        }
        // tstnbz
        0x01 if h & 0xf0 == 0x90 => Note::None,
        // One-register operations on rz.
        0x00 | 0x01 => state.clobber(z),
        // mov rz, rx
        0x12 => match state.get(x) {
            Some((value, kind)) => state.constant(z, value, kind),
            None if z == x => Note::None,
            None => {
                state.set(z, None);
                Note::Copy { reg: z, src: x }
            }
        },
        // addu rz, rx
        0x1c => match state.get(z).zip(state.get(x)) {
            Some(((a, ka), (b, kb))) => {
                let sum = a.wrapping_add(b);
                let kind = match (ka, kb) {
                    // The GOT base: the PC plus an offset into `r14`.
                    (Kind::Imm | Kind::Pool, Kind::Pc) if z == GB => {
                        state.gb = Some(sum);
                        Kind::Gb
                    }
                    (Kind::Pc, _) | (_, Kind::Pc) => Kind::Pc,
                    (Kind::Imm, Kind::Imm) => Kind::Imm,
                    _ => Kind::Pool,
                };
                state.constant(z, sum, kind)
            }
            None => state.clobber(z),
        },
        // subu rz, rx
        0x05 => match state.get(z).zip(state.get(x)) {
            Some(((a, ka), (b, _))) => state.constant(z, a.wrapping_sub(b), ka),
            None => state.clobber(z),
        },
        // mac, cmphs, cmplt, tst, cmpne, mtcr
        0x04 | 0x0c..=0x0f | 0x18 | 0x19 => Note::None,
        // The other two-register operations write rz.
        0x02..=0x1f => state.clobber(z),
        // addi, subi rz, imm + 1
        0x20 | 0x21 | 0x24 | 0x25 => {
            let imm = imm5.wrapping_add(1);
            match state.get(z) {
                Some((value, kind)) => {
                    let value = if h >> 9 == 0x10 {
                        value.wrapping_add(imm)
                    } else {
                        value.wrapping_sub(imm)
                    };
                    state.constant(z, value, kind)
                }
                None => state.clobber(z),
            }
        }
        // cmplti, cpwgr, cmpnei, btsti
        0x22 | 0x23 | 0x26 | 0x27 | 0x2a | 0x2b | 0x36 | 0x37 => Note::None,
        // bgeni rz, imm (7 and up; below, divs and coprocessor moves)
        0x32 | 0x33 if imm5 >= 7 => state.constant(z, 1 << imm5, Kind::Imm),
        // bmaski rz, imm (8 and up; below, divu and the MAC moves)
        0x2c | 0x2d if imm5 >= 8 => {
            state.constant(z, u32::MAX >> 32_u32.wrapping_sub(imm5), Kind::Imm)
        }
        // bseti, bclri, lsli on a constant
        0x34 | 0x35 | 0x30 | 0x31 | 0x3c | 0x3d => match state.get(z) {
            Some((value, kind)) => {
                let value = match h >> 9 {
                    0x1a => value | 1 << imm5,
                    0x18 => value & !(1 << imm5),
                    _ => value << imm5,
                };
                state.constant(z, value, kind)
            }
            None => state.clobber(z),
        },
        // The other immediate operations, and the MAC, DSP and
        // coprocessor ones.
        0x20..=0x5f => state.clobber(z),
        // movi rz, imm7
        0x60..=0x67 => state.constant(z, (h >> 4) & 0x7f, Kind::Imm),
        // cprcr, cpwcr: rz is three bits.
        0x6b => state.clobber(h & 7),
        0x6f => Note::None,
        0x68..=0x6e => state.clobber(z),
        // ldw rz, (rx, disp)
        0x80..=0x8f => {
            let rz = (h >> 8) & 15;
            let disp = u64::from((h >> 4) & 15) << 2;
            let base = state.get(z);
            state.set(rz, None);
            Note::Fetch {
                reg: rz,
                mem: match base {
                    Some((value, _)) => Mem {
                        base: None,
                        index: None,
                        scale: 1,
                        disp: u64::from(value).wrapping_add(disp) & MASK,
                    },
                    None => Mem {
                        base: Some(z),
                        index: None,
                        scale: 1,
                        disp,
                    },
                },
                size: 4,
                signed: false,
            }
        }
        // ldb, ldh
        0xa0..=0xaf | 0xc0..=0xcf => state.clobber((h >> 8) & 15),
        // stw, stb, sth
        _ => Note::None,
    }
}

impl Decode for Decoder {
    fn decode(&mut self, bytes: &[u8], addr: u64) -> Insn {
        decode(self, bytes, addr)
    }

    /// The state a block starts in: nothing known but the GOT base.
    fn reset(&mut self) {
        self.regs = Regs::default();
        self.set(GB, self.gb.map(|gb| (gb, Kind::Gb)));
    }

    fn call(&mut self) {
        self.regs.forget(u64::from(VOLATILE));
    }

    /// Whether `bytes` begin a frame: GCC's first instruction lowers the
    /// stack pointer (`subi r0, n`) or saves registers (`stm rN-r15, (r0)`).
    /// Not a far branch, which saves `r15` around the `bsr` that reads the PC
    /// (`subi r0, 8; stw r15, (r0, 0); bsr 1f; 1: lrw r1, [offset]`), and
    /// lands inside a function.
    fn starts_frame(&self, bytes: &[u8]) -> bool {
        let far = half(bytes, 4) == Some(0xf800)
            && half(bytes, 6).is_some_and(|h| h >> 12 == 7 && u32::from((h >> 8) & 15) != GB);
        !far && half(bytes, 0).is_some_and(|h| h & 0xfe0f == 0x2400 || h & 0xfff0 == 0x0070)
    }

    /// The literal-pool word an `lrw`, `jmpi` or `jsri` at `addr` reads: data
    /// a linear sweep steps over.
    fn literal(&self, bytes: &[u8], addr: u64) -> Option<u64> {
        let h = u32::from(half(bytes, 0)?);
        matches!(h >> 11, 0x0e | 0x0f).then(|| pool(h, addr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each instruction of `halves`, decoded from `addr`, carrying what it
    /// leaves in registers on as `isa::Decoder` does.
    fn run(halves: &[u16], addr: u64) -> Vec<Insn> {
        let code: Vec<u8> = halves.iter().flat_map(|h| h.to_le_bytes()).collect();
        let mut decoder = Decoder::default();
        (0..halves.len())
            .map(|i| decoder.advance(&code[i * 2..], addr + i as u64 * 2))
            .collect()
    }

    /// uClibc's `_start`: `lrw r2, main; ...; lrw r12, __uClibc_main; jsr
    /// r12`, then the pool.
    #[test]
    fn start() {
        let insns = run(
            &[
                0x7209, 0x8300, 0x1204, 0x2034, 0x1205, 0x2470, 0x9500, 0x7506, 0x7607, 0x7c07,
                0x00dc, 0xf800, 0x65d1, 0x0008, 0xf7ff, 0xf7ff, 0xf7ff, 0x1200, 0x8148, 0x0000,
                0x80d4, 0x0000, 0x74b4, 0x0002, 0x437c, 0x0001,
            ],
            0x8600,
        );
        assert_eq!(
            insns[0].note,
            Note::Address {
                reg: 2,
                addr: 0x8148
            }
        );
        assert_eq!(insns[10].flow, Flow::Call(0x1_437c));
        // `bsr` to the next instruction.
        assert_eq!(insns[11].flow, Flow::Next);
        assert_eq!(insns[13].flow, Flow::Next);
        assert_eq!(insns[14].flow, Flow::Jump(0x861c));
    }

    #[test]
    fn trap() {
        assert_eq!(run(&[0xffff], 0xd7fc)[0].flow, Flow::Stop);
    }

    /// `bsr 1f; 1: lrw r1, [0x96e]; addu r1, r15; ldw r15, (r0, 0); addi
    /// r0, 8; jmp r1`: a branch to 0xec58 + 0x96e.
    #[test]
    fn far_branch() {
        let insns = run(
            &[
                0xf800, 0x7103, 0x1cf1, 0x8f00, 0x2070, 0x00c1, 0x0000, 0x096e, 0x0000,
            ],
            0xec56,
        );
        assert_eq!(insns[0].flow, Flow::Next);
        assert_eq!(insns[5].flow, Flow::Jump(0xf5c6));
    }

    #[test]
    fn frames() {
        let decoder = Decoder::default();
        // subi r0, 8; stw r15, (r0, 0)
        assert!(decoder.starts_frame(&[0x70, 0x24, 0x00, 0x9f]));
        assert!(!decoder.starts_frame(&[0x00, 0x12, 0xcf, 0x00]));
        // A far branch.
        assert!(!decoder.starts_frame(&[0x70, 0x24, 0x00, 0x9f, 0x00, 0xf8, 0x03, 0x71]));
    }

    /// `movi r2, 5` is an integer; `jmp r2` then goes to it, and `rts`
    /// returns.
    #[test]
    fn immediates_are_values() {
        let insns = run(&[0x6052, 0x00c2], 0x1000);
        assert_eq!(insns[0].note, Note::Value { reg: 2, value: 5 });
        assert_eq!(insns[1].flow, Flow::Jump(5));
        assert_eq!(run(&[0x00cf], 0x1000)[0].flow, Flow::Return);
    }

    /// A `jmpi` or `jsri` whose pool word is not in the bytes goes through
    /// the slot; the sweep steps over the word either way.
    #[test]
    fn pool_slots() {
        // jmpi [1 word on], at 0x1000: the slot at 0x1004.
        assert_eq!(run(&[0x7001], 0x1000)[0].flow, Flow::JumpSlot(0x1004));
        // jsri, the same slot.
        assert_eq!(run(&[0x7f01], 0x1000)[0].flow, Flow::CallSlot(0x1004));
        let decoder = Decoder::default();
        assert_eq!(
            decoder.literal(&0x7f01_u16.to_le_bytes(), 0x1000),
            Some(0x1004)
        );
        assert_eq!(decoder.literal(&0x00cf_u16.to_le_bytes(), 0x1000), None);
    }

    /// A call forgets the registers it may change (`r2`), not the others
    /// (`r8`).
    #[test]
    fn calls_forget_volatile_registers() {
        // movi r2, 5; movi r8, 6; jsr r12; jmp r2
        let insns = run(&[0x6052, 0x6068, 0x00dc, 0x00c2], 0x1000);
        assert_eq!(insns[2].flow, Flow::CallRegister(12));
        assert_eq!(insns[3].flow, Flow::JumpRegister(2));
        // movi r2, 5; movi r8, 6; jsr r12; jmp r8
        let insns = run(&[0x6052, 0x6068, 0x00dc, 0x00c8], 0x1000);
        assert_eq!(insns[3].flow, Flow::Jump(6));
    }
}
