//! Tensilica Xtensa (little-endian, windowed ABI): control flow, and the
//! constants calls and jumps through registers need. Instructions are two
//! or three bytes, byte-aligned. A density option adds the `.n` narrow
//! forms (`l32i.n`, `movi.n`, `ret.n`).
//!
//! Constants come from a literal pool of 4-byte words placed *before* the
//! code that reads them: `l32r at, label` loads the word at a negative,
//! word-aligned offset. The pool holds callees' addresses, jump tables and
//! data pointers, so an `l32r` of a function's address followed by `callx`
//! is a call there. Direct calls are PC-relative `call0`/`call4`/`call8`/
//! `call12`; `j` jumps, `jx` jumps through a register, and functions in the
//! windowed ABI open with `entry` and end with `retw`/`retw.n`.

use crate::isa::{Decode, Flow, Insn, Mem, Note, relative, sext, uint};

/// The decoder, and which of the sixteen address registers hold a fixed
/// value (an immediate, or a literal-pool word a later pass reads).
#[derive(Clone, Debug, Default)]
pub(crate) struct Decoder {
    /// Bit `n` set: register `n` holds a fixed value.
    known: u16,
}

/// The stack pointer.
const SP: u32 = 1;

/// Addresses are 32 bits.
const MASK: u64 = 0xffff_ffff;

/// The wide `nop`, the narrow `nop.n`, and `or a0, a0, a0`, which
/// assemblers emit as a `nop` too.
const NOPS: [u32; 3] = [0x00_20f0, 0xf03d, 0x20_0000];

/// Bytes of an instruction whose low nibble is `op0`: two for the narrow
/// forms (`op0` 8 to 13), three otherwise (`op0` 14 and 15 are reserved,
/// and decode as invalid).
const fn length(op0: u32) -> usize {
    if op0 >= 0x8 { 2 } else { 3 }
}

/// The instruction word at the start of `bytes`, and its length.
fn word(bytes: &[u8]) -> Option<(u32, u32)> {
    let len = length(u32::from(*bytes.first()?) & 0xf);
    let instr = u32::try_from(uint(bytes.get(..len)?, false)?).ok()?;
    Some((instr, u32::try_from(len).ok()?))
}

/// The word-aligned address an `l32r` at `addr` loads from: its 16-bit
/// field is the low half of a negative word count from the next word.
fn l32r_address(instr: u32, addr: u64) -> u64 {
    let count = 0xffff_0000 | (instr >> 8) & 0xffff;
    relative(addr.wrapping_add(3) & !3, count, 32, 4) & MASK
}

/// A word load `at = [as + disp]`, which a jump table or a GOT read
/// resolves once the base register holds a fixed address.
fn load(dest: u32, base: Option<u32>, disp: u64) -> Note {
    Note::Fetch {
        reg: dest,
        mem: Mem {
            base,
            index: None,
            scale: 1,
            disp,
        },
        size: 4,
        signed: false,
    }
}

/// The signed eight-bit offset in bits 16..24.
fn imm8(instr: u32) -> i64 {
    sext((instr >> 16) & 0xff, 8)
}

/// A branch, jump or call target: `addr + 4 + offset`.
fn target(addr: u64, offset: i64) -> u64 {
    addr.wrapping_add(4).wrapping_add_signed(offset) & MASK
}

/// `value` as the register holds it.
fn constant(reg: u32, value: i64) -> Note {
    Note::Value {
        reg,
        value: value.cast_unsigned() & MASK,
    }
}

impl Decoder {
    fn holds(&self, reg: u32) -> bool {
        self.known >> reg & 1 != 0
    }

    fn set(&mut self, reg: u32, known: bool) {
        let bit = 1_u16.checked_shl(reg).unwrap_or(0);
        if known {
            self.known |= bit;
        } else {
            self.known &= !bit;
        }
    }
}

impl Decode for Decoder {
    fn decode(&mut self, bytes: &[u8], addr: u64) -> Insn {
        let Some((instr, len)) = word(bytes) else {
            return Insn::new(2, Flow::Invalid);
        };
        let op0 = instr & 0xf;
        let t = (instr >> 4) & 0xf;
        let s = (instr >> 8) & 0xf;
        let r = (instr >> 12) & 0xf;
        let mut note = Note::None;
        // The register the instruction overwrites with a value not tracked.
        let mut written: Option<u32> = None;
        let flow = match op0 {
            // ill: GCC's trap after a call that never returns (`_start`'s
            // `callx4 __libc_start_main`).
            0x0 if instr == 0 => Flow::Stop,
            // QRST with op1 and op2 zero: ST0, by the r field.
            0x0 if instr >> 16 == 0 => match r {
                // SNM0: returns, and jumps and calls through a register.
                0 => match t {
                    0x8 | 0x9 => Flow::Return,
                    0xa => Flow::JumpRegister(s),
                    0xc..=0xf => Flow::CallRegister(s),
                    _ => Flow::Next,
                },
                // movsp at, as; rsil at, level: write t.
                1 | 6 => {
                    written = Some(t);
                    Flow::Next
                }
                // The syncs (nop, memw, isync, ...), the returns from
                // exceptions, break, syscall, waiti and the boolean
                // reductions write no address register.
                _ => Flow::Next,
            },
            // Other QRST: writes the r register (ALU), or nothing.
            0x0 => {
                written = Some(r);
                Flow::Next
            }
            // L32R: load a word from the literal pool before it.
            0x1 => {
                note = load(t, None, l32r_address(instr, addr));
                self.set(t, true);
                Flow::Next
            }
            // LSAI: loads, stores and the immediate arithmetic, by the r field.
            0x2 => {
                match r {
                    // movi at, imm12
                    0xa => {
                        note = constant(t, sext(s << 8 | (instr >> 16) & 0xff, 12));
                        self.set(t, true);
                    }
                    // addi / addmi at, as, imm8: tracked only off a known base.
                    0xc | 0xd => {
                        let imm = if r == 0xd {
                            imm8(instr) << 8
                        } else {
                            imm8(instr)
                        };
                        if self.holds(s) && s != SP {
                            note = Note::Offset {
                                reg: t,
                                src: s,
                                imm: imm.cast_unsigned() & MASK,
                            };
                            self.set(t, true);
                        } else {
                            written = Some(t);
                        }
                    }
                    // l32i at, as, imm8 * 4: a word load, which a jump table
                    // or a GOT read goes through.
                    0x2 => {
                        note = load(t, Some(s), u64::from((instr >> 16) & 0xff) << 2);
                        self.set(t, false);
                    }
                    // The byte and half-word loads write t.
                    0x0 | 0x1 | 0x9 | 0xb => written = Some(t),
                    _ => {}
                }
                Flow::Next
            }
            // CALLN: call0/call4/call8/call12 (the n field is the window), to
            // a word-aligned target.
            0x5 => Flow::Call(relative((addr & !3).wrapping_add(4), instr >> 6, 18, 4) & MASK),
            // SI: j, and the twelve- and eight-bit branches.
            0x6 => match (instr >> 4) & 3 {
                0 => Flow::Jump(target(addr, sext(instr >> 6, 18))),
                // BRI12: beqz / bnez / bltz / bgez.
                1 => Flow::Branch(target(addr, sext(instr >> 12, 12))),
                // BRI8: the immediate branches (beqi, bnei, blti, bgei).
                2 => Flow::Branch(target(addr, imm8(instr))),
                // n == 3, m == 0: entry (a frame).
                _ if (instr >> 6) & 3 == 0 => Flow::Next,
                // m == 1: bf/bt (signed offset), and loop/loopnez/loopgtz,
                // whose unsigned offset names the loop's end: loopnez and
                // loopgtz skip there, loop falls into its body.
                _ if (instr >> 6) & 3 == 1 => match r {
                    0 | 1 => Flow::Branch(target(addr, imm8(instr))),
                    0x8 => Flow::Next,
                    0x9 | 0xa => Flow::Branch(target(addr, i64::from((instr >> 16) & 0xff))),
                    _ => Flow::Invalid,
                },
                // m == 2, 3: bltui / bgeui.
                _ => Flow::Branch(target(addr, imm8(instr))),
            },
            // B: the register-register branches (beq, bne, blt, ...).
            0x7 => Flow::Branch(target(addr, imm8(instr))),
            // L32I.N: narrow word load (base s, displacement r * 4).
            0x8 => {
                note = load(t, Some(s), u64::from(r) << 2);
                self.set(t, false);
                Flow::Next
            }
            0x9 => Flow::Next,
            // ADD.N / ADDI.N: narrow, write the r register.
            0xa | 0xb => {
                written = Some(r);
                Flow::Next
            }
            // ST2: movi.n as, imm7 (t below 8), or beqz.n / bnez.n as, imm6
            // (t 8 and up; the offset is unsigned, t's low bits over r).
            0xc => {
                if t & 8 != 0 {
                    Flow::Branch(target(addr, i64::from((t & 3) << 4 | r)))
                } else {
                    // imm7 runs from -32 to 95.
                    let imm = i64::from((t & 7) << 4 | r);
                    note = constant(
                        s,
                        if imm >= 96 {
                            imm.wrapping_sub(128)
                        } else {
                            imm
                        },
                    );
                    self.set(s, true);
                    Flow::Next
                }
            }
            // ST3: mov.n (writes t), ret.n / retw.n, or nop.n / break.n.
            0xd => {
                if r == 0xf {
                    match t {
                        0 | 1 => Flow::Return,
                        // ill.n
                        6 => Flow::Stop,
                        _ => Flow::Next,
                    }
                } else {
                    written = Some(t);
                    Flow::Next
                }
            }
            // Reserved (or FLIX bundles, which no configuration seen uses).
            _ => Flow::Invalid,
        };
        if let Some(reg) = written {
            self.set(reg, false);
            note = Note::Write(reg);
        }
        let mut insn = Insn::new(len, flow);
        insn.note = note;
        insn.pad = NOPS.contains(&instr);
        insn
    }

    fn reset(&mut self) {
        self.known = 0;
    }

    /// A windowed call rotates the register file: the callee's writes land
    /// above the caller's live registers, but nothing the decoder tracked
    /// survives a call it cannot see through.
    fn call(&mut self) {
        self.reset();
    }

    /// Whether `bytes` open a frame: the windowed ABI's `entry`, which
    /// lowers the stack pointer and saves the window.
    fn starts_frame(&self, bytes: &[u8]) -> bool {
        // entry: op0 6, n 3, m 0, s == sp.
        word(bytes).is_some_and(|(instr, _)| instr & 0xff == 0x36 && (instr >> 8) & 0xf == SP)
    }

    /// The literal-pool word an `l32r` at `addr` reads, for a sweep to step
    /// over as data.
    fn literal(&self, bytes: &[u8], addr: u64) -> Option<u64> {
        let (instr, _) = word(bytes)?;
        (instr & 0xf == 0x1).then(|| l32r_address(instr, addr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(bytes: &[u8], addr: u64) -> Vec<Insn> {
        let mut decoder = Decoder::default();
        let mut out = Vec::new();
        let mut at = 0;
        while at < bytes.len() {
            let insn = decoder.decode(&bytes[at..], addr + at as u64);
            at += insn.len as usize;
            out.push(insn);
        }
        out
    }

    #[test]
    fn calls_and_returns() {
        // call8 .-0x94 ; callx8 a8 ; retw.n
        let insns = run(&[0xa5, 0xf6, 0xff, 0xe0, 0x08, 0x00, 0x1d, 0xf0], 0x401006);
        assert_eq!(insns[0].flow, Flow::Call(0x400f70));
        assert_eq!(insns[1].flow, Flow::CallRegister(8));
        assert_eq!(insns[2].flow, Flow::Return);
    }

    #[test]
    fn jumps_and_branches() {
        // j .+0x1f
        assert_eq!(
            run(&[0xc6, 0x06, 0x00], 0x400fdf)[0].flow,
            Flow::Jump(0x400ffe)
        );
        // bnez a2, .+0x50
        assert_eq!(
            run(&[0x56, 0xc2, 0x04], 0x400fc9)[0].flow,
            Flow::Branch(0x401019)
        );
        // beq a8, a10, .+0xb
        assert_eq!(
            run(&[0xa7, 0x18, 0x07], 0x400f79)[0].flow,
            Flow::Branch(0x400f84)
        );
        // jx a8
        assert_eq!(
            run(&[0xa0, 0x08, 0x00], 0x400c60)[0].flow,
            Flow::JumpRegister(8)
        );
    }

    #[test]
    fn signed_and_narrow_branches() {
        // bnei a2, 1, .-0x10 (imm8 0xf0: a backward branch)
        assert_eq!(
            run(&[0x66, 0x12, 0xf0], 0x401000)[0].flow,
            Flow::Branch(0x400ff4)
        );
        // bne a2, a3, .-0x4
        assert_eq!(
            run(&[0x37, 0x92, 0xfc], 0x401000)[0].flow,
            Flow::Branch(0x401000)
        );
        // beqz.n a2, .+0x24 (imm6 0x20: t 0b1010, r 0)
        assert_eq!(run(&[0xac, 0x02], 0x401000)[0].flow, Flow::Branch(0x401024));
        // movi.n a2, -1 (imm7 0x7f: t 0b0111, r 0xf) is no branch.
        let insns = run(&[0x7c, 0xf2], 0x401000);
        assert_eq!(insns[0].flow, Flow::Next);
        assert_eq!(
            insns[0].note,
            Note::Value {
                reg: 2,
                value: 0xffff_ffff
            }
        );
        // call0 .+0x8
        assert_eq!(
            run(&[0x45, 0x00, 0x00], 0x401000)[0].flow,
            Flow::Call(0x401008)
        );
    }

    #[test]
    fn literal_load() {
        // l32r a6, . 0x400f38 at 0x400f4a
        let insns = run(&[0x61, 0xfb, 0xff], 0x400f4a);
        assert_eq!(insns[0].note, load(6, None, 0x400f38));
        let decoder = Decoder::default();
        assert_eq!(
            decoder.literal(&[0x61, 0xfb, 0xff], 0x400f4a),
            Some(0x400f38)
        );
        assert_eq!(decoder.literal(&[0x36, 0x41, 0x00], 0x400f4a), None);
    }

    /// The wide `nop` and the other ST0 forms that write no address
    /// register (`memw`, `isync`, `break`) are no writes, and `nop` pads.
    #[test]
    fn syncs_write_nothing() {
        // nop; memw; isync; break 1, 15
        for word in [0x00_20f0_u32, 0x00_20c0, 0x00_2000, 0x00_41f0] {
            let insn = run(&word.to_le_bytes()[..3], 0x401000)[0];
            assert_eq!(
                (insn.flow, insn.note),
                (Flow::Next, Note::None),
                "{word:#x}"
            );
            assert_eq!(insn.pad, word == 0x00_20f0);
        }
        // rsil a2, 1 writes a2.
        assert_eq!(run(&[0x20, 0x61, 0x00], 0x401000)[0].note, Note::Write(2));
    }

    #[test]
    fn frame() {
        let decoder = Decoder::default();
        // entry a1, 0x20
        assert!(decoder.starts_frame(&[0x36, 0x41, 0x00]));
        // retw.n is no frame.
        assert!(!decoder.starts_frame(&[0x1d, 0xf0]));
    }
}
