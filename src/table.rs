//! Jump tables: what the instructions before an indirect jump computed into
//! its target.
//!
//! Compilers lower a dense `switch` to a load from a table indexed by the
//! case value, after a `cmp` that bounds the value:
//!
//! ```text
//! jmp [table + eax*4]                                  absolute
//! lea rdx, [table]; movsxd rax, [rdx + rax*4]
//!     add rax, rdx; jmp rax                            table-relative
//! lea r8, [image]; mov ecx, [r8 + rax*4 + rva]
//!     add rcx, r8; jmp rcx                             image-relative
//! ```
//!
//! A sparse `switch` first maps case values to entries through a byte table
//! (`movzx eax, byte [bytes + eax]`). A [`Tracker`] follows the few register
//! values these sequences build and nothing else: an instruction it does not
//! model forgets the register it writes.

use crate::decode::{Flow, Mem, Memory, Note};

/// Register values along one path through a function.
#[derive(Clone, Default)]
pub(crate) struct Tracker {
    values: Vec<(u32, Value)>,
    /// The tag the next copy of an unknown value gets.
    tags: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Value {
    /// Not known, but the same as in every register with this tag: a copy
    /// of a register shares whatever later bounds the original.
    Unknown(u32),
    /// A case value: compared with `n - 1`, so below `n` if in range.
    Case(u64),
    /// A fixed address.
    Address(u64),
    /// An entry of a table.
    Entry(Table),
}

/// A table of `size`-byte entries, `scale` bytes apart from `addr`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Table {
    addr: u64,
    scale: u8,
    size: u8,
    signed: bool,
    /// Added to each entry; `None` for a table of absolute addresses.
    base: Option<u64>,
    cases: Cases,
}

/// Which entries the case values select.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cases {
    /// Entries `0..n`.
    First(u64),
    /// Entry `bytes[v]` for each case value `v` in `0..n`.
    Mapped { bytes: u64, n: u64 },
    /// No bound was seen.
    Unbounded,
}

impl Tracker {
    /// Forget what a call may have changed. A fixed address stays: a
    /// compiler keeps one across a call only in a register the callee saves,
    /// and rewrites any other before reading it.
    pub(crate) fn call(&mut self) {
        self.values
            .retain(|(_, value)| matches!(value, Value::Address(_)));
    }

    pub(crate) fn note(&mut self, note: Note) {
        let (reg, value) = match note {
            Note::None => return,
            Note::Compare { reg, imm } => {
                let case = Value::Case(imm.saturating_add(1));
                if let Some(same @ Value::Unknown(_)) = self.get(reg) {
                    for (_, value) in &mut self.values {
                        if *value == same {
                            *value = case;
                        }
                    }
                }
                (reg, Some(case))
            }
            Note::Address { reg, addr } => (reg, Some(Value::Address(addr))),
            Note::Load {
                reg,
                mem,
                size,
                signed,
            } => (reg, self.load(mem, size, signed).map(Value::Entry)),
            Note::Copy { reg, src } => (reg, Some(self.copy(src))),
            Note::Add { reg, src } => (reg, self.add(reg, src)),
            Note::Write(reg) => (reg, None),
        };
        self.values.retain(|&(held, _)| held != reg);
        if let Some(value) = value {
            self.values.push((reg, value));
        }
    }

    /// The value in `src`, tagging it first when unknown.
    fn copy(&mut self, src: u32) -> Value {
        if let Some(value) = self.get(src) {
            return value;
        }
        let tag = Value::Unknown(self.tags);
        self.tags = self.tags.wrapping_add(1);
        self.values.push((src, tag));
        tag
    }

    fn get(&self, reg: u32) -> Option<Value> {
        self.values
            .iter()
            .find_map(|&(held, value)| (held == reg).then_some(value))
    }

    /// The fixed address in `reg`; zero for no register at all.
    fn address(&self, reg: Option<u32>) -> Option<u64> {
        match reg.map(|reg| self.get(reg)) {
            None => Some(0),
            Some(Some(Value::Address(addr))) => Some(addr),
            Some(_) => None,
        }
    }

    /// `reg += src`: a 32-bit table entry plus a fixed address is a target.
    fn add(&self, reg: u32, src: u32) -> Option<Value> {
        let (entry, base) = match (self.get(reg)?, self.get(src)?) {
            (Value::Entry(table), Value::Address(base))
            | (Value::Address(base), Value::Entry(table)) => (table, base),
            _ => return None,
        };
        (entry.base.is_none() && entry.size == 4).then_some(Value::Entry(Table {
            base: Some(base),
            ..entry
        }))
    }

    /// The table a load of `size` bytes from `mem` reads: one register of
    /// the operand holds a fixed address or is absent, and the other holds
    /// the case value.
    fn load(&self, mem: Mem, size: u8, signed: bool) -> Option<Table> {
        let (offset, index, scale) = match (mem.base, mem.index) {
            (base, Some(index)) if self.address(base).is_some() => {
                (self.address(base)?, index, mem.scale)
            }
            // `[value + address]`: the encoding put the address second.
            (Some(base), Some(index)) if mem.scale == 1 => (self.address(Some(index))?, base, 1),
            (Some(base), None) => (0, base, 1),
            (_, Some(_)) => return None,
            (None, None) => return None,
        };
        if !matches!(size, 1 | 2 | 4 | 8) || !matches!(scale, 1 | 2 | 4 | 8) {
            return None;
        }
        let cases = match self.get(index) {
            Some(Value::Case(n)) => Cases::First(n),
            Some(Value::Entry(map)) if map.is_byte_map() => match map.cases {
                Cases::First(n) => Cases::Mapped { bytes: map.addr, n },
                _ => return None,
            },
            _ => Cases::Unbounded,
        };
        Some(Table {
            addr: offset.wrapping_add(mem.disp),
            scale,
            size,
            signed,
            base: None,
            cases,
        })
    }

    /// The table an indirect jump on a machine with `width`-byte addresses
    /// takes its target from.
    pub(crate) fn jump(&self, flow: Flow, width: u8) -> Option<Table> {
        match flow {
            Flow::JumpMemory(mem) => self.load(mem, width, false),
            Flow::JumpRegister(reg) => match self.get(reg)? {
                Value::Entry(table) if table.base.is_some() || table.size == width => Some(table),
                _ => None,
            },
            _ => None,
        }
    }
}

impl Table {
    /// One-byte entries packed together: a map from case values to entries
    /// of another table.
    fn is_byte_map(&self) -> bool {
        self.size == 1 && self.scale == 1 && self.base.is_none()
    }

    /// The case targets in case-value order, up to `most` and up to the
    /// first that is not code: past it the table has ended, or was never
    /// one. Like rizin, a target counts once per case value that selects it.
    pub(crate) fn targets(&self, memory: &Memory<'_>, most: usize) -> Vec<u64> {
        let most = u64::try_from(most).unwrap_or(u64::MAX);
        let (n, map) = match self.cases {
            Cases::First(n) => (n, None),
            Cases::Mapped { bytes, n } => (n, Some(bytes)),
            // Without a bound, only a table of absolute addresses stands out
            // from the data after it.
            Cases::Unbounded if self.base.is_none() && self.size == self.scale => (most, None),
            Cases::Unbounded => (0, None),
        };
        (0..n.min(most))
            .map_while(|value| {
                let slot = match map {
                    Some(bytes) => memory.read(bytes.wrapping_add(value), 1)?,
                    None => value,
                };
                let at = self
                    .addr
                    .wrapping_add(slot.wrapping_mul(u64::from(self.scale)));
                let entry = memory.read(at, self.size)?;
                let entry = if self.signed {
                    sign_extend(entry, self.size)
                } else {
                    entry
                };
                let target = self.base.unwrap_or(0).wrapping_add(entry);
                memory.is_code(target).then_some(target)
            })
            .collect()
    }
}

/// `value`, read as a signed `size`-byte integer, widened to 64 bits.
fn sign_extend(value: u64, size: u8) -> u64 {
    let shift = 64 - 8 * u32::from(size.clamp(1, 8));
    ((value << shift).cast_signed() >> shift).cast_unsigned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Segment;

    const EAX: u32 = 1;
    const ECX: u32 = 2;
    const R8: u32 = 3;

    fn mem(base: Option<u32>, index: Option<u32>, scale: u8, disp: u64) -> Mem {
        Mem {
            base,
            index,
            scale,
            disp,
        }
    }

    fn words(values: &[u32]) -> Vec<u8> {
        values
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect()
    }

    #[test]
    fn absolute_bounded_by_compare() {
        let mut tracker = Tracker::default();
        tracker.note(Note::Compare { reg: EAX, imm: 2 });
        let table = tracker.jump(Flow::JumpMemory(mem(None, Some(EAX), 4, 0x2000)), 4);
        let code = [0_u8; 0x10];
        let data = words(&[0x1000, 0x1004, 0x1008, 0x100c]);
        let memory = Memory::new(&[
            Segment {
                addr: 0x1000,
                bytes: &code,
                executable: true,
            },
            Segment {
                addr: 0x2000,
                bytes: &data,
                executable: false,
            },
        ]);
        // `cmp eax, 2` admits three cases; the fourth entry is not read.
        let targets = table.map(|table| table.targets(&memory, 512));
        assert_eq!(targets, Some(vec![0x1000, 0x1004, 0x1008]));
    }

    #[test]
    fn absolute_unbounded_ends_at_data() {
        let tracker = Tracker::default();
        let table = tracker.jump(Flow::JumpMemory(mem(None, Some(EAX), 4, 0x2000)), 4);
        let code = [0_u8; 0x10];
        let data = words(&[0x1000, 0x1004, 0x7777]);
        let memory = Memory::new(&[
            Segment {
                addr: 0x1000,
                bytes: &code,
                executable: true,
            },
            Segment {
                addr: 0x2000,
                bytes: &data,
                executable: false,
            },
        ]);
        let targets = table.map(|table| table.targets(&memory, 512));
        assert_eq!(targets, Some(vec![0x1000, 0x1004]));
    }

    #[test]
    fn image_relative_through_a_byte_map() {
        let mut tracker = Tracker::default();
        tracker.note(Note::Compare { reg: EAX, imm: 3 });
        tracker.note(Note::Address {
            reg: R8,
            addr: 0x1_0000,
        });
        let map = mem(Some(R8), Some(EAX), 1, 0x2100);
        tracker.note(Note::Load {
            reg: EAX,
            mem: map,
            size: 1,
            signed: false,
        });
        let entries = mem(Some(R8), Some(EAX), 4, 0x2000);
        tracker.note(Note::Load {
            reg: ECX,
            mem: entries,
            size: 4,
            signed: false,
        });
        tracker.note(Note::Add { reg: ECX, src: R8 });
        let table = tracker.jump(Flow::JumpRegister(ECX), 8);

        let code = [0_u8; 0x10];
        let mut data = words(&[0x1000, 0x1008]);
        data.resize(0x100, 0);
        data.extend_from_slice(&[1, 0, 1, 1]);
        let memory = Memory::new(&[
            Segment {
                addr: 0x1_1000,
                bytes: &code,
                executable: true,
            },
            Segment {
                addr: 0x1_2000,
                bytes: &data,
                executable: false,
            },
        ]);
        let targets = table.map(|table| table.targets(&memory, 512));
        assert_eq!(targets, Some(vec![0x1_1008, 0x1_1000, 0x1_1008, 0x1_1008]));
    }

    #[test]
    fn table_relative_signed() {
        let mut tracker = Tracker::default();
        tracker.note(Note::Compare { reg: EAX, imm: 1 });
        tracker.note(Note::Address {
            reg: R8,
            addr: 0x2000,
        });
        let entries = mem(Some(R8), Some(EAX), 4, 0);
        tracker.note(Note::Load {
            reg: EAX,
            mem: entries,
            size: 4,
            signed: true,
        });
        tracker.note(Note::Add { reg: EAX, src: R8 });
        let table = tracker.jump(Flow::JumpRegister(EAX), 8);
        let code = [0_u8; 0x10];
        let data = words(&[(-0x1000_i32).cast_unsigned(), (-0xff8_i32).cast_unsigned()]);
        let memory = Memory::new(&[
            Segment {
                addr: 0x1000,
                bytes: &code,
                executable: true,
            },
            Segment {
                addr: 0x2000,
                bytes: &data,
                executable: false,
            },
        ]);
        let targets = table.map(|table| table.targets(&memory, 512));
        assert_eq!(targets, Some(vec![0x1000, 0x1008]));
    }

    #[test]
    fn writes_forget() {
        let mut tracker = Tracker::default();
        tracker.note(Note::Compare { reg: EAX, imm: 3 });
        tracker.note(Note::Write(EAX));
        let table = tracker.jump(Flow::JumpMemory(mem(None, Some(EAX), 4, 0x2000)), 4);
        assert_eq!(table.map(|table| table.cases), Some(Cases::Unbounded));

        tracker.note(Note::Address {
            reg: R8,
            addr: 0x1_0000,
        });
        tracker.note(Note::Write(R8));
        let entries = mem(Some(R8), Some(EAX), 4, 0);
        tracker.note(Note::Load {
            reg: ECX,
            mem: entries,
            size: 4,
            signed: true,
        });
        assert_eq!(tracker.jump(Flow::JumpRegister(ECX), 8), None);
    }

    #[test]
    fn a_copy_shares_a_later_bound() {
        // mov r11d, edx; cmp edx, 11; jmp [r11*4 + 0x2000]
        let (edx, r11) = (4, 5);
        let mut tracker = Tracker::default();
        tracker.note(Note::Copy { reg: r11, src: edx });
        tracker.note(Note::Compare { reg: edx, imm: 11 });
        let table = tracker.jump(Flow::JumpMemory(mem(None, Some(r11), 4, 0x2000)), 4);
        assert_eq!(table.map(|table| table.cases), Some(Cases::First(12)));
    }

    #[test]
    fn sign_extension() {
        assert_eq!(sign_extend(0xffff_fff0, 4), (-16_i64).cast_unsigned());
        assert_eq!(sign_extend(0x10, 4), 0x10);
        assert_eq!(sign_extend(0x80, 1), (-128_i64).cast_unsigned());
        assert_eq!(sign_extend(u64::MAX, 8), u64::MAX);
    }
}
