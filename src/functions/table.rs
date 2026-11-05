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
//! (`movzx eax, byte [bytes + eax]`). Position-independent 32-bit x86 code
//! finds its tables from the address a call pushes (`call thunk; add ebx,
//! offset`), and A64 code scales small entries as it adds them
//! (`ldrb w1, [x0, w1, uxtw]; adr x2, base; add x1, x2, w1, sxtb #2`). A
//! [`Tracker`] follows the few register values these sequences build and
//! nothing else: an instruction it does not model forgets the registers it
//! writes.

use crate::isa::{Extend, Flow, Mem, Memory, Note, sext};

/// Register values along one path through a function.
#[derive(Clone)]
pub(crate) struct Tracker {
    values: Vec<(u32, Value)>,
    /// The tag the next copy of an unknown value gets.
    tags: u32,
    /// The fixed address on top of the stack, when the last instruction
    /// pushed one.
    pushed: Option<u64>,
    /// Bytes in an address: arithmetic on addresses wraps at this width.
    width: u8,
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
    /// Added to each entry, shifted left by `shift`; `None` for a table of
    /// absolute addresses.
    base: Option<u64>,
    shift: u8,
    cases: Cases,
    /// The address width's mask, which targets wrap at.
    mask: u64,
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
    /// A tracker for a machine with `width`-byte addresses, knowing nothing.
    pub(crate) fn new(width: u8) -> Self {
        Self {
            values: Vec::new(),
            tags: 0,
            pushed: None,
            width,
        }
    }

    fn mask(&self) -> u64 {
        match self.width {
            1..=7 => (1_u64 << (8 * u32::from(self.width))).wrapping_sub(1),
            _ => u64::MAX,
        }
    }

    /// Forget what a call may have changed, but for the registers in
    /// `kept`, a mask of those the callee leaves as they were. A fixed
    /// address stays: a compiler keeps one across a call only in a register
    /// the callee saves, and rewrites any other before reading it.
    pub(crate) fn call(&mut self, kept: u32) {
        self.pushed = None;
        self.values.retain(|&(reg, value)| {
            matches!(value, Value::Address(_)) || (reg < 32 && kept >> reg & 1 != 0)
        });
    }

    /// The fixed address in `reg`.
    pub(crate) fn held(&self, reg: u32) -> Option<u64> {
        match self.get(reg)? {
            Value::Address(addr) => Some(addr),
            _ => None,
        }
    }

    /// The fixed address the last instruction pushed.
    pub(crate) fn pushed(&self) -> Option<u64> {
        self.pushed
    }

    pub(crate) fn note(&mut self, note: Note) {
        // Only the very next instruction reads what a push left on top.
        let pushed = self.pushed.take();
        let (reg, value) = match note {
            Note::None => return,
            Note::Push(addr) => {
                self.pushed = Some(addr & self.mask());
                return;
            }
            Note::PushRegister(reg) => {
                self.pushed = self.held(reg);
                return;
            }
            Note::Pop(reg) => (reg, pushed.map(Value::Address)),
            Note::Clobber(regs) => {
                self.values
                    .retain(|&(held, _)| held >= 32 || regs & (1 << held) == 0);
                return;
            }
            Note::Compare { reg, imm } => {
                let case = Value::Case(imm.saturating_add(1));
                // Copies share the bound: of an unknown value, or of a value
                // loaded from memory (`ldub [%l1+8], %g1; and %g1, 0xff,
                // %g2; cmp %g2, n`).
                if let Some(same @ (Value::Unknown(_) | Value::Entry(_))) = self.get(reg) {
                    for (_, value) in &mut self.values {
                        if *value == same {
                            *value = case;
                        }
                    }
                }
                (reg, Some(case))
            }
            Note::Address { reg, addr } | Note::Value { reg, value: addr } => {
                (reg, Some(Value::Address(addr)))
            }
            // Unresolved: the walk replaces those it can read.
            Note::Fetch { reg, .. } => (reg, None),
            Note::Load {
                reg,
                mem,
                size,
                signed,
            } => (reg, self.load(mem, size, signed).map(Value::Entry)),
            Note::Copy { reg, src } => (reg, Some(self.copy(src))),
            // A constant added to an entry of absolute offsets makes them
            // relative to it (MIPS adds `$gp`; ARC adds `pcl` to halfword
            // and byte entries).
            Note::Offset { reg, src, imm } => (
                reg,
                match self.get(src) {
                    Some(Value::Address(addr)) => {
                        Some(Value::Address(addr.wrapping_add(imm) & self.mask()))
                    }
                    Some(Value::Entry(table)) if table.base.is_none() => {
                        Some(Value::Entry(Table {
                            base: Some(imm & self.mask()),
                            ..table
                        }))
                    }
                    _ => None,
                },
            ),
            Note::Add {
                reg,
                base,
                index,
                shift,
                extend,
            } => (reg, self.add(base, index, shift, extend)),
            Note::Sub { reg, base, index } => (
                reg,
                match (self.get(base), self.get(index)) {
                    (Some(Value::Address(a)), Some(Value::Address(b))) => {
                        Some(Value::Address(a.wrapping_sub(b) & self.mask()))
                    }
                    _ => None,
                },
            ),
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

    /// The fixed address `mem` names, without an index.
    pub(crate) fn fixed(&self, mem: Mem) -> Option<u64> {
        if mem.index.is_some() {
            return None;
        }
        Some(self.address(mem.base)?.wrapping_add(mem.disp) & self.mask())
    }

    /// The fixed address in `reg`; zero for no register at all.
    fn address(&self, reg: Option<u32>) -> Option<u64> {
        match reg.map(|reg| self.get(reg)) {
            None => Some(0),
            Some(Some(Value::Address(addr))) => Some(addr),
            Some(_) => None,
        }
    }

    /// `base + (extend(index) << shift)`: a fixed address plus a table entry
    /// is a target. Unshifted, either operand may be the address.
    fn add(&self, base: u32, index: u32, shift: u8, extend: Extend) -> Option<Value> {
        let (table, addr) = match (self.get(base)?, self.get(index)?) {
            // Two addresses: an offset added to the PC (Sun Studio on SPARC).
            (Value::Address(a), Value::Address(b)) if shift == 0 && extend == Extend::None => {
                return Some(Value::Address(a.wrapping_add(b) & self.mask()));
            }
            (Value::Address(addr), Value::Entry(table)) => (table, addr),
            (Value::Entry(table), Value::Address(addr)) if shift == 0 && extend == Extend::None => {
                (table, addr)
            }
            _ => return None,
        };
        if table.base.is_some() || !matches!(table.size, 1 | 2 | 4 | 8) || shift > 4 {
            return None;
        }
        Some(Value::Entry(Table {
            base: Some(addr),
            shift,
            signed: extended(table.size, table.signed, extend)?,
            ..table
        }))
    }

    /// The table a load of `size` bytes from `mem` reads: one register of
    /// the operand holds a fixed address or is absent, and the other holds
    /// the case value.
    fn load(&self, mem: Mem, size: u8, signed: bool) -> Option<Table> {
        let (offset, index, scale) = match (mem.base, mem.index) {
            (base, Some(index)) => match self.address(base) {
                Some(offset) => (offset, index, mem.scale),
                // `[value + address]`: the encoding put the address second.
                None if mem.scale == 1 => (self.address(Some(index))?, base?, 1),
                None => return None,
            },
            (Some(base), None) => (0, base, 1),
            (None, None) => return None,
        };
        if !matches!(size, 1 | 2 | 4 | 8) || !matches!(scale, 1 | 2 | 4 | 8) {
            return None;
        }
        let cases = match self.get(index) {
            Some(Value::Case(n)) => Cases::First(n),
            // One-byte entries packed together: a map from case values to
            // entries of this table.
            Some(Value::Entry(map)) if map.size == 1 && map.scale == 1 && map.base.is_none() => {
                match map.cases {
                    Cases::First(n) => Cases::Mapped { bytes: map.addr, n },
                    _ => return None,
                }
            }
            _ => Cases::Unbounded,
        };
        Some(Table {
            addr: offset.wrapping_add(mem.disp) & self.mask(),
            scale,
            size,
            signed,
            base: None,
            shift: 0,
            cases,
            mask: self.mask(),
        })
    }

    /// The table an indirect jump takes its target from.
    pub(crate) fn jump(&self, flow: Flow) -> Option<Table> {
        match flow {
            Flow::JumpMemory(mem) => self.load(mem, self.width, false),
            Flow::JumpAdd { base, index } => match self.add(base, index, 0, Extend::None)? {
                Value::Entry(table) => Some(table),
                _ => None,
            },
            Flow::JumpTable {
                mem,
                size,
                base,
                shift,
            } => Some(Table {
                size,
                base: Some(base),
                shift,
                ..self.load(mem, size.max(1), false)?
            }),
            // Absolute entries fill the register, or fill it sign-extended
            // (RV64's `lw; jr` in code linked below 2 GiB).
            Flow::JumpRegister(reg) => match self.get(reg)? {
                Value::Entry(table)
                    if table.base.is_some()
                        || table.size == self.width
                        || (table.size == 4 && table.signed) =>
                {
                    Some(table)
                }
                _ => None,
            },
            _ => None,
        }
    }
}

/// Whether a `size`-byte entry, read as `signed`, is signed once `extend`
/// widens it: extending it from its own width decides; extending it from
/// wider keeps it, except that zero-extending a sign-extended entry from
/// less than 64 bits makes a value neither reading gives. `None` when the
/// extension drops some of the entry's bytes.
fn extended(size: u8, signed: bool, extend: Extend) -> Option<bool> {
    match extend {
        Extend::None => Some(signed),
        Extend::Sign(n) | Extend::Zero(n) if n < size => None,
        Extend::Sign(n) => Some(n == size || signed),
        Extend::Zero(n) if n == size => Some(false),
        Extend::Zero(n) if n >= 8 || !signed => Some(signed),
        Extend::Zero(_) => None,
    }
}

impl Table {
    /// Whether a compare bounds the case values.
    pub(crate) fn bounded(&self) -> bool {
        !matches!(self.cases, Cases::Unbounded)
    }

    /// The case targets in case-value order, up to `most` and up to the
    /// first that is not code: past it the table has ended, or was never
    /// one. A target counts once per case value that selects it.
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
                let entry = match self.size {
                    0 => slot,
                    size => memory.read(at, size)?,
                };
                let entry = if self.signed {
                    sign_extend(entry, self.size)
                } else {
                    entry
                };
                let target = self.base.unwrap_or(0).wrapping_add(entry << self.shift) & self.mask;
                memory.is_code(target).then_some(target)
            })
            .collect()
    }
}

/// `value`, read as a signed `size`-byte integer, widened to 64 bits.
pub(super) fn sign_extend(value: u64, size: u8) -> u64 {
    sext(value, 8 * u32::from(size.clamp(1, 8))).cast_unsigned()
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

    /// `reg += src`, as x86 writes it.
    fn add(reg: u32, src: u32) -> Note {
        Note::Add {
            reg,
            base: reg,
            index: src,
            shift: 0,
            extend: Extend::None,
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
        let mut tracker = Tracker::new(4);
        tracker.note(Note::Compare { reg: EAX, imm: 2 });
        let table = tracker.jump(Flow::JumpMemory(mem(None, Some(EAX), 4, 0x2000)));
        let code = [0_u8; 0x10];
        let data = words(&[0x1000, 0x1004, 0x1008, 0x100c]);
        let segments = [
            Segment {
                addr: 0x1000,
                bytes: (&code[..]).into(),
                executable: true,
            },
            Segment {
                addr: 0x2000,
                bytes: (&data[..]).into(),
                executable: false,
            },
        ];
        let memory = Memory::new(&segments);
        // `cmp eax, 2` admits three cases; the fourth entry is not read.
        let targets = table.map(|table| table.targets(&memory, 512));
        assert_eq!(targets, Some(vec![0x1000, 0x1004, 0x1008]));
    }

    #[test]
    fn absolute_unbounded_ends_at_data() {
        let tracker = Tracker::new(4);
        let table = tracker.jump(Flow::JumpMemory(mem(None, Some(EAX), 4, 0x2000)));
        let code = [0_u8; 0x10];
        let data = words(&[0x1000, 0x1004, 0x7777]);
        let segments = [
            Segment {
                addr: 0x1000,
                bytes: (&code[..]).into(),
                executable: true,
            },
            Segment {
                addr: 0x2000,
                bytes: (&data[..]).into(),
                executable: false,
            },
        ];
        let memory = Memory::new(&segments);
        let targets = table.map(|table| table.targets(&memory, 512));
        assert_eq!(targets, Some(vec![0x1000, 0x1004]));
    }

    #[test]
    fn image_relative_through_a_byte_map() {
        let mut tracker = Tracker::new(8);
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
        tracker.note(add(ECX, R8));
        let table = tracker.jump(Flow::JumpRegister(ECX));

        let code = [0_u8; 0x10];
        let mut data = words(&[0x1000, 0x1008]);
        data.resize(0x100, 0);
        data.extend_from_slice(&[1, 0, 1, 1]);
        let segments = [
            Segment {
                addr: 0x1_1000,
                bytes: (&code[..]).into(),
                executable: true,
            },
            Segment {
                addr: 0x1_2000,
                bytes: (&data[..]).into(),
                executable: false,
            },
        ];
        let memory = Memory::new(&segments);
        let targets = table.map(|table| table.targets(&memory, 512));
        assert_eq!(targets, Some(vec![0x1_1008, 0x1_1000, 0x1_1008, 0x1_1008]));
    }

    #[test]
    fn table_relative_signed() {
        let mut tracker = Tracker::new(8);
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
        tracker.note(add(EAX, R8));
        let table = tracker.jump(Flow::JumpRegister(EAX));
        let code = [0_u8; 0x10];
        let data = words(&[(-0x1000_i32).cast_unsigned(), (-0xff8_i32).cast_unsigned()]);
        let segments = [
            Segment {
                addr: 0x1000,
                bytes: (&code[..]).into(),
                executable: true,
            },
            Segment {
                addr: 0x2000,
                bytes: (&data[..]).into(),
                executable: false,
            },
        ];
        let memory = Memory::new(&segments);
        let targets = table.map(|table| table.targets(&memory, 512));
        assert_eq!(targets, Some(vec![0x1000, 0x1008]));
    }

    #[test]
    fn writes_forget() {
        let mut tracker = Tracker::new(4);
        tracker.note(Note::Compare { reg: EAX, imm: 3 });
        tracker.note(Note::Write(EAX));
        let table = tracker.jump(Flow::JumpMemory(mem(None, Some(EAX), 4, 0x2000)));
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
        assert_eq!(tracker.jump(Flow::JumpRegister(ECX)), None);
    }

    #[test]
    fn a_copy_shares_a_later_bound() {
        // mov r11d, edx; cmp edx, 11; jmp [r11*4 + 0x2000]
        let (edx, r11) = (4, 5);
        let mut tracker = Tracker::new(4);
        tracker.note(Note::Copy { reg: r11, src: edx });
        tracker.note(Note::Compare { reg: edx, imm: 11 });
        let table = tracker.jump(Flow::JumpMemory(mem(None, Some(r11), 4, 0x2000)));
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
