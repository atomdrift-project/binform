//! The value model a call walk keeps: what each register holds, and the bytes
//! written to the current stack frame. A register holds a constant integer, a
//! stack pointer (the frame pointer at entry plus an offset), or nothing
//! known. Stack stores record bytes against their offset from that entry
//! pointer, so a `sockaddr` built field by field on the stack reads back whole
//! at the call.

use super::{MAX_POINTED, Value};
use crate::Arch;
use crate::isa::Memory;
use std::collections::BTreeMap;

/// What a register holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Val {
    /// Nothing the walk could follow.
    Unknown,
    /// A constant, zero-extended to 64 bits.
    Int(u64),
    /// The stack pointer at function entry, plus this signed offset.
    Stack(i64),
}

/// The register and stack model during one function's walk.
pub(crate) struct State<'a> {
    regs: Vec<Val>,
    /// Bytes written to the frame, keyed by offset from the entry stack
    /// pointer. Bounded so a wild store cannot grow it without limit.
    stack: BTreeMap<i64, u8>,
    /// Symbolic values spilled to the frame, keyed by offset: a pointer or
    /// constant stored to a slot and read back whole, so a `sockaddr` address
    /// parked on the stack and reloaded into an argument register survives.
    /// The width lets a read require the store that matches it.
    slots: BTreeMap<i64, (Val, u8)>,
    memory: &'a Memory<'a>,
    /// The stack pointer's register, set to the frame base at every reset so a
    /// frame stays addressable: `r13` on Arm, `rsp`/`esp` on x86.
    frame: u32,
}

/// Cap on remembered stack bytes per function: a frame of constants far larger
/// than any argument structure a caller decodes.
const MAX_STACK_BYTES: usize = 4096;

impl<'a> State<'a> {
    pub(crate) fn new(arch: Arch, memory: &'a Memory<'a>) -> Self {
        // The stack pointer: Arm's `r13`, or `rsp`/`esp`, which is the fifth
        // 64-bit register in the order the x86 tracker numbers them.
        let frame = match arch {
            Arch::Arm => 13,
            Arch::Arm64 => 31,
            _ => 4,
        };
        let mut state = Self {
            regs: vec![Val::Unknown; 32],
            stack: BTreeMap::new(),
            slots: BTreeMap::new(),
            memory,
            frame,
        };
        state.reset();
        state
    }

    /// Forget every register and the stack: called at a join, and after a
    /// barrier. The stack pointer is known again, at offset zero, because the
    /// frame is addressed relative to wherever it now is.
    pub(crate) fn reset(&mut self) {
        for reg in &mut self.regs {
            *reg = Val::Unknown;
        }
        if let Some(sp) = self.regs.get_mut(self.frame as usize) {
            *sp = Val::Stack(0);
        }
        self.stack.clear();
        self.slots.clear();
    }

    pub(crate) fn get(&self, reg: u32) -> Val {
        self.regs.get(reg as usize).copied().unwrap_or(Val::Unknown)
    }

    pub(crate) fn set(&mut self, reg: u32, val: Val) {
        if let Some(slot) = self.regs.get_mut(reg as usize) {
            *slot = val;
        }
    }

    pub(crate) fn set_int(&mut self, reg: u32, value: u64) {
        self.set(reg, Val::Int(value));
    }

    pub(crate) fn clear(&mut self, reg: u32) {
        self.set(reg, Val::Unknown);
    }

    /// Record `count` little-endian bytes of `value` at stack offset `off`.
    pub(crate) fn store_stack(&mut self, off: i64, value: u64, count: u8) {
        self.invalidate_slots(off, count);
        if self.stack.len() > MAX_STACK_BYTES {
            return;
        }
        for i in 0..i64::from(count) {
            #[expect(clippy::cast_possible_truncation, reason = "one byte")]
            let byte = (value >> (8 * i as u32)) as u8;
            self.stack.insert(off.wrapping_add(i), byte);
        }
    }

    /// Forget any stack bytes `count` wide at `off`: an overwrite the walk
    /// cannot resolve must not leave stale bytes behind.
    pub(crate) fn forget_stack(&mut self, off: i64, count: u8) {
        self.invalidate_slots(off, count);
        for i in 0..i64::from(count) {
            self.stack.remove(&off.wrapping_add(i));
        }
    }

    /// Record a symbolic value `val`, `width` bytes wide, spilled to stack
    /// offset `off` — a register parked on the frame. The bytes it occupies are
    /// forgotten, since a pointer's runtime bytes are not known.
    pub(crate) fn store_slot(&mut self, off: i64, val: Val, width: u8) {
        self.invalidate_slots(off, width);
        for i in 0..i64::from(width) {
            self.stack.remove(&off.wrapping_add(i));
        }
        if self.slots.len() <= MAX_STACK_BYTES {
            self.slots.insert(off, (val, width));
        }
    }

    /// The symbolic value spilled at `off`, if a `width`-wide store put one
    /// there: a reload reads back exactly what a matching store parked.
    pub(crate) fn load_slot(&self, off: i64, width: u8) -> Option<Val> {
        self.slots.get(&off).and_then(|&(val, w)| (w == width).then_some(val))
    }

    /// Drop every spilled slot whose bytes overlap `[off, off + count)`: a
    /// write there makes a parked pointer stale. Slots are at most 8 wide, so
    /// any overlap starts within 7 bytes before `off`.
    fn invalidate_slots(&mut self, off: i64, count: u8) {
        let start = off.wrapping_sub(7);
        let end = off.wrapping_add(i64::from(count));
        let stale: Vec<i64> = self
            .slots
            .range(start..end)
            .filter(|&(&at, &(_, width))| at.wrapping_add(i64::from(width)) > off)
            .map(|(&at, _)| at)
            .collect();
        for at in stale {
            self.slots.remove(&at);
        }
    }

    /// The argument value a register carries: a constant, or a pointer and
    /// the bytes behind it.
    pub(crate) fn value(&self, reg: u32) -> Value {
        match self.get(reg) {
            Val::Unknown => Value::Unknown,
            Val::Int(n) => self.pointed(n).unwrap_or(Value::Int(n)),
            Val::Stack(off) => Value::Mem {
                addr: None,
                bytes: trim(self.read_stack(off)),
            },
        }
    }

    /// Read up to [`MAX_POINTED`] bytes of the frame from `off`.
    fn read_stack(&self, off: i64) -> Vec<Option<u8>> {
        let n = i64::try_from(MAX_POINTED).unwrap_or(i64::MAX);
        (off..off.saturating_add(n))
            .map(|a| self.stack.get(&a).copied())
            .collect()
    }

    /// If `addr` points into a mapped segment, the pointer and up to
    /// [`MAX_POINTED`] bytes behind it; `None` when nothing is mapped there,
    /// so the caller keeps it as an integer.
    fn pointed(&self, addr: u64) -> Option<Value> {
        // A value too small to be an address is an integer, not a pointer; a
        // null pointer carries no bytes.
        if addr == 0 {
            return None;
        }
        let (bytes, _) = self.memory.at(addr)?;
        let take = bytes.len().min(MAX_POINTED);
        let bytes = bytes.get(..take)?.iter().map(|&b| Some(b)).collect();
        Some(Value::Mem {
            addr: Some(addr),
            bytes: trim(bytes),
        })
    }
}

/// Drop trailing unknown bytes, so a structure's known prefix is all that is
/// reported.
fn trim(mut bytes: Vec<Option<u8>>) -> Vec<Option<u8>> {
    while matches!(bytes.last(), Some(None)) {
        bytes.pop();
    }
    bytes
}
