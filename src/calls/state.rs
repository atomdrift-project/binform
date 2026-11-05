//! The value model a call walk keeps: what each register holds, and what
//! the walk knows of the current stack frame.
//!
//! A register holds a constant, a stack pointer (the frame base plus an
//! offset), or nothing known. The frame base is wherever the stack pointer
//! was at the last reset, and the stack pointer always holds a stack
//! pointer, so the frame stays addressable. When it moves by an amount the
//! walk cannot tell (`and rsp, -16`, an `alloca`), it is taken to move far
//! down, past the old frame, which a frame pointer may still address: what
//! is stored through it never meets what the old frame holds.
//!
//! A store to the frame records a constant as its little-endian bytes, so a
//! `sockaddr` built field by field reads back whole at the call, and a stack
//! pointer as itself, since its runtime bytes are not known. A load reads
//! back either: the pointer a store of the same offset and width left, or
//! the constant the bytes it covers spell.

use super::{MAX_POINTED, Value};
use crate::isa::Memory;
use std::collections::BTreeMap;

/// What a register holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Val {
    /// Nothing the walk could follow.
    Unknown,
    /// A constant, zero-extended to 64 bits.
    Int(u64),
    /// The frame base plus this offset.
    Stack(i64),
}

impl Val {
    /// This value plus `delta`: a stack pointer moves, a constant wraps.
    pub(crate) const fn plus(self, delta: i64) -> Self {
        match self {
            Self::Unknown => Self::Unknown,
            Self::Int(n) => Self::Int(n.wrapping_add_signed(delta)),
            Self::Stack(off) => Self::Stack(off.wrapping_add(delta)),
        }
    }

    /// A constant cut to its low 32 bits, as a 32-bit register holds it.
    pub(crate) const fn low32(self) -> Self {
        match self {
            Self::Int(n) => Self::Int(n & 0xffff_ffff),
            other => other,
        }
    }
}

/// Cap on what the frame model remembers per function, bytes and stored
/// pointers together: far more than any argument structure a caller decodes,
/// and bounded so a wild run of stores cannot grow it without limit.
const MAX_FRAME: usize = 4096;

/// How far below the old frame a stack pointer that moved by an amount the
/// walk cannot tell is taken to point: further than any frame reaches.
const FAR: i64 = 1 << 32;

/// Below this, a constant is an integer, not a pointer: no loader maps the
/// first page, and the small numbers arguments carry (a length, a flag, a
/// descriptor) would otherwise read as addresses in an image based at zero.
const MIN_POINTER: u64 = 0x1000;

/// The register and frame model during one function's walk.
#[derive(Clone)]
pub(crate) struct State<'a> {
    regs: [Val; 32],
    /// Constant bytes stored to the frame, by offset from its base.
    bytes: BTreeMap<i64, u8>,
    /// Stack pointers stored to the frame, by offset: each a pointer wide.
    pointers: BTreeMap<i64, Val>,
    memory: &'a Memory<'a>,
    /// The stack pointer's register number, in the tracker's numbering.
    sp: u32,
    /// Bytes in a pointer.
    pointer: u8,
}

impl<'a> State<'a> {
    pub(crate) fn new(memory: &'a Memory<'a>, sp: u32, pointer: u8) -> Self {
        let mut state = Self {
            regs: [Val::Unknown; 32],
            bytes: BTreeMap::new(),
            pointers: BTreeMap::new(),
            memory,
            sp,
            pointer,
        };
        state.reset();
        state
    }

    /// Forget everything: control may arrive here from elsewhere. The stack
    /// pointer is the base of a new frame.
    pub(crate) fn reset(&mut self) {
        self.regs = [Val::Unknown; 32];
        self.bytes.clear();
        self.pointers.clear();
        self.set(self.sp, Val::Stack(0));
    }

    /// The stack pointer, which was at `off`, moved by an amount the walk
    /// cannot tell: take it to point [`FAR`] below.
    fn moved(&mut self, off: i64) {
        self.set(self.sp, Val::Stack(off.saturating_sub(FAR)));
    }

    pub(crate) fn get(&self, reg: u32) -> Val {
        self.regs.get(reg as usize).copied().unwrap_or(Val::Unknown)
    }

    /// Set `reg`. The stack pointer set to what is no stack pointer has
    /// moved by an amount the walk cannot tell.
    pub(crate) fn set(&mut self, reg: u32, val: Val) {
        match (reg == self.sp, val, self.get(reg)) {
            (true, Val::Int(_) | Val::Unknown, Val::Stack(off)) => self.moved(off),
            _ => {
                if let Some(slot) = self.regs.get_mut(reg as usize) {
                    *slot = val;
                }
            }
        }
    }

    pub(crate) fn clear(&mut self, reg: u32) {
        self.set(reg, Val::Unknown);
    }

    /// Clear every register but the stack pointer: an instruction that
    /// writes registers the tracker cannot tell.
    pub(crate) fn clear_all(&mut self) {
        let sp = self.get(self.sp);
        self.regs = [Val::Unknown; 32];
        self.set(self.sp, sp);
    }

    /// Keep only what both `self` and `other` agree on: the state after an
    /// instruction that may or may not run, `self` the one and `other` the
    /// other.
    pub(crate) fn meet(&mut self, other: &Self) {
        let sp = self.get(self.sp);
        for (mine, theirs) in self.regs.iter_mut().zip(&other.regs) {
            if mine != theirs {
                *mine = Val::Unknown;
            }
        }
        self.bytes
            .retain(|off, byte| other.bytes.get(off) == Some(byte));
        self.pointers
            .retain(|off, stored| other.pointers.get(off) == Some(stored));
        if let (Val::Unknown, Val::Stack(off)) = (self.get(self.sp), sp) {
            self.moved(off);
        }
    }

    /// Record a store of `val`, `width` bytes wide, to frame offset `off`.
    /// A stack pointer stored to other than a pointer's width leaves bytes
    /// the walk cannot tell.
    pub(crate) fn store(&mut self, off: i64, val: Val, width: u8) {
        self.forget(off, width.into());
        if self.bytes.len().saturating_add(self.pointers.len()) >= MAX_FRAME {
            return;
        }
        match val {
            Val::Int(n) => {
                for (at, byte) in (off..).zip(n.to_le_bytes().into_iter().take(width.into())) {
                    self.bytes.insert(at, byte);
                }
            }
            Val::Stack(_) if width == self.pointer => {
                self.pointers.insert(off, val);
            }
            Val::Stack(_) | Val::Unknown => {}
        }
    }

    /// Forget the `width` bytes at frame offset `off`: a store of a value
    /// the walk does not know.
    pub(crate) fn forget(&mut self, off: i64, width: u16) {
        let end = off.saturating_add(i64::from(width));
        self.bytes.extract_if(off..end, |_, _| true).for_each(drop);
        // A stored pointer that overlaps starts less than a pointer's width
        // before `off`.
        let first = off
            .saturating_sub(i64::from(self.pointer))
            .saturating_add(1);
        self.pointers
            .extract_if(first..end, |_, _| true)
            .for_each(drop);
    }

    /// Forget the whole frame: a store into it at an offset the walk cannot
    /// tell.
    pub(crate) fn forget_frame(&mut self) {
        self.bytes.clear();
        self.pointers.clear();
    }

    /// Forget the frame below the stack pointer, which a call's own frame
    /// overwrites.
    pub(crate) fn forget_below_sp(&mut self) {
        if let Val::Stack(sp) = self.get(self.sp) {
            self.bytes = self.bytes.split_off(&sp);
            self.pointers = self.pointers.split_off(&sp);
        }
    }

    /// What a load of `width` bytes from frame offset `off` reads: the stack
    /// pointer a store of the same offset and width left, or the constant
    /// the known bytes there spell, zero-extended.
    pub(crate) fn load(&self, off: i64, width: u8) -> Val {
        if let Some(&val) = self.pointers.get(&off) {
            return if width == self.pointer {
                val
            } else {
                Val::Unknown
            };
        }
        if width > 8 {
            return Val::Unknown;
        }
        let mut word = [0; 8];
        for (at, byte) in (off..).zip(word.iter_mut().take(width.into())) {
            match self.bytes.get(&at) {
                Some(&known) => *byte = known,
                None => return Val::Unknown,
            }
        }
        Val::Int(u64::from_le_bytes(word))
    }

    /// The `width`-byte constant the image holds at `addr`: a literal.
    pub(crate) fn read(&self, addr: u64, width: u8) -> Val {
        self.memory.read(addr, width).map_or(Val::Unknown, Val::Int)
    }

    /// The argument value a register carries: a constant, or a pointer and
    /// the bytes behind it.
    pub(crate) fn value(&self, reg: u32) -> Value {
        match self.get(reg) {
            Val::Unknown => Value::Unknown,
            Val::Int(n) => self.pointed(n).unwrap_or(Value::Int(n)),
            Val::Stack(off) => Value::Mem {
                addr: None,
                bytes: trim(
                    (off..)
                        .take(MAX_POINTED)
                        .map(|at| self.bytes.get(&at).copied())
                        .collect(),
                ),
            },
        }
    }

    /// If `addr` is a pointer into the image, the pointer and up to
    /// [`MAX_POINTED`] bytes behind it; `None` for an integer, so the caller
    /// keeps it as one.
    fn pointed(&self, addr: u64) -> Option<Value> {
        if addr < MIN_POINTER {
            return None;
        }
        let (bytes, _) = self.memory.at(addr)?;
        let bytes = bytes.iter().take(MAX_POINTED).map(|&b| Some(b)).collect();
        Some(Value::Mem {
            addr: Some(addr),
            bytes: trim(bytes),
        })
    }
}

/// Swap the bytes of each 16-bit half: `rev16`, which puts a port in network
/// order.
pub(crate) const fn rev16(v: u64) -> u64 {
    (v & 0x00ff_00ff_00ff_00ff) << 8 | (v & 0xff00_ff00_ff00_ff00) >> 8
}

/// The little-endian 32-bit word `bytes` begin with.
pub(crate) fn word(bytes: &[u8]) -> Option<u32> {
    bytes.first_chunk::<4>().map(|&b| u32::from_le_bytes(b))
}

/// Drop trailing unknown bytes, so a structure's known prefix is all that is
/// reported.
fn trim(mut bytes: Vec<Option<u8>>) -> Vec<Option<u8>> {
    while matches!(bytes.last(), Some(None)) {
        bytes.pop();
    }
    bytes
}
