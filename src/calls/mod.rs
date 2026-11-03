//! Call and syscall sites, with the values their arguments carry.
//!
//! [`calls`] walks each recovered function, tracking what its instructions
//! put in registers and stack slots, so that at every call and syscall it can
//! say what the arguments are: a constant, or a pointer and the bytes behind
//! it. filefacts turns these into syscall facts and decodes the sockaddr a
//! `connect` points at; nothing here knows what a `sockaddr` is.
//!
//! The walk is the value-tracking counterpart of function recovery: per
//! function, a linear pass over its code resets its register and stack model
//! wherever control may arrive from elsewhere (a branch target, the
//! instruction after a jump or return), so a value is used only where it
//! provably holds. Work is bounded by the recovered functions and their size.

mod arm;
mod arm64;
mod state;
#[cfg(test)]
mod tests;
mod x86;

use crate::isa::Memory;
use crate::{Arch, Binary, Functions};
use state::State;

/// The most bytes read from behind a pointer argument: enough for the
/// sockaddr structures a caller decodes, and bounded so a pointer into a huge
/// mapped segment copies no more.
pub(crate) const MAX_POINTED: usize = 64;

/// A call or syscall, and the values of its arguments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Call {
    /// Address of the call or syscall instruction.
    pub addr: u64,
    /// Where it goes.
    pub target: Target,
    /// Its arguments, in the calling convention's order: the integer and
    /// pointer registers that carry the first arguments, as many as the
    /// convention and the tracker resolve. A trailing [`Value::Unknown`] is
    /// dropped, so the vector is as long as the last argument known.
    pub args: Vec<Value>,
}

/// Where a call or syscall goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    /// A syscall, by its number; resolve its name with
    /// [`Binary::syscall`](crate::Binary::syscall).
    Syscall(u64),
    /// A call that reaches an import, directly or through its stub: the index
    /// into [`Binary::imports`](crate::Binary::imports).
    Import(usize),
    /// A direct call to this address in the binary.
    Addr(u64),
    /// An indirect call, or one whose target could not be resolved.
    Unknown,
}

/// The value an argument carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// Not a constant the tracker could follow.
    Unknown,
    /// A constant integer, zero-extended to 64 bits.
    Int(u64),
    /// A pointer, and the bytes it points at that the tracker could read:
    /// from the file for a mapped address, or from the stack model for a
    /// pointer into the current frame. `addr` is the pointer when it is a
    /// fixed address, `None` for a stack pointer. Each byte is `None` where
    /// its value is not known. Trailing unknown bytes are dropped.
    Mem {
        /// The pointer, when it is a fixed address; `None` for a stack pointer.
        addr: Option<u64>,
        /// The bytes behind it, `None` where a byte's value is unknown.
        bytes: Vec<Option<u8>>,
    },
}

/// The calls and syscalls of `bin`, given its recovered `funcs`, in address
/// order. Empty for an architecture whose arguments binform does not yet
/// track (every architecture but x86, x86-64 and 32-bit Arm).
#[must_use]
pub fn calls(bin: &Binary<'_>, funcs: &Functions) -> Vec<Call> {
    let Some(arch) = bin.arch else {
        return Vec::new();
    };
    if !matches!(arch, Arch::X86 | Arch::X86_64 | Arch::Arm | Arch::Arm64) {
        return Vec::new();
    }
    let memory = Memory::for_arch(&bin.segments, arch);
    let mut decoder = crate::isa::Decoder::new(bin, arch);
    let mut found = Vec::new();
    for function in &funcs.functions {
        decoder.reset();
        walk(bin, arch, &memory, &mut decoder, function, &mut found);
    }
    found.sort_by_key(|call: &Call| call.addr);
    found
}

/// The block-start addresses within `function`: its entry, and every target
/// of a branch or jump it makes that lands inside it. Control may arrive at
/// each from elsewhere, so the value model is reset there.
fn joins(function: &crate::Function) -> std::collections::BTreeSet<u64> {
    let mut joins = std::collections::BTreeSet::new();
    joins.insert(function.entry);
    let end = function.entry.wrapping_add(function.size);
    for r in &function.refs {
        if matches!(r.kind, crate::RefKind::Branch | crate::RefKind::Jump | crate::RefKind::Case)
            && (function.entry..end).contains(&r.to)
        {
            joins.insert(r.to);
        }
    }
    joins
}

/// Walk one function, appending the calls it makes.
fn walk(
    bin: &Binary<'_>,
    arch: Arch,
    memory: &Memory<'_>,
    decoder: &mut crate::isa::Decoder,
    function: &crate::Function,
    out: &mut Vec<Call>,
) {
    let entry = function.entry;
    let Some(code) = memory.code(entry) else {
        return;
    };
    let size = usize::try_from(function.size).unwrap_or(code.len()).min(code.len());
    let Some(code) = code.get(..size) else {
        return;
    };
    let joins = joins(function);
    let mut state = State::new(arch, memory);
    let mut addr = entry;
    let mut budget = size; // one unit per instruction; the loop advances `addr`.
    while let Some(rel) = usize::try_from(addr.wrapping_sub(entry)).ok().filter(|&r| r < code.len()) {
        if budget == 0 {
            break;
        }
        budget -= 1;
        // A block start: control may arrive from elsewhere, so nothing a
        // previous instruction left can be relied on. The entry keeps the
        // fresh state.
        if addr != entry && joins.contains(&addr) {
            state.reset();
        }
        let Some(bytes) = code.get(rel..) else {
            break;
        };
        let step = match arch {
            Arch::Arm => arm::step(&mut state, decoder, bytes, addr),
            Arch::Arm64 => arm64::step(&mut state, decoder, bytes, addr),
            Arch::X86 => x86::step(&mut state, 32, bytes, addr),
            Arch::X86_64 => x86::step(&mut state, 64, bytes, addr),
            _ => break,
        };
        let len = step.len.max(1);
        if let Some(site) = step.site {
            out.push(resolve(bin, addr, site));
        }
        if step.barrier {
            state.reset();
        }
        addr = addr.wrapping_add(u64::from(len));
    }
}

/// A raw site the tracker found, before its target is resolved against the
/// binary's imports.
pub(crate) struct Site {
    pub(crate) raw: RawTarget,
    pub(crate) args: Vec<Value>,
}

pub(crate) enum RawTarget {
    Syscall(u64),
    Call(u64),
    Indirect,
}

/// What a tracker returns for one instruction.
pub(crate) struct Step {
    pub(crate) len: u32,
    /// A call or syscall this instruction is.
    pub(crate) site: Option<Site>,
    /// Control leaves after this instruction (a jump, return or trap), so the
    /// value model must be reset.
    pub(crate) barrier: bool,
}

impl Step {
    pub(crate) const fn go(len: u32) -> Self {
        Self { len, site: None, barrier: false }
    }

    pub(crate) const fn stop(len: u32) -> Self {
        Self { len, site: None, barrier: true }
    }
}

/// Resolve a raw site's target against the binary: a call that lands on an
/// import, or its stub, becomes [`Target::Import`].
fn resolve(bin: &Binary<'_>, addr: u64, site: Site) -> Call {
    let mut args = site.args;
    while matches!(args.last(), Some(Value::Unknown)) {
        args.pop();
    }
    let target = match site.raw {
        RawTarget::Syscall(number) => Target::Syscall(number),
        RawTarget::Indirect => Target::Unknown,
        RawTarget::Call(to) => import_at(bin, to)
            .map(Target::Import)
            .unwrap_or(Target::Addr(to)),
    };
    Call { addr, target, args }
}

/// The index of the import whose slot is at `addr`, if any.
fn import_at(bin: &Binary<'_>, addr: u64) -> Option<usize> {
    bin.imports.iter().position(|import| import.slot == Some(addr))
}
