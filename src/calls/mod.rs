//! Call and syscall sites, with the values their arguments carry.
//!
//! [`calls`] walks each recovered function, tracking what its instructions
//! put in registers and stack slots, so that at every call and syscall it can
//! say what the arguments are: a constant, or a pointer and the bytes behind
//! it. Nothing here knows what the arguments mean; a caller decodes, say, the
//! `sockaddr` a `connect` points at.
//!
//! The walk is the value-tracking counterpart of function recovery. It
//! decodes a function's blocks in address order: from each place control may
//! arrive from elsewhere (the entry, a branch or jump target, a landing pad)
//! up to a jump, return or trap, where it skips to the next such place. At
//! each of those places the value model is reset, so a value is used only
//! where it holds on every path the recovered edges show. A function's walk
//! decodes the code recovery decoded in it, and code no function decoded
//! that it runs straight into (a call after one that does not return), once
//! for all functions; it skips the rest of its span (other functions' code,
//! or data). Work is linear in what recovery decoded and the code, however
//! many functions overlap, and records are kept one per call site.

mod arm;
mod arm64;
mod state;
#[cfg(test)]
mod tests;
mod x86;

use crate::isa::{Flow, Insn, Memory};
use crate::{Arch, Binary, Dest, Function, Recovery, RefKind};
use state::{State, Val};
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::iter::once;
use std::ops::RangeInclusive;

/// The most bytes read from behind a pointer argument: enough for the
/// sockaddr structures a caller decodes, and bounded so a pointer into a huge
/// mapped segment copies no more.
pub(crate) const MAX_POINTED: usize = 64;

/// A call or syscall, and the values of its arguments.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
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
#[non_exhaustive]
pub enum Target {
    /// A syscall, by its number, `None` when the walk could not tell the
    /// number; resolve its name with [`Binary::syscall`](crate::Binary::syscall).
    Syscall(Option<u64>),
    /// A call that reaches an import, through its slot or through a stub
    /// that only jumps through the slot: the index into
    /// [`Binary::imports`](crate::Binary::imports).
    Import(usize),
    /// A direct call to this address in the binary.
    Addr(u64),
    /// An indirect call, or one whose target could not be resolved.
    Unknown,
}

/// The value an argument carries.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Value {
    /// Not a constant the tracker could follow.
    Unknown,
    /// A constant integer, zero-extended to 64 bits. A constant below the
    /// first page (0x1000) is always an integer, never a pointer.
    Int(u64),
    /// A pointer, and the bytes it points at that the tracker could read:
    /// from the file for a mapped address, or from the stack model for a
    /// pointer into the current frame.
    Mem {
        /// The pointer, when it is a fixed address; `None` for a stack pointer.
        addr: Option<u64>,
        /// The bytes behind it, `None` where a byte's value is unknown.
        /// Trailing unknown bytes are dropped.
        bytes: Vec<Option<u8>>,
    },
}

/// The calls and syscalls of `bin`, given its recovered `funcs`, in address
/// order. Empty for an architecture whose arguments binform does not yet
/// track: every architecture but x86, x86-64, 32-bit Arm and AArch64.
#[must_use]
pub fn calls(bin: &Binary<'_>, funcs: &Recovery) -> Vec<Call> {
    let Some(arch) = bin.arch else {
        return Vec::new();
    };
    match arch {
        Arch::X86 => run(bin, arch, funcs, x86::X86::new(32)),
        Arch::X86_64 => run(bin, arch, funcs, x86::X86::new(64)),
        Arch::Arm => run(bin, arch, funcs, arm::Arm::new(bin)),
        Arch::Arm64 => run(bin, arch, funcs, arm64::Arm64::new(bin)),
        _ => Vec::new(),
    }
}

/// One architecture's value tracking: what each instruction does to the
/// value model.
pub(crate) trait Tracker<'a> {
    /// The stack pointer's register number.
    fn sp(&self) -> u32;
    /// Bytes in a pointer.
    fn pointer(&self) -> u8;
    /// Start walking `code`, which is mapped at `start`.
    fn begin(&mut self, code: &'a [u8], start: u64);
    /// Control may arrive here from elsewhere: forget any state carried
    /// from the instructions before.
    fn reset(&mut self);
    /// Model the instruction `at` bytes into the code, mapped at `addr`.
    fn step(&mut self, state: &mut State<'_>, at: usize, addr: u64) -> Step;
}

/// The calls of `bin`'s `funcs`, walked with `tracker`.
fn run<'a, T: Tracker<'a>>(
    bin: &'a Binary<'_>,
    arch: Arch,
    funcs: &Recovery,
    mut tracker: T,
) -> Vec<Call> {
    let memory = Memory::for_arch(&bin.segments, arch);
    let targets = Targets::new(bin, funcs);
    let mut shared = Shared::new(funcs);
    for function in &funcs.functions {
        walk(
            &memory,
            &targets,
            funcs,
            function,
            &mut tracker,
            &mut shared,
        );
    }
    let mut found: Vec<Call> = shared.found.into_values().collect();
    found.sort_unstable_by_key(|call| call.addr);
    found
}

/// What the walks of a binary's functions share.
struct Shared {
    /// The code some function decoded, as sorted, disjoint ranges.
    decoded: Vec<(u64, u64)>,
    /// The addresses of code no function decoded that a walk has stepped.
    walked: HashSet<u64>,
    /// The call sites found, by address.
    found: HashMap<u64, Call>,
}

impl Shared {
    fn new(funcs: &Recovery) -> Self {
        let mut runs: Vec<(u64, u64)> = funcs.runs.values().flatten().copied().collect();
        runs.sort_unstable();
        let mut decoded: Vec<(u64, u64)> = Vec::with_capacity(runs.len());
        for (start, end) in runs {
            match decoded.last_mut() {
                Some(last) if last.1 >= start => last.1 = last.1.max(end),
                _ => decoded.push((start, end)),
            }
        }
        Self {
            decoded,
            walked: HashSet::new(),
            found: HashMap::new(),
        }
    }

    /// Whether a walk may step `addr`, which is not its function's code:
    /// only when no function decoded it and no walk has stepped it, so each
    /// such address costs one step for all walks.
    fn adopt(&mut self, addr: u64) -> bool {
        let below = self.decoded.partition_point(|&(start, _)| start <= addr);
        let decoded = below
            .checked_sub(1)
            .and_then(|i| self.decoded.get(i))
            .is_some_and(|&(_, end)| addr < end);
        !decoded && self.walked.insert(addr)
    }

    /// Record `call`. Recovered functions can overlap, so one instruction
    /// may be walked from several of them; an address is one call site, so
    /// a single record is kept per address: the one whose arguments the
    /// richest walk resolved, the first of those equally rich.
    fn record(&mut self, call: Call) {
        match self.found.entry(call.addr) {
            Entry::Vacant(slot) => {
                slot.insert(call);
            }
            Entry::Occupied(mut slot) => {
                if richness(&call) > richness(slot.get()) {
                    slot.insert(call);
                }
            }
        }
    }
}

/// How much a site's arguments resolved, for choosing between records of the
/// same address: the count of known arguments, then the bytes known behind
/// their pointers.
fn richness(call: &Call) -> (usize, usize) {
    let known = call.args.iter().filter(|v| **v != Value::Unknown).count();
    let bytes = call
        .args
        .iter()
        .map(|v| match v {
            Value::Mem { bytes, .. } => bytes.iter().filter(|b| b.is_some()).count(),
            _ => 0,
        })
        .sum();
    (known, bytes)
}

/// Walk one function's blocks, appending the calls it makes.
fn walk<'a, T: Tracker<'a>>(
    memory: &Memory<'a>,
    targets: &Targets<'_>,
    funcs: &Recovery,
    function: &Function,
    tracker: &mut T,
    shared: &mut Shared,
) {
    let joins = joins(memory, targets, funcs, function);
    let Some(&start) = joins.first() else {
        return;
    };
    let Some(code) = memory.code(start) else {
        return;
    };
    // Every block lies within `size` bytes of the lowest, and no join lies
    // below that block.
    let end = start.saturating_add(function.size);
    // What recovery decoded in the function, where it says: a recovery
    // built by hand walks the whole span.
    let span = [(start, end)];
    let runs = funcs
        .runs
        .get(&function.entry)
        .map_or(span.as_slice(), Vec::as_slice);
    let mut runs = runs.iter().copied().peekable();
    tracker.begin(code, start);
    let mut state = State::new(memory, tracker.sp(), tracker.pointer());
    let mut addr = start;
    // Whether the walk came to `addr` from the instruction before it.
    let mut ran_on = false;
    // The walk only moves forward: the joins not yet passed.
    let mut joins = joins.iter().copied().peekable();
    while addr < end {
        while runs.next_if(|&(_, run_end)| run_end <= addr).is_some() {}
        let own = runs.peek().is_some_and(|&(run_start, _)| run_start <= addr);
        if !own && !(ran_on && shared.adopt(addr)) {
            // Skip to the function's next code, where control arrives from
            // elsewhere.
            let Some(&(run_start, _)) = runs.peek() else {
                break;
            };
            addr = run_start;
            ran_on = false;
            state.reset();
            tracker.reset();
            continue;
        }
        while joins.next_if(|&join| join < addr).is_some() {}
        if joins.next_if_eq(&addr).is_some() {
            state.reset();
            tracker.reset();
        }
        let at = usize::try_from(addr.wrapping_sub(start)).unwrap_or(usize::MAX);
        let step = if at < code.len() {
            tracker.step(&mut state, at, addr)
        } else {
            Step::stop(1)
        };
        let next = addr.saturating_add(u64::from(step.len.max(1)));
        ran_on = !matches!(step.then, Then::Barrier);
        addr = match step.then {
            Then::Next => next,
            Then::Site(site) => {
                shared.record(targets.resolve(addr, site));
                next
            }
            Then::Barrier => {
                while joins.next_if(|&join| join < next).is_some() {}
                match joins.peek() {
                    Some(&join) => join,
                    None => break,
                }
            }
        };
    }
}

/// Where control may arrive in `function` from elsewhere: its entry, its
/// landing pads, and every branch, jump or jump-table target in its own code
/// (a jump to another function's entry is a tail call, a jump through an
/// import slot leaves the image). In address order, each once.
fn joins(
    memory: &Memory<'_>,
    targets: &Targets<'_>,
    funcs: &Recovery,
    function: &Function,
) -> Vec<u64> {
    let entry = function.entry;
    // Recovered blocks lie within `size` bytes of the entry, either side.
    let near = entry.saturating_sub(function.size)..entry.saturating_add(function.size);
    let jumps = function
        .refs
        .iter()
        .filter(|r| matches!(r.kind, RefKind::Branch | RefKind::Jump | RefKind::Case))
        .filter_map(|r| match r.to {
            Dest::Code(to) => Some(to),
            Dest::Slot { .. } => None,
        })
        .filter(|&to| near.contains(&to))
        .filter(|&to| to == entry || funcs.function(to).is_none())
        .filter(|&to| memory.is_code(to));
    let pads = targets.pads.get(&entry).into_iter().flatten().copied();
    let mut joins: Vec<u64> = once(entry).chain(jumps).chain(pads).collect();
    joins.sort_unstable();
    joins.dedup();
    joins
}

/// What a raw call target resolves to, built once per [`calls`].
struct Targets<'b> {
    bin: &'b Binary<'b>,
    /// Stub entry to the index of the import it jumps to.
    stubs: HashMap<u64, usize>,
    /// Function entry to its landing pads.
    pads: HashMap<u64, Vec<u64>>,
}

impl<'b> Targets<'b> {
    fn new(bin: &'b Binary<'b>, funcs: &Recovery) -> Self {
        let stubs = funcs
            .stubs
            .iter()
            .filter_map(|(&entry, &slot)| Some((entry, bin.import(slot)?.0)))
            .collect();
        let mut pads: HashMap<u64, Vec<u64>> = HashMap::new();
        for handler in &bin.handlers {
            pads.entry(handler.function).or_default().push(handler.addr);
        }
        Self { bin, stubs, pads }
    }

    /// The call a site the tracker found makes.
    fn resolve(&self, addr: u64, site: Site) -> Call {
        let mut args = site.args;
        while matches!(args.last(), Some(Value::Unknown)) {
            args.pop();
        }
        // Kept with the call: not the room the unknown arguments took.
        args.shrink_to_fit();
        let target = match site.raw {
            RawTarget::Syscall(number) => Target::Syscall(number),
            RawTarget::Call(to) => self
                .stubs
                .get(&to)
                .copied()
                .or_else(|| Some(self.bin.import(to)?.0))
                .map_or(Target::Addr(to), Target::Import),
            RawTarget::Slot(slot) => self
                .bin
                .import(slot)
                .map_or(Target::Unknown, |(index, _)| Target::Import(index)),
            RawTarget::Indirect => Target::Unknown,
        };
        Call { addr, target, args }
    }
}

/// A site the tracker found, before its target is resolved against the
/// binary's imports.
pub(crate) struct Site {
    pub(crate) raw: RawTarget,
    pub(crate) args: Vec<Value>,
}

pub(crate) enum RawTarget {
    /// A syscall, by its number when known.
    Syscall(Option<u64>),
    /// A direct call to this address.
    Call(u64),
    /// A call through the pointer stored at this address.
    Slot(u64),
    /// A call through a register or a computed address.
    Indirect,
}

/// What a tracker returns for one instruction: its length, and what comes
/// after it.
pub(crate) struct Step {
    len: u32,
    then: Then,
}

/// Where control goes after an instruction.
enum Then {
    /// On to the next instruction.
    Next,
    /// On to the next instruction, past the call or syscall this one is.
    Site(Site),
    /// Nowhere the walk follows (a jump, return or trap): it resumes at the
    /// next join.
    Barrier,
}

impl Step {
    pub(crate) const fn go(len: u32) -> Self {
        Self {
            len,
            then: Then::Next,
        }
    }

    pub(crate) const fn stop(len: u32) -> Self {
        Self {
            len,
            then: Then::Barrier,
        }
    }

    pub(crate) const fn site(len: u32, site: Site) -> Self {
        Self {
            len,
            then: Then::Site(site),
        }
    }

    /// A syscall whose number register holds `number`, passing `args`.
    pub(crate) fn syscall(len: u32, number: Val, args: impl Iterator<Item = Value>) -> Self {
        let number = match number {
            Val::Int(n) => Some(n),
            _ => None,
        };
        Self::site(
            len,
            Site {
                raw: RawTarget::Syscall(number),
                args: args.collect(),
            },
        )
    }
}

/// The step for an instruction whose control flow binform's decoder told,
/// on an architecture whose calls pass arguments in registers `args` and
/// may change the registers `clobbered` and the frame below the stack
/// pointer. `None` for an instruction that goes on to the next, whose
/// effect on the values the tracker models.
pub(crate) fn flow(
    state: &mut State<'_>,
    insn: &Insn,
    args: RangeInclusive<u32>,
    clobbered: &[u32],
) -> Option<Step> {
    let raw = match insn.flow {
        Flow::Next => return None,
        Flow::Call(to) => RawTarget::Call(to),
        Flow::CallSlot(slot) => RawTarget::Slot(slot),
        Flow::CallIndirect | Flow::CallRegister(_) => RawTarget::Indirect,
        // A conditional branch, or a return or jump that may not be taken:
        // on the way on, it changed nothing.
        Flow::Branch(_) => return Some(Step::go(insn.len)),
        _ if insn.falls => return Some(Step::go(insn.len)),
        Flow::Jump(_)
        | Flow::JumpSlot(_)
        | Flow::JumpMemory(_)
        | Flow::JumpRegister(_)
        | Flow::JumpIndirect
        | Flow::JumpAdd { .. }
        | Flow::JumpTable { .. }
        | Flow::Return
        | Flow::Stop
        | Flow::Invalid => return Some(Step::stop(insn.len)),
    };
    let site = Site {
        raw,
        args: args.map(|r| state.value(r)).collect(),
    };
    for &reg in clobbered {
        state.clear(reg);
    }
    state.forget_below_sp();
    Some(Step::site(insn.len, site))
}
