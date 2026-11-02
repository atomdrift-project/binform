//! Function discovery and control-flow graphs.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use crate::decode::{Decoder, Flow, Insn, Memory, Note};
use crate::table::Tracker;
use crate::{Found, Function, Image, Limits, Origin, Recovery, Ref, RefKind};

/// Functions that never return, by name. Rizin's list, so a call to one ends
/// its basic block in both tools.
const NORETURN: [&str; 20] = [
    "ExitProcess",
    "ExitThread",
    "FatalExit",
    "FreeLibraryAndExitThread",
    "RaiseException",
    "RtlRaiseException",
    "_Exit",
    "__assert_fail",
    "__assert_rtn",
    "__cxa_throw",
    "__libc_init",
    "__libc_start_main",
    "__stack_chk_fail",
    "__uClibc_main",
    "_exit",
    "abort",
    "err",
    "errc",
    "errx",
    "exit",
];

/// C runtime start routines, and which of their arguments is `main`.
const STARTS: [(&str, usize); 3] = [
    ("__libc_start_main", 0),
    ("__uClibc_main", 0),
    // Bionic: `__libc_init(raw_args, onexit, main, structors)`.
    ("__libc_init", 2),
];

/// `name` as C spells it: Mach-O prefixes C names with `_`; decorated 32-bit
/// Windows names end in `@N`.
fn c_names(name: &str) -> [&str; 2] {
    let name = name.split('@').next().unwrap_or(name);
    [name, name.strip_prefix('_').unwrap_or(name)]
}

/// Whether `name` is a function that never returns.
fn never_returns(name: &str) -> bool {
    c_names(name).iter().any(|name| NORETURN.contains(name))
}

/// Which argument is `main`, when `name` is a C runtime start routine.
fn main_argument(name: &str) -> Option<usize> {
    c_names(name).iter().find_map(|name| {
        STARTS
            .iter()
            .find_map(|&(start, argument)| (start == *name).then_some(argument))
    })
}

pub(crate) fn recover(image: &Image<'_>, limits: &Limits) -> Recovery {
    let mut work = Work {
        memory: Memory::new(&image.segments),
        decoder: Decoder::new(image),
        budget: limits.instructions,
        table_entries: limits.table_entries,
        truncated: false,
        entries: BTreeMap::new(),
        imports: image.imports.iter().map(|import| import.slot).collect(),
        noreturn: HashSet::new(),
        thunks: HashMap::new(),
        handlers: HashMap::new(),
        starts: HashMap::new(),
        explored: HashSet::new(),
    };
    for handler in &image.handlers {
        work.handlers
            .entry(handler.function)
            .or_default()
            .push(handler.addr);
    }
    for import in &image.imports {
        if never_returns(&import.name) {
            work.noreturn.insert(import.slot);
        }
        if let Some(argument) = main_argument(&import.name) {
            work.starts.insert(import.slot, argument);
        }
    }
    for seed in &image.seeds {
        if let Origin::Symbol(name) | Origin::Export(name) = &seed.origin {
            if never_returns(name) {
                work.noreturn.insert(seed.addr);
            }
            if let Some(argument) = main_argument(name) {
                work.starts.insert(seed.addr, argument);
            }
        }
    }

    // Every known start, then every call target a linear sweep finds: the
    // entry set is nearly complete before any function is explored, so which
    // jumps are tail calls does not depend on exploration order.
    for seed in &image.seeds {
        work.add_entry(seed.addr, Found::from(&seed.origin), limits.functions);
    }
    work.sweep(limits.functions);

    let mut functions = Vec::new();
    let mut runs = Vec::new();
    let mut queue: Vec<u64> = work.entries.keys().rev().copied().collect();
    let mut done = HashSet::new();
    while let Some(entry) = queue.pop() {
        // A start another function absorbed is gone from the entries.
        if !work.entries.contains_key(&entry) || !done.insert(entry) {
            continue;
        }
        if work.truncated {
            break;
        }
        let explored = work.explore(entry);
        for target in explored.calls {
            if work.add_entry(target, Found::CALL, limits.functions) {
                queue.push(target);
            }
        }
        for main in explored.mains {
            if work.add_entry(main, Found::MAIN, limits.functions) {
                queue.push(main);
            }
        }
        runs.extend(explored.runs);
        functions.push(explored.function);
    }
    // Callers explored after a function add to how it was found.
    for function in &mut functions {
        function.found = work
            .entries
            .get(&function.entry)
            .copied()
            .unwrap_or_default();
    }
    functions.sort_by_key(|function| function.entry);
    Recovery {
        functions,
        covered: covered(runs),
        truncated: work.truncated,
    }
}

/// Bytes in the union of half-open address ranges.
fn covered(mut runs: Vec<(u64, u64)>) -> u64 {
    runs.sort_unstable();
    let mut total = 0_u64;
    let mut reach = 0_u64;
    for (start, end) in runs {
        let start = start.max(reach);
        if end > start {
            total = total.saturating_add(end - start);
            reach = end;
        }
    }
    total
}

struct Work<'a> {
    memory: Memory<'a>,
    decoder: Decoder,
    /// Instructions left to decode.
    budget: usize,
    table_entries: usize,
    truncated: bool,
    /// Function starts known so far, and how each was found.
    entries: BTreeMap<u64, Found>,
    imports: HashSet<u64>,
    /// Slots and functions whose callers never resume.
    noreturn: HashSet<u64>,
    /// Address -> the import slot the code there only jumps through.
    thunks: HashMap<u64, Option<u64>>,
    /// Function start -> its landing pads.
    handlers: HashMap<u64, Vec<u64>>,
    /// C runtime start routines (functions and import slots) -> which
    /// argument is `main`.
    starts: HashMap<u64, usize>,
    /// Entries explored so far.
    explored: HashSet<u64>,
}

/// One explored function, and what it found beyond itself.
struct Explored {
    function: Function,
    /// Direct call targets.
    calls: Vec<u64>,
    /// What it passes a C runtime start routine as `main`.
    mains: Vec<u64>,
    /// Address ranges of its instructions.
    runs: Vec<(u64, u64)>,
}

impl Work<'_> {
    /// Decode one instruction, or `None` when the budget is spent.
    fn decode(&mut self, bytes: &[u8], addr: u64) -> Option<Insn> {
        if self.budget == 0 {
            self.truncated = true;
            return None;
        }
        self.budget -= 1;
        Some(self.decoder.decode(bytes, addr))
    }

    /// Record a function start inside code, found `how`. True when it is
    /// new.
    fn add_entry(&mut self, addr: u64, how: Found, most: usize) -> bool {
        if let Some(found) = self.entries.get_mut(&addr) {
            *found |= how;
            return false;
        }
        if !self.memory.is_code(addr) {
            return false;
        }
        if self.entries.len() >= most {
            self.truncated = true;
            return false;
        }
        self.entries.insert(addr, how);
        true
    }

    /// Linear sweep of every code segment for direct calls into code, and
    /// direct jumps to code that starts a frame. (Code after `int3` padding
    /// is no sign of a function: MSVC aligns jump targets inside functions
    /// with it.)
    fn sweep(&mut self, most: usize) {
        let segments: Vec<(u64, &[u8])> = self
            .memory
            .code_segments()
            .map(|segment| (segment.addr, segment.bytes))
            .collect();
        let step = self.decoder.alignment();
        for (base, bytes) in segments {
            self.decoder.reset();
            let mut offset = 0_usize;
            while let Some(rest) = bytes.get(offset..).filter(|rest| !rest.is_empty()) {
                let addr = base.wrapping_add(offset as u64);
                let Some(insn) = self.decode(rest, addr) else {
                    return;
                };
                match insn.flow {
                    Flow::Call(target) => {
                        self.add_entry(target, Found::SWEEP, most);
                    }
                    Flow::Jump(target) => {
                        let frame = self
                            .memory
                            .code(target)
                            .is_some_and(|code| self.decoder.starts_frame(code));
                        if frame {
                            self.add_entry(target, Found::TAIL_CALL, most);
                        }
                    }
                    _ => {}
                }
                let len = u64::from(insn.len).max(step);
                offset = offset.saturating_add(usize::try_from(len).unwrap_or(usize::MAX));
            }
        }
    }

    /// The import slot the code at `addr` does nothing but jump through.
    fn thunk(&mut self, addr: u64) -> Option<u64> {
        if let Some(&known) = self.thunks.get(&addr) {
            return known;
        }
        self.decoder.reset();
        let mut found = None;
        let mut at = addr;
        // A stub is a jump through a slot, after at most three instructions
        // of padding or (on Arm) the address arithmetic that finds the slot.
        for _ in 0..4 {
            let Some(bytes) = self.memory.code(at) else {
                break;
            };
            let Some(insn) = self.decode(bytes, at) else {
                break;
            };
            match insn.flow {
                Flow::JumpSlot(slot) => {
                    found = self.imports.contains(&slot).then_some(slot);
                    break;
                }
                Flow::Next if insn.pad || self.decoder.alignment() == 4 => {
                    at = at.wrapping_add(u64::from(insn.len));
                }
                _ => break,
            }
        }
        self.thunks.insert(addr, found);
        found
    }

    /// The `main` a call to `target` (a function or an import slot) at the
    /// end of the instruction before `next` passes, when `target` is a C
    /// runtime start routine: one named so, or, unnamed, the routine the
    /// program's entry point calls just before a trap (`call
    /// __libc_start_main; hlt`), when `main` travels in a register.
    fn main(&mut self, entry: u64, target: u64, next: u64, tracker: &Tracker) -> Option<u64> {
        let named = match self.starts.get(&target) {
            Some(&argument) => Some(argument),
            None if self.starts.is_empty() => None,
            None => self
                .thunk(target)
                .and_then(|slot| self.starts.get(&slot).copied()),
        };
        let argument = match named {
            Some(argument) => argument,
            None => {
                let start = self
                    .entries
                    .get(&entry)
                    .is_some_and(|f| f.contains(Found::ENTRY));
                if !start || self.decoder.argument(0).is_none() {
                    return None;
                }
                // A copy decodes it: the walk decodes it again.
                let bytes = self.memory.code(next)?;
                if self.decoder.clone().decode(bytes, next).flow != Flow::Stop {
                    return None;
                }
                0
            }
        };
        let main = match self.decoder.argument(argument) {
            Some(reg) => tracker.held(reg),
            // On the stack: the last push is the first argument.
            None if argument == 0 => tracker.pushed(),
            None => None,
        }?;
        self.memory.is_code(main).then_some(main)
    }

    fn never_returns(&mut self, target: u64) -> bool {
        self.noreturn.contains(&target)
            || self
                .thunk(target)
                .is_some_and(|slot| self.noreturn.contains(&slot))
    }

    fn explore(&mut self, entry: u64) -> Explored {
        self.explored.insert(entry);
        let mut insns: BTreeMap<u64, Insn> = BTreeMap::new();
        let mut leaders = BTreeSet::from([entry]);
        // Block starts still to walk, with the register values on the path
        // that found them. Landing pads sit beneath the entry, so the body
        // claims its own code first; each starts a block nothing branches to.
        let fresh = Tracker::new(self.decoder.address_width());
        let mut pending = Vec::new();
        for &pad in self.handlers.get(&entry).into_iter().flatten().rev() {
            if !self.entries.contains_key(&pad) && self.memory.is_code(pad) && leaders.insert(pad) {
                pending.push((pad, fresh.clone()));
            }
        }
        pending.push((entry, fresh));
        let mut refs = Vec::new();
        let mut calls = Vec::new();
        let mut mains = Vec::new();
        let mut ends = HashSet::new(); // calls that never return
        let mut cases: HashMap<u64, u32> = HashMap::new();

        while let Some((start, mut tracker)) = pending.pop() {
            let mut addr = start;
            self.decoder.reset();
            // Whether the last instruction walked runs into `addr`, other
            // than by returning from a call (which may never return).
            let mut falls = false;
            loop {
                if insns.contains_key(&addr) {
                    break;
                }
                if addr != entry
                    && let Some(&found) = self.entries.get(&addr)
                {
                    // Code that runs straight into a start known only from
                    // unwind data continues there: a compiler that
                    // shrink-wraps a function gives its parts their own
                    // unwind entries. Anything else there is another
                    // function.
                    if !(falls && found == Found::UNWIND) || self.explored.contains(&addr) {
                        break;
                    }
                    self.entries.remove(&addr);
                    if refs.iter().any(|r: &Ref| r.to == addr) {
                        leaders.insert(addr);
                    }
                }
                let Some(bytes) = self.memory.code(addr) else {
                    break;
                };
                let Some(insn) = self.decode(bytes, addr) else {
                    break;
                };
                insns.insert(addr, insn);
                // Padding after a call that never returns runs into
                // nothing.
                if !insn.pad {
                    falls = matches!(insn.flow, Flow::Next | Flow::Branch(_));
                }
                let next = addr.wrapping_add(u64::from(insn.len));
                let target = |to: u64,
                              tracker: &Tracker,
                              leaders: &mut BTreeSet<u64>,
                              pending: &mut Vec<(u64, Tracker)>| {
                    // A jump to another function's start is a tail call.
                    let local = to == entry || !self.entries.contains_key(&to);
                    if local && self.memory.is_code(to) && leaders.insert(to) {
                        pending.push((to, tracker.clone()));
                    }
                };
                // Branches and calls only read registers; what a call
                // changes, `call` forgets below.
                if insn.flow == Flow::Next {
                    tracker.note(insn.note);
                }
                match insn.flow {
                    Flow::Next => {}
                    Flow::CallIndirect => tracker.call(),
                    Flow::Call(to) => {
                        mains.extend(self.main(entry, to, next, &tracker));
                        tracker.call();
                        // A PC thunk returns the address after the call.
                        let thunk = self
                            .memory
                            .code(to)
                            .and_then(|code| self.decoder.pc_thunk(code));
                        if let Some(reg) = thunk {
                            tracker.note(Note::Address { reg, addr: next });
                        }
                        refs.push(Ref {
                            from: addr,
                            to,
                            kind: RefKind::Call,
                        });
                        calls.push(to);
                        if self.never_returns(to) {
                            ends.insert(addr);
                            break;
                        }
                    }
                    Flow::CallSlot(slot) => {
                        mains.extend(self.main(entry, slot, next, &tracker));
                        tracker.call();
                        refs.push(Ref {
                            from: addr,
                            to: slot,
                            kind: RefKind::Call,
                        });
                        if self.noreturn.contains(&slot) {
                            ends.insert(addr);
                            break;
                        }
                    }
                    Flow::Branch(to) => {
                        refs.push(Ref {
                            from: addr,
                            to,
                            kind: RefKind::Branch,
                        });
                        target(to, &tracker, &mut leaders, &mut pending);
                        // The fall-through starts a block; this walk decodes it.
                        leaders.insert(next);
                    }
                    Flow::Jump(to) => {
                        refs.push(Ref {
                            from: addr,
                            to,
                            kind: RefKind::Jump,
                        });
                        target(to, &tracker, &mut leaders, &mut pending);
                        break;
                    }
                    Flow::JumpSlot(slot) => {
                        refs.push(Ref {
                            from: addr,
                            to: slot,
                            kind: RefKind::Jump,
                        });
                        break;
                    }
                    Flow::JumpMemory(_) | Flow::JumpRegister(_) => {
                        let table = tracker.jump(insn.flow);
                        let targets = table
                            .map(|table| table.targets(&self.memory, self.table_entries))
                            .unwrap_or_default();
                        cases.insert(addr, u32::try_from(targets.len()).unwrap_or(u32::MAX));
                        for to in targets {
                            refs.push(Ref {
                                from: addr,
                                to,
                                kind: RefKind::Case,
                            });
                            target(to, &tracker, &mut leaders, &mut pending);
                        }
                        break;
                    }
                    Flow::JumpIndirect | Flow::Return | Flow::Stop => break,
                }
                addr = next;
            }
        }

        let (blocks, edges, exits) = self.graph(entry, &insns, &leaders, &ends, &cases);
        let complexity = (i64::from(edges) - i64::from(blocks) + 2 * i64::from(exits)).max(0);
        let low = insns.keys().next().copied().unwrap_or(entry);
        let high = insns
            .iter()
            .map(|(&addr, insn)| addr.saturating_add(u64::from(insn.len)))
            .max()
            .unwrap_or(entry);
        refs.sort_by_key(|r| (r.from, r.to));
        let thunk = self.thunk(entry);
        Explored {
            function: Function {
                entry,
                size: high.saturating_sub(low),
                blocks,
                edges,
                complexity: u32::try_from(complexity).unwrap_or(u32::MAX),
                refs,
                thunk,
                // Filled in once every caller is known.
                found: Found::default(),
            },
            calls,
            mains,
            runs: runs(&insns),
        }
    }

    /// Count blocks, edges and exit blocks: a block starts at each leader
    /// that was decoded and runs to its terminator or the next leader.
    fn graph(
        &self,
        entry: u64,
        insns: &BTreeMap<u64, Insn>,
        leaders: &BTreeSet<u64>,
        ends: &HashSet<u64>,
        cases: &HashMap<u64, u32>,
    ) -> (u32, u32, u32) {
        let (mut blocks, mut edges, mut exits) = (0_u32, 0_u32, 0_u32);
        for &leader in leaders {
            if !insns.contains_key(&leader) {
                continue;
            }
            blocks = blocks.saturating_add(1);
            let mut addr = leader;
            while let Some(insn) = insns.get(&addr) {
                let (out, exit) = match insn.flow {
                    _ if ends.contains(&addr) => (0, true),
                    Flow::Jump(_) => (1, false),
                    Flow::Branch(_) => (2, false),
                    Flow::JumpMemory(_) | Flow::JumpRegister(_) => {
                        (cases.get(&addr).copied().unwrap_or(0), true)
                    }
                    Flow::JumpSlot(_) | Flow::JumpIndirect | Flow::Return | Flow::Stop => (0, true),
                    _ => {
                        let next = addr.wrapping_add(u64::from(insn.len));
                        if leaders.contains(&next) && insns.contains_key(&next) {
                            (1, false)
                        } else if insns.contains_key(&next) {
                            addr = next;
                            continue;
                        } else if next != entry && self.entries.contains_key(&next) {
                            // Falls into the next function.
                            (1, false)
                        } else {
                            (0, true)
                        }
                    }
                };
                edges = edges.saturating_add(out);
                exits = exits.saturating_add(u32::from(exit));
                break;
            }
        }
        (blocks, edges, exits)
    }
}

/// The contiguous address ranges a function's instructions occupy.
fn runs(insns: &BTreeMap<u64, Insn>) -> Vec<(u64, u64)> {
    let mut runs: Vec<(u64, u64)> = Vec::new();
    for (&addr, insn) in insns {
        let end = addr.saturating_add(u64::from(insn.len));
        match runs.last_mut() {
            Some(last) if last.1 >= addr => last.1 = last.1.max(end),
            _ => runs.push((addr, end)),
        }
    }
    runs
}
