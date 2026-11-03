//! Function discovery and control-flow graphs.

pub(crate) mod table;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use crate::functions::table::Tracker;
use crate::isa::{Decoder, Flow, Insn, Memory, Note};
use crate::{Binary, Found, Function, Functions, Limits, Origin, Ref, RefKind};

/// Functions that never return, by name. Rizin's list, so a call to one ends
/// its basic block in both tools.
const NORETURN: &[&str] = &[
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
    // Go's runtime: panics, fatal errors and the bounds-check failures the
    // compiler calls (whose padding after the call is no code).
    "runtime.abort",
    "runtime.exit",
    "runtime.fatal",
    "runtime.fatalpanic",
    "runtime.fatalthrow",
    "runtime.gopanic",
    "runtime.goPanicExtendIndex",
    "runtime.goPanicExtendIndexU",
    "runtime.goPanicExtendSlice3Acap",
    "runtime.goPanicIndex",
    "runtime.goPanicIndexU",
    "runtime.goPanicSlice3Acap",
    "runtime.goPanicSlice3Alen",
    "runtime.goPanicSliceAcap",
    "runtime.goPanicSliceAlen",
    "runtime.goPanicSliceB",
    "runtime.goexit0",
    "runtime.panicIndex",
    "runtime.panicIndexU",
    "runtime.panicSlice3Acap",
    "runtime.panicSlice3Alen",
    "runtime.panicSlice3B",
    "runtime.panicSlice3C",
    "runtime.panicSliceAcap",
    "runtime.panicSliceAlen",
    "runtime.panicSliceB",
    "runtime.panicSliceConvert",
    "runtime.panicdivide",
    "runtime.panicdottypeE",
    "runtime.panicdottypeI",
    "runtime.panicmem",
    "runtime.panicmemAddr",
    "runtime.panicnildottype",
    "runtime.panicshift",
    "runtime.panicunsafeslicelen",
    "runtime.panicwrap",
    "runtime.throw",
];

/// C runtime start routines, and which of their arguments is `main`.
/// How deep a call chain the walk that decides whether a call returns
/// follows (`_start_c` -> `__libc_start_main` -> `exit` -> `_Exit`).
const RETURN_DEPTH: u8 = 6;

/// The most instructions that walk decodes in one function.
const RETURN_WALK: usize = 1 << 12;

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

/// What recovery knows about a function beyond what consumers read: kept
/// for the golden fixtures and the comparison tools.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Detail {
    /// Control-flow edges between blocks, including edges that leave the
    /// function (tail calls) and one per jump-table entry.
    pub(crate) edges: u32,
    /// The import slot the function only jumps through: a PLT entry, a
    /// Mach-O stub, an import thunk.
    pub(crate) thunk: Option<u64>,
    /// Every way its entry was found.
    pub(crate) found: Found,
}

/// Recover the functions of `image`, and each one's [`Detail`], in the same
/// (entry) order.
pub(crate) fn recover(image: &Binary<'_>, limits: &Limits) -> (Functions, Vec<Detail>) {
    let Some(arch) = image.arch else {
        return (Functions::default(), Vec::new());
    };
    let mut work = Work {
        memory: Memory::for_arch(&image.segments, arch),
        decoder: Decoder::new(image, arch),
        budget: limits.instructions,
        table_entries: limits.table_entries,
        truncated: false,
        entries: BTreeMap::new(),
        imports: image.slots.iter().map(|slot| slot.slot).collect(),
        rebased: image.rebased.iter().copied().collect(),
        noreturn: HashSet::new(),
        returns: HashMap::new(),
        return_budget: limits.instructions / 4,
        thunks: HashMap::new(),
        pools: HashSet::new(),
        handlers: HashMap::new(),
        starts: HashMap::new(),
        explored: HashSet::new(),
        extents: HashMap::new(),
    };
    for extent in &image.extents {
        if extent.start < extent.end {
            let end = work.extents.entry(extent.start).or_insert(extent.end);
            *end = (*end).max(extent.end);
        }
    }
    for handler in &image.handlers {
        work.handlers
            .entry(handler.function)
            .or_default()
            .push(handler.addr);
    }
    for import in &image.slots {
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
    let (mut invalid, mut unresolved) = (0_u64, 0_u64);
    let mut queue: Vec<u64> = work.entries.keys().rev().copied().collect();
    let mut done = HashSet::new();
    let mut scanned = false;
    // Addresses code builds, kept for when everything called is explored.
    let mut noted = BTreeSet::new();
    // Where explored code jumps or branches to: block starts.
    let mut targets = HashSet::new();
    loop {
        let Some(entry) = queue.pop() else {
            // An address code builds may be an integer that happens to fall
            // in code: one inside a function explored is no function's
            // start, unless code jumps there or it sets up a frame.
            if !noted.is_empty() {
                let merged = merge(&runs);
                for pointer in std::mem::take(&mut noted) {
                    let frame = work
                        .memory
                        .code(pointer)
                        .is_some_and(|code| work.decoder.starts_frame(code));
                    if (frame || targets.contains(&pointer) || !inside(&merged, pointer))
                        && let Some(entry) =
                            work.add_entry(pointer, Found::POINTER, limits.functions)
                    {
                        queue.push(entry);
                    }
                }
                continue;
            }
            // Last, functions reached only through a table of addresses in
            // data (a stripped static binary's callbacks).
            if scanned {
                break;
            }
            scanned = true;
            for pointer in data_pointers(image, arch, &work, &runs) {
                if let Some(entry) = work.add_entry(pointer, Found::POINTER, limits.functions) {
                    queue.push(entry);
                }
            }
            continue;
        };
        // A start another function absorbed is gone from the entries.
        if !work.entries.contains_key(&entry) || !done.insert(entry) {
            continue;
        }
        if work.truncated {
            break;
        }
        let explored = work.explore(entry);
        for target in explored.calls {
            if let Some(entry) = work.add_entry(target, Found::CALL, limits.functions) {
                queue.push(entry);
            }
        }
        for main in explored.mains {
            if let Some(entry) = work.add_entry(main, Found::MAIN, limits.functions) {
                queue.push(entry);
            }
        }
        for tail in explored.tails {
            if let Some(entry) = work.add_entry(tail, Found::TAIL_CALL, limits.functions) {
                queue.push(entry);
            }
        }
        for pointer in explored.pointers {
            if work.entries.contains_key(&pointer) {
                work.add_entry(pointer, Found::POINTER, limits.functions);
            } else {
                noted.insert(pointer);
            }
        }
        runs.extend(explored.runs);
        targets.extend(
            explored
                .function
                .refs
                .iter()
                .filter(|r| r.kind != crate::RefKind::Call)
                .map(|r| r.to),
        );
        invalid = invalid.saturating_add(explored.invalid);
        unresolved = unresolved.saturating_add(explored.unresolved);
        functions.push((explored.function, explored.detail));
    }
    // Callers explored after a function add to how it was found. A name
    // comes from a symbol, then an export, then the import a thunk reaches.
    let mut names: HashMap<u64, &str> = HashMap::new();
    for seed in &image.seeds {
        if let Origin::Export(name) = &seed.origin
            && !name.is_empty()
        {
            names.entry(seed.addr).or_insert(name);
        }
    }
    for seed in &image.seeds {
        if let Origin::Symbol(name) = &seed.origin
            && !name.is_empty()
        {
            names.insert(seed.addr, name);
        }
    }
    for (function, detail) in &mut functions {
        detail.found = work
            .entries
            .get(&function.entry)
            .copied()
            .unwrap_or_default();
        function.name = names
            .get(&function.entry)
            .copied()
            .or_else(|| detail.thunk.and_then(|slot| image.import(slot)))
            .map(str::to_owned);
    }
    functions.sort_by_key(|(function, _)| function.entry);
    let (functions, details) = functions.into_iter().unzip();
    let recovered = Functions {
        functions,
        code: image
            .segments
            .iter()
            .filter(|segment| segment.executable)
            .map(|segment| segment.bytes.len() as u64)
            .fold(0, u64::saturating_add),
        covered: covered(runs),
        invalid,
        unresolved,
        truncated: work.truncated,
    };
    (recovered, details)
}

/// Code addresses data holds where nothing recovered reaches: aligned
/// words in the segments that are not code, each pointing at code no
/// function covers that sets up a frame (as only a function's first
/// instructions do). Not on Arm: a pointer to Thumb code carries bit 0, and
/// an even word into Thumb code is no function's address.
fn data_pointers(
    image: &Binary<'_>,
    arch: crate::Arch,
    work: &Work<'_>,
    runs: &[(u64, u64)],
) -> Vec<u64> {
    if arch == crate::Arch::Arm {
        return Vec::new();
    }
    let merged = merge(runs);
    let width = usize::from(arch.address_width());
    let big = arch.big_endian();
    let align = work.decoder.alignment();
    let mut found = BTreeSet::new();
    let mut candidate = |value: u64| {
        if value.is_multiple_of(align)
            && !work.entries.contains_key(&value)
            && !found.contains(&value)
            && work
                .memory
                .code(value)
                .is_some_and(|code| work.decoder.starts_frame(code))
            && !inside(&merged, value)
        {
            found.insert(value);
        }
    };
    // Slots the loader fills (RELA's `RELATIVE`, whose slot holds zero).
    for &(_, value) in &image.rebased {
        candidate(value);
    }
    for segment in image.segments.iter().filter(|segment| !segment.executable) {
        let start = segment.addr.next_multiple_of(width as u64) - segment.addr;
        let Some(words) = segment
            .bytes
            .get(usize::try_from(start).unwrap_or(usize::MAX)..)
        else {
            continue;
        };
        for word in words.chunks_exact(width) {
            let value = match (width, big) {
                (8, false) => word.try_into().map(u64::from_le_bytes),
                (8, true) => word.try_into().map(u64::from_be_bytes),
                (_, false) => word.try_into().map(u32::from_le_bytes).map(u64::from),
                (_, true) => word.try_into().map(u32::from_be_bytes).map(u64::from),
            };
            if let Ok(value) = value {
                candidate(value);
            }
        }
    }
    found.into_iter().collect()
}

/// Half-open address ranges, sorted and with overlaps joined.
fn merge(runs: &[(u64, u64)]) -> Vec<(u64, u64)> {
    let mut sorted = runs.to_vec();
    sorted.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::new();
    for (start, end) in sorted {
        match merged.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    merged
}

/// Whether `merge`'s ranges hold `addr`.
fn inside(merged: &[(u64, u64)], addr: u64) -> bool {
    let at = merged.partition_point(|&(start, _)| start <= addr);
    at > 0 && merged.get(at - 1).is_some_and(|&(_, end)| addr < end)
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
    /// Slots the loader fills with an address, and the address.
    rebased: HashMap<u64, u64>,
    /// Slots and functions whose callers never resume.
    noreturn: HashSet<u64>,
    /// Whether a call to each function may return, as far as a walk of it
    /// found.
    returns: HashMap<u64, bool>,
    /// Instructions left for those walks.
    return_budget: usize,
    /// Address -> the import slot the code there only jumps through.
    thunks: HashMap<u64, Option<u64>>,
    /// The literal-pool words the sweep stepped over: data, where no
    /// function an address or call names starts.
    pools: HashSet<u64>,
    /// Function start -> its landing pads.
    handlers: HashMap<u64, Vec<u64>>,
    /// C runtime start routines (functions and import slots) -> which
    /// argument is `main`.
    starts: HashMap<u64, usize>,
    /// Entries explored so far.
    explored: HashSet<u64>,
    /// Function start -> the end of the code unwind tables say it spans.
    extents: HashMap<u64, u64>,
}

/// One explored function, and what it found beyond itself.
struct Explored {
    function: Function,
    detail: Detail,
    /// Direct call targets.
    calls: Vec<u64>,
    /// What it passes a C runtime start routine as `main`.
    mains: Vec<u64>,
    /// Code addresses it loads: functions whose address is taken.
    pointers: Vec<u64>,
    /// Fixed addresses it jumps to through a register: tail calls.
    tails: Vec<u64>,
    /// Address ranges of its instructions.
    runs: Vec<(u64, u64)>,
    /// Instructions on its paths that do not decode.
    invalid: u64,
    /// Indirect jumps it makes to targets not known.
    unresolved: u64,
}

impl Work<'_> {
    /// Decode one instruction, or `None` when the budget is spent.
    fn decode(&mut self, bytes: &[u8], addr: u64) -> Option<Insn> {
        if self.budget == 0 {
            self.truncated = true;
            return None;
        }
        self.budget -= 1;
        let mut insn = self.decoder.decode(bytes, addr);
        // A MIPS GOT slot for a function of this binary holds its address
        // until the loader relocates it: the call or jump goes there.
        if self.decoder.slots_hold_targets() {
            let target = |slot: u64| {
                let to = self.memory.read(slot, self.decoder.address_width())?;
                (!self.imports.contains(&slot) && self.memory.is_code(to)).then_some(to)
            };
            insn.flow = match insn.flow {
                Flow::CallSlot(slot) => target(slot).map_or(insn.flow, Flow::Call),
                Flow::JumpSlot(slot) => target(slot).map_or(insn.flow, Flow::Jump),
                flow => flow,
            };
        }
        Some(insn)
    }

    /// Record a function start inside code, found `how`: the function's
    /// own entry, when `addr` is one past the start (64-bit ELFv2's local
    /// entry). The entry, when it is new.
    fn add_entry(&mut self, addr: u64, how: Found, most: usize) -> Option<u64> {
        let addr = addr
            .checked_sub(8)
            .and_then(|before| self.memory.code(before))
            .map_or(addr, |before| self.decoder.global_entry(addr, before));
        if let Some(found) = self.entries.get_mut(&addr) {
            *found |= how;
            return None;
        }
        if !self.memory.is_code(addr) {
            return None;
        }
        let inferred = Found::CALL | Found::SWEEP | Found::TAIL_CALL | Found::POINTER;
        if inferred.contains(how) && self.pools.contains(&(addr & !3)) {
            return None;
        }
        // An address only taken, never called, is a function's when it is
        // as aligned as functions are.
        if how == Found::POINTER && !addr.is_multiple_of(self.decoder.function_alignment()) {
            return None;
        }
        if self.entries.len() >= most {
            self.truncated = true;
            return None;
        }
        self.entries.insert(addr, how);
        Some(addr)
    }

    /// Linear sweep of every code segment for direct calls into code,
    /// direct jumps to code that starts a frame, and code only a function
    /// starts with (64-bit ELFv2's global entry). (Code after `int3` padding
    /// is no sign of a function: MSVC aligns jump targets inside functions
    /// with it.) Windows of bytes as random as compressed or encrypted data
    /// (a packer's payload kept in `.text`) are skipped: what decodes there
    /// is noise, and its calls go nowhere real.
    /// Record the literal-pool words a segment's `l32r`s read, so the
    /// sweep steps over them as data. A linear decode finds them; where it
    /// strays into a pool it resyncs within a few instructions, and a word
    /// another `l32r` names is skipped so the stray is brief.
    fn collect_literals(&mut self, base: u64, bytes: &[u8]) {
        self.decoder.reset();
        let mut offset = 0_usize;
        while let Some(rest) = bytes.get(offset..).filter(|rest| !rest.is_empty()) {
            let addr = base.wrapping_add(offset as u64);
            if addr.is_multiple_of(4) && self.pools.contains(&addr) {
                offset = offset.saturating_add(4);
                self.decoder.reset();
                continue;
            }
            if let Some(pool) = self.decoder.literal(rest, addr) {
                self.pools.insert(pool);
            }
            let len = self.decoder.decode(rest, addr).len.max(1);
            offset = offset.saturating_add(usize::try_from(len).unwrap_or(1));
        }
        self.decoder.reset();
    }

    fn sweep(&mut self, most: usize) {
        let segments: Vec<(u64, &[u8])> = self
            .memory
            .code_segments()
            .map(|segment| (segment.addr, segment.bytes))
            .collect();
        let step = self.decoder.alignment();
        let mode = self.decoder.sweep_mode();
        let behind = self.decoder.literals_behind();
        for (base, bytes) in &segments {
            if behind {
                self.collect_literals(*base, bytes);
            }
        }
        for (base, bytes) in segments {
            self.decoder.reset();
            let mut offset = 0_usize;
            let mut window = usize::MAX;
            // Literal-pool words ahead, which hold data.
            let mut pools = BTreeSet::new();
            // Whether only padding and pools have followed a pool or the
            // end of a block: the code after that starts a function when
            // it sets up a frame (one nothing calls, in a static binary).
            // Only on sets with pools, whose frames are distinctive.
            let mut after_end = false;
            while let Some(rest) = bytes.get(offset..).filter(|rest| !rest.is_empty()) {
                if offset / WINDOW != window {
                    window = offset / WINDOW;
                    let start = window * WINDOW;
                    if bytes.get(start..start + WINDOW).is_some_and(random) {
                        offset = start + WINDOW;
                        self.decoder.reset();
                        continue;
                    }
                }
                let addr = base.wrapping_add(offset as u64) | mode;
                // A literal pool found in the pass before this one: skip
                // the word as data, the way code after it would.
                if behind && addr.is_multiple_of(4) && self.pools.contains(&addr) {
                    offset = offset.saturating_add(4);
                    self.decoder.reset();
                    after_end = true;
                    continue;
                }
                while pools.first().is_some_and(|&pool| pool + 4 <= addr) {
                    pools.pop_first();
                }
                if let Some(&pool) = pools.first().filter(|&&pool| pool <= addr) {
                    self.pools.insert(pool);
                    offset = offset.saturating_add(usize::try_from(step).unwrap_or(1));
                    self.decoder.reset();
                    after_end = true;
                    continue;
                }
                if !behind && let Some(pool) = self.decoder.literal(rest, addr) {
                    pools.insert(pool);
                }
                let Some(insn) = self.decode(rest, addr) else {
                    return;
                };
                if let Some(entry) = self.decoder.entry_of(rest, addr) {
                    self.add_entry(entry, Found::SWEEP, most);
                } else if (after_end || self.decoder.calls_open_frames())
                    && addr.is_multiple_of(self.decoder.function_alignment())
                    && self.decoder.starts_frame(rest)
                {
                    self.add_entry(addr, Found::SWEEP, most);
                }
                after_end = (after_end && insn.pad)
                    || (!pools.is_empty() || !self.pools.is_empty())
                        && matches!(
                            insn.flow,
                            Flow::Return | Flow::Jump(_) | Flow::JumpRegister(_) | Flow::Stop
                        )
                        && !insn.falls;
                let framed = |work: &Self, target| {
                    !work.decoder.calls_open_frames()
                        || work
                            .memory
                            .code(target)
                            .is_some_and(|code| work.decoder.starts_frame(code))
                };
                // A small negative integer in a literal pool decodes as a
                // call a few bytes back (Arm's `0xfbfffffc`, `blx` six
                // bytes back): no function calls just behind itself. (A call
                // to itself is `bl .`, a weak symbol left unresolved; a call
                // just ahead may be real: musl's `_start` calls the
                // `_start_c` that follows it.) The sweep reads one Arm mode;
                // a call into the other (a `blx` from A32) is more often a
                // data word (`0xfafafafa`) than code, and a walk follows the
                // real ones.
                let near = |target: u64| target < (addr & !1) && (addr & !1) - target <= 16;
                let same_mode = |target: u64| target & 1 == mode;
                match insn.flow {
                    Flow::Call(target)
                        if framed(self, target) && !near(target) && same_mode(target) =>
                    {
                        self.add_entry(target, Found::SWEEP, most);
                    }
                    Flow::Jump(target) if !self.decoder.frames_late() => {
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
        // A stub is a jump through a slot, after at most five instructions
        // of padding or the address arithmetic that finds the slot (on
        // 64-bit PowerPC, a TOC save and restore around the load as well).
        for _ in 0..6 {
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
                Flow::Next if insn.pad || self.decoder.stub_arithmetic() => {
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

    /// Whether a call to `target`, which would resume at `next`, never
    /// returns: by name, or, when what follows the call soon fails to
    /// decode (the data word after musl's call to `_start_c`, past the TOC
    /// restore a 64-bit PowerPC call leaves), by a walk of the callee.
    /// rizin infers no more (a stripped `abort` wrapper's callers run on
    /// into their padding), and binform matches it there.
    fn never_returns(&mut self, target: u64, next: u64) -> bool {
        if self.named_noreturn(target) {
            return true;
        }
        // The delay slot, then two instructions.
        let mut decoder = self.decoder.clone();
        let mut at = next;
        let mut nothing = false;
        for i in 0..2 + u8::from(self.decoder.delay_slots()) {
            let Some(bytes) = self.memory.code(at) else {
                nothing = true;
                break;
            };
            let insn = decoder.decode(bytes, at);
            if insn.flow == Flow::Invalid {
                nothing = true;
                break;
            }
            if insn.flow != Flow::Next && !(i == 0 && self.decoder.delay_slots()) {
                break;
            }
            at = at.wrapping_add(u64::from(insn.len));
        }
        nothing && !self.may_return(target, RETURN_DEPTH)
    }

    /// Whether `target` is a function, or a stub of an import, known by
    /// name never to return.
    fn named_noreturn(&mut self, target: u64) -> bool {
        self.noreturn.contains(&target)
            || self
                .thunk(target)
                .is_some_and(|slot| self.noreturn.contains(&slot))
    }

    /// Whether a call to `target` may return: false only when no path
    /// through the code it reaches does, as in a stripped binary's `exit`,
    /// `abort` and `_start_c` (each path ends in a trap, a loop, or a call
    /// that never returns). Anything not followed (an indirect jump, an
    /// instruction that does not decode, a long walk) may return. A call
    /// chain back into a function still being walked counts as returning.
    fn may_return(&mut self, target: u64, depth: u8) -> bool {
        if let Some(&known) = self.returns.get(&target) {
            return known;
        }
        if depth == 0 || self.return_budget == 0 {
            return true;
        }
        self.returns.insert(target, true);
        let returns = self.walk_returns(target, depth);
        self.returns.insert(target, returns);
        returns
    }

    fn walk_returns(&mut self, target: u64, depth: u8) -> bool {
        let mut decoder = self.decoder.clone();
        let mut seen = HashSet::new();
        let mut pending = vec![target];
        while let Some(start) = pending.pop() {
            decoder.reset();
            let mut addr = start;
            while seen.insert(addr) {
                if seen.len() > RETURN_WALK || self.return_budget == 0 {
                    return true;
                }
                self.return_budget -= 1;
                let Some(bytes) = self.memory.code(addr) else {
                    return true;
                };
                let insn = decoder.decode(bytes, addr);
                let callee_returns = |work: &mut Self, to: u64| {
                    !work.named_noreturn(to) && work.may_return(to, depth - 1)
                };
                let ends = match insn.flow {
                    Flow::Next | Flow::CallIndirect | Flow::CallRegister(_) => false,
                    Flow::Branch(to) => {
                        pending.push(to);
                        false
                    }
                    Flow::Call(to) => !callee_returns(self, to),
                    Flow::CallSlot(slot) => self.noreturn.contains(&slot),
                    // A jump to another function's start returns when it does.
                    Flow::Jump(to) if to != target && self.entries.contains_key(&to) => {
                        if callee_returns(self, to) {
                            return true;
                        }
                        true
                    }
                    Flow::Jump(to) => {
                        pending.push(to);
                        true
                    }
                    Flow::JumpSlot(slot) if self.noreturn.contains(&slot) => !insn.falls,
                    Flow::Stop => !insn.falls,
                    Flow::Return
                    | Flow::Invalid
                    | Flow::JumpSlot(_)
                    | Flow::JumpMemory(_)
                    | Flow::JumpRegister(_)
                    | Flow::JumpAdd { .. }
                    | Flow::JumpTable { .. }
                    | Flow::JumpIndirect => return true,
                };
                if ends {
                    break;
                }
                addr = addr.wrapping_add(u64::from(insn.len));
            }
        }
        false
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
        let mut pointers = Vec::new();
        let mut tails = Vec::new();
        let mut ends = HashSet::new(); // calls that never return
        let mut cases: HashMap<u64, u32> = HashMap::new();
        let (mut invalid, mut unresolved) = (0_u64, 0_u64);
        let extent = self.extents.get(&entry).copied();
        // How far into the extent the search for unreached code has come.
        let mut cursor = entry;

        loop {
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
                        falls = insn.falls || matches!(insn.flow, Flow::Next | Flow::Branch(_));
                    }
                    let next = addr.wrapping_add(u64::from(insn.len));
                    let target =
                        |to: u64,
                         tracker: &Tracker,
                         leaders: &mut BTreeSet<u64>,
                         pending: &mut Vec<(u64, Tracker)>| {
                            // A jump to another function's start is a tail call.
                            let local = to == entry || !self.entries.contains_key(&to);
                            if local && self.memory.is_code(to) && leaders.insert(to) {
                                pending.push((to, tracker.clone()));
                            }
                        };
                    if let Note::Address { addr: to, .. } = insn.note
                        && self.decoder.notes_pointers()
                        && to.is_multiple_of(self.decoder.alignment())
                        && to != entry
                        && self.memory.is_code(to)
                    {
                        pointers.push(to);
                    }
                    // Branches and calls only read registers; what a call
                    // changes, `call` forgets below.
                    // A compare-and-branch bounds a case value too. A delay
                    // slot runs before a call or jump arrives.
                    if matches!(insn.flow, Flow::Next | Flow::Branch(_))
                        || matches!(insn.note, Note::Pc { .. })
                        || (self.decoder.delay_slots()
                            && matches!(
                                insn.flow,
                                Flow::Call(_)
                                    | Flow::CallIndirect
                                    | Flow::CallSlot(_)
                                    | Flow::Jump(_)
                            ))
                    {
                        let note = match insn.note {
                            // A slot of this binary that holds an address.
                            Note::Fetch {
                                reg,
                                mem,
                                size,
                                signed,
                            } => tracker
                                .fixed(mem)
                                .filter(|slot| !self.imports.contains(slot))
                                .and_then(|slot| match self.memory.read(slot, size) {
                                    Some(0) | None => self.rebased.get(&slot).copied(),
                                    value => value,
                                })
                                .map(|value| {
                                    let shift = 64 - 8 * u32::from(size.clamp(1, 8));
                                    if signed {
                                        ((value << shift).cast_signed() >> shift).cast_unsigned()
                                    } else {
                                        value
                                    }
                                })
                                .map_or(Note::Write(reg), |addr| Note::Address { reg, addr }),
                            note => note,
                        };
                        tracker.note(note);
                    }
                    // A register holding a fixed address of code: a call
                    // there. The walk below sees which.
                    let flow = match insn.flow {
                        Flow::CallRegister(reg) => tracker
                            .held(reg)
                            .filter(|&to| self.memory.is_code(to))
                            .map_or(Flow::CallIndirect, Flow::Call),
                        flow => flow,
                    };
                    match flow {
                        Flow::Next => {}
                        Flow::CallIndirect | Flow::CallRegister(_) => {
                            tracker.call(self.decoder.call_preserved());
                        }
                        Flow::Call(to) => {
                            mains.extend(self.main(entry, to, next, &tracker));
                            tracker.call(self.decoder.call_preserved());
                            // A PC thunk returns the address after the call.
                            let thunk = self
                                .memory
                                .code(to)
                                .and_then(|code| self.decoder.pc_thunk(code, addr, next));
                            if let Some(note) = thunk {
                                tracker.note(note);
                            }
                            refs.push(Ref {
                                from: addr,
                                to,
                                kind: RefKind::Call,
                            });
                            calls.push(to);
                            if self.never_returns(to, next) {
                                ends.insert(addr);
                                break;
                            }
                        }
                        Flow::CallSlot(slot) => {
                            mains.extend(self.main(entry, slot, next, &tracker));
                            tracker.call(self.decoder.call_preserved());
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
                            if !insn.falls {
                                break;
                            }
                        }
                        // A register holding a fixed address of code: a
                        // tail call, as code of this function would be
                        // reached by a direct branch (musl's PowerPC start
                        // code computes the next stage's address from the
                        // PC; s390x `larl %r1, f; br %r1`).
                        Flow::JumpRegister(reg)
                            if tracker
                                .held(reg)
                                .is_some_and(|to| to != entry && self.memory.is_code(to)) =>
                        {
                            let to = tracker.held(reg).unwrap_or_default();
                            refs.push(Ref {
                                from: addr,
                                to,
                                kind: RefKind::Jump,
                            });
                            tails.push(to);
                            if !insn.falls {
                                break;
                            }
                        }
                        Flow::JumpMemory(_)
                        | Flow::JumpRegister(_)
                        | Flow::JumpAdd { .. }
                        | Flow::JumpTable { .. } => {
                            let table = tracker.jump(insn.flow);
                            let mut targets = table
                                .map(|table| table.targets(&self.memory, self.table_entries))
                                .unwrap_or_default();
                            // An unbounded table ends before a target past
                            // another function's start: the next table, of
                            // the next function (glibc's printf variants).
                            if table.is_some_and(|table| !table.bounded()) {
                                let crosses = |to: u64| {
                                    let (low, high) = (addr.min(to), addr.max(to));
                                    self.entries
                                        .range(low.wrapping_add(1)..=high)
                                        .next()
                                        .is_some()
                                };
                                if let Some(end) = targets.iter().position(|&to| crosses(to)) {
                                    targets.truncate(end);
                                }
                            }
                            cases.insert(addr, u32::try_from(targets.len()).unwrap_or(u32::MAX));
                            if targets.is_empty() {
                                unresolved = unresolved.saturating_add(1);
                            }
                            for to in targets {
                                refs.push(Ref {
                                    from: addr,
                                    to,
                                    kind: RefKind::Case,
                                });
                                target(to, &tracker, &mut leaders, &mut pending);
                            }
                            if !insn.falls {
                                break;
                            }
                        }
                        Flow::JumpIndirect => {
                            unresolved = unresolved.saturating_add(1);
                            if !insn.falls {
                                break;
                            }
                        }
                        Flow::Invalid => {
                            invalid = invalid.saturating_add(1);
                            break;
                        }
                        Flow::Return | Flow::Stop if !insn.falls => break,
                        Flow::Return | Flow::Stop => {}
                    }
                    // A conditional return or jump ends its block; the code
                    // after it, reached when the condition fails, starts one.
                    if insn.falls {
                        leaders.insert(next);
                    }
                    addr = next;
                }
            }
            // After a jump to targets not known, code the unwind table gives
            // this function that no path reached is reached from there: the
            // cases of a table without a bound (a switch on an enum the
            // compiler knows the range of).
            let Some(end) = extent.filter(|_| unresolved > 0) else {
                break;
            };
            let Some(gap) = self.unreached(entry, end, &mut cursor, &insns) else {
                break;
            };
            leaders.insert(gap);
            pending.push((gap, Tracker::new(self.decoder.address_width())));
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
                // Filled in once every function is known.
                name: None,
                size: high.saturating_sub(low),
                blocks,
                complexity: u32::try_from(complexity).unwrap_or(u32::MAX),
                refs,
            },
            detail: Detail {
                edges,
                thunk,
                // Filled in once every caller is known.
                found: Found::default(),
            },
            calls,
            mains,
            pointers,
            tails,
            runs: runs(&insns),
            invalid,
            unresolved,
        }
    }

    /// The first instruction from `cursor` up to `end` that no path of the
    /// function at `entry` decoded, past padding. `None` at `end`, at
    /// another function's start, and at bytes that do not decode: the
    /// unwind table was wrong, or the bytes are data.
    fn unreached(
        &mut self,
        entry: u64,
        end: u64,
        cursor: &mut u64,
        insns: &BTreeMap<u64, Insn>,
    ) -> Option<u64> {
        self.decoder.reset();
        while *cursor < end {
            let at = *cursor;
            if let Some((&addr, insn)) = insns.range(..=at).next_back() {
                let past = addr.saturating_add(u64::from(insn.len));
                if past > at {
                    *cursor = past;
                    continue;
                }
            }
            if at != entry && self.entries.contains_key(&at) {
                return None;
            }
            let insn = self.decode(self.memory.code(at)?, at)?;
            if insn.flow == Flow::Invalid {
                return None;
            }
            if !insn.pad {
                return Some(at);
            }
            *cursor = at.saturating_add(u64::from(insn.len));
        }
        None
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
                // A conditional return or jump also runs into the next block.
                let falls = u32::from(insn.falls);
                let (out, exit) = match insn.flow {
                    _ if ends.contains(&addr) => (0, true),
                    Flow::Jump(_) => (1, false),
                    Flow::Branch(_) => (2, false),
                    Flow::JumpMemory(_)
                    | Flow::JumpRegister(_)
                    | Flow::JumpAdd { .. }
                    | Flow::JumpTable { .. } => (
                        cases.get(&addr).copied().unwrap_or(0).saturating_add(falls),
                        true,
                    ),
                    Flow::JumpSlot(_) | Flow::JumpIndirect | Flow::Return | Flow::Stop => {
                        (falls, true)
                    }
                    Flow::Invalid => (0, true),
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

/// The contiguous address ranges a function's instructions occupy. Bytes
/// that do not decode are no instruction.
fn runs(insns: &BTreeMap<u64, Insn>) -> Vec<(u64, u64)> {
    let mut runs: Vec<(u64, u64)> = Vec::new();
    for (&addr, insn) in insns.iter().filter(|(_, insn)| insn.flow != Flow::Invalid) {
        let end = addr.saturating_add(u64::from(insn.len));
        match runs.last_mut() {
            Some(last) if last.1 >= addr => last.1 = last.1.max(end),
            _ => runs.push((addr, end)),
        }
    }
    runs
}

/// The bytes the sweep judges a window at a time.
const WINDOW: usize = 1024;

/// Whether `bytes` are as random as compressed or encrypted data: more than
/// 7.5 bits of entropy a byte. Machine code, even dense Thumb-2, stays
/// under 7.2 over a kilobyte; random bytes come to about 7.8.
fn random(bytes: &[u8]) -> bool {
    let mut counts = [0_u32; 256];
    for &byte in bytes {
        if let Some(count) = counts.get_mut(usize::from(byte)) {
            *count += 1;
        }
    }
    let total = f64::from(u32::try_from(bytes.len()).unwrap_or(u32::MAX));
    let entropy: f64 = counts
        .iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let p = f64::from(count) / total;
            -p * p.log2()
        })
        .sum();
    entropy > 7.5
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn randomness() {
        // A xorshift stream: random. A repeated instruction pattern: not.
        let mut x = 0x2545_f491_u32;
        let noise: Vec<u8> = (0..WINDOW)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                x.to_le_bytes()[0]
            })
            .collect();
        assert!(random(&noise));
        let code: Vec<u8> = [0x55, 0x48, 0x89, 0xe5, 0xc3]
            .iter()
            .copied()
            .cycle()
            .take(WINDOW)
            .collect();
        assert!(!random(&code));
    }
}
