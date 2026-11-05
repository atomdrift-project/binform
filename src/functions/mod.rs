//! Function discovery and control-flow graphs.

pub(crate) mod table;

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use crate::functions::table::Tracker;
use crate::isa::{Decoder, Flow, Insn, Mem, Memory, Note};
use crate::{Arch, Binary, Dest, Found, Function, Limits, Origin, Recovery, Ref, RefKind};

/// Functions that never return, by name: a call to one ends its basic block.
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

/// How deep a call chain the walk that decides whether a call returns
/// follows (`_start_c` -> `__libc_start_main` -> `exit` -> `_Exit`).
const RETURN_DEPTH: u8 = 6;

/// The most instructions that walk decodes in one function.
const RETURN_WALK: usize = 1 << 12;

/// The share of the instruction budget, one part in this many, that the
/// walks deciding whether calls return may spend between them.
const RETURN_SHARE: usize = 4;

/// The most instructions a stub runs before its jump through a slot: up to
/// five of padding or of the address arithmetic that finds the slot (on
/// 64-bit PowerPC, a TOC save and restore around the load as well).
const STUB_INSNS: usize = 6;

/// How far back, in bytes, a call the sweep finds is taken for a literal
/// word rather than code: no function calls just behind itself.
const NEAR_BEHIND: u64 = 16;

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
    let names = c_names(name);
    STARTS
        .iter()
        .find_map(|&(start, argument)| names.contains(&start).then_some(argument))
}

/// What recovery knows about a function beyond [`Function`]: how it was
/// found, how its blocks connect, and the slot a stub jumps through.
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
pub(crate) fn recover(image: &Binary<'_>, limits: &Limits) -> (Recovery, Vec<Detail>) {
    let Some(arch) = image.arch else {
        return (Recovery::default(), Vec::new());
    };
    let mut work = Work {
        memory: Memory::for_arch(&image.segments, arch),
        decoder: Decoder::new(image, arch),
        budget: limits.instructions,
        table_entries: limits.table_entries,
        truncated: false,
        entries: BTreeMap::new(),
        imports: image
            .slots
            .iter()
            .map(|slot| (slot.slot, slot.import))
            .collect(),
        rebased: image.rebased.iter().copied().collect(),
        noreturn: HashSet::new(),
        returns: HashMap::new(),
        return_budget: limits.instructions / RETURN_SHARE,
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
    let mut runs = Runs::default();
    // Each function's own runs.
    let mut decoded = HashMap::new();
    let (mut invalid, mut unresolved) = (0_u64, 0_u64);
    let mut queue: Vec<u64> = work.entries.keys().rev().copied().collect();
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
                for pointer in std::mem::take(&mut noted) {
                    let frame = work
                        .memory
                        .code(pointer)
                        .is_some_and(|code| work.decoder.starts_frame(code));
                    if frame || targets.contains(&pointer) || !runs.contains(pointer) {
                        queue.extend(work.add_entry(pointer, Found::POINTER, limits.functions));
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
                queue.extend(work.add_entry(pointer, Found::POINTER, limits.functions));
            }
            continue;
        };
        // A start another function absorbed is gone from the entries.
        if !work.entries.contains_key(&entry) || work.explored.contains(&entry) {
            continue;
        }
        if work.truncated {
            break;
        }
        let explored = work.explore(entry);
        for target in explored.calls {
            queue.extend(work.add_entry(target, Found::CALL, limits.functions));
        }
        for main in explored.mains {
            queue.extend(work.add_entry(main, Found::MAIN, limits.functions));
        }
        for tail in explored.tails {
            queue.extend(work.add_entry(tail, Found::TAIL_CALL, limits.functions));
        }
        for pointer in explored.pointers {
            if work.entries.contains_key(&pointer) {
                work.add_entry(pointer, Found::POINTER, limits.functions);
            } else {
                noted.insert(pointer);
            }
        }
        for &(start, end) in &explored.runs {
            runs.insert(start, end);
        }
        decoded.insert(explored.function.entry, explored.runs);
        targets.extend(
            explored
                .function
                .refs
                .iter()
                .filter(|r| r.kind != RefKind::Call)
                .map(Ref::addr),
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
            .or_else(|| {
                let (_, import) = image.import(detail.thunk?)?;
                Some(import.name.as_str())
            })
            .map(str::to_owned);
    }
    // Each entry is explored once.
    functions.sort_unstable_by_key(|(function, _)| function.entry);
    let stubs = functions
        .iter()
        .filter_map(|(function, detail)| Some((function.entry, detail.thunk?)))
        .collect();
    let (functions, details) = functions.into_iter().unzip();
    let recovered = Recovery {
        functions,
        code: image
            .segments
            .iter()
            .filter(|segment| segment.executable)
            .map(|segment| segment.bytes.len() as u64)
            .fold(0, u64::saturating_add),
        covered: runs.bytes(),
        invalid,
        unresolved,
        truncated: work.truncated,
        stubs,
        runs: decoded,
    };
    (recovered, details)
}

/// Code addresses data holds where nothing recovered reaches: aligned
/// words in the segments that are not code, each pointing at code no
/// function covers that sets up a frame (as only a function's first
/// instructions do). Not on Arm: a pointer to Thumb code carries bit 0, and
/// an even word into Thumb code is no function's address.
fn data_pointers(image: &Binary<'_>, arch: Arch, work: &Work<'_>, runs: &Runs) -> Vec<u64> {
    if arch == Arch::Arm {
        return Vec::new();
    }
    let width = usize::from(arch.address_width());
    let big = arch.big_endian();
    let align = work.decoder.alignment();
    let mut found = BTreeSet::new();
    // Most words are no code address: that is asked first, as it is the
    // quickest to answer.
    let mut candidate = |value: u64| {
        if value.is_multiple_of(align)
            && let Some(code) = work.memory.code(value)
            && !work.entries.contains_key(&value)
            && !found.contains(&value)
            && work.decoder.starts_frame(code)
            && !runs.contains(value)
        {
            found.insert(value);
        }
    };
    // Slots the loader fills (RELA's `RELATIVE`, whose slot holds zero).
    for &(_, value) in &image.rebased {
        candidate(value);
    }
    // Each byte once, however many segments claim it.
    for segment in work.memory.spans().filter(|span| !span.executable) {
        // Words aligned in the address space; a segment that ends the
        // address space has none past its last aligned one.
        let skip = segment
            .addr
            .checked_next_multiple_of(width as u64)
            .map_or(u64::MAX, |aligned| aligned.wrapping_sub(segment.addr));
        let Some(words) = segment
            .bytes
            .get(usize::try_from(skip).unwrap_or(usize::MAX)..)
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

/// Half-open address ranges, joined where they overlap or touch: start ->
/// end.
#[derive(Default)]
struct Runs(BTreeMap<u64, u64>);

impl Runs {
    fn insert(&mut self, mut start: u64, mut end: u64) {
        if start >= end {
            return;
        }
        if let Some((&before, &reach)) = self.0.range(..=start).next_back()
            && reach >= start
        {
            start = before;
            end = end.max(reach);
        }
        while let Some((&inner, &reach)) = self.0.range(start..=end).next() {
            self.0.remove(&inner);
            end = end.max(reach);
        }
        self.0.insert(start, end);
    }

    fn contains(&self, addr: u64) -> bool {
        self.0
            .range(..=addr)
            .next_back()
            .is_some_and(|(_, &end)| addr < end)
    }

    /// Bytes in the union.
    fn bytes(&self) -> u64 {
        self.0
            .iter()
            .map(|(&start, &end)| end.saturating_sub(start))
            .fold(0, u64::saturating_add)
    }
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
    /// Import slots, and the import of each.
    imports: HashMap<u64, Option<usize>>,
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

/// One function's walk under way.
struct Walk {
    entry: u64,
    /// Every instruction decoded, by address.
    insns: BTreeMap<u64, Decoded>,
    /// Block starts.
    leaders: BTreeSet<u64>,
    /// Block starts still to walk, with the register values on the path
    /// that found them.
    pending: Vec<(u64, Tracker)>,
    refs: Vec<Ref>,
    /// The code addresses `refs` reach, to ask of in constant time.
    referenced: HashSet<u64>,
    calls: Vec<u64>,
    mains: Vec<u64>,
    pointers: Vec<u64>,
    tails: Vec<u64>,
    /// Calls that never return.
    ends: HashSet<u64>,
    /// Indirect jump -> how many targets its table gave.
    cases: HashMap<u64, u32>,
    invalid: u64,
    unresolved: u64,
}

impl Walk {
    fn new(entry: u64) -> Self {
        Self {
            entry,
            insns: BTreeMap::new(),
            leaders: BTreeSet::from([entry]),
            pending: Vec::new(),
            refs: Vec::new(),
            referenced: HashSet::new(),
            calls: Vec::new(),
            mains: Vec::new(),
            pointers: Vec::new(),
            tails: Vec::new(),
            ends: HashSet::new(),
            cases: HashMap::new(),
            invalid: 0,
            unresolved: 0,
        }
    }

    fn refer(&mut self, from: u64, to: Dest, kind: RefKind) {
        if let Dest::Code(to) = to {
            self.referenced.insert(to);
        }
        self.refs.push(Ref::new(from, to, kind));
    }
}

/// What a function's graph and extent need of an instruction it decoded,
/// kept per address instead of the whole [`Insn`], which is twelve times
/// the size: maps of these are smaller and quicker to search and grow.
#[derive(Clone, Copy)]
struct Decoded {
    len: u32,
    exit: Exit,
    /// A conditional return or jump: it also runs on.
    falls: bool,
}

/// How an instruction leaves its block, if it does.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Exit {
    /// On to the next instruction: any but a transfer, and calls.
    Next,
    Jump,
    Branch,
    /// Through a table or a register: to its cases.
    Indirect,
    /// Out of the function: a return, a trap, a jump through a slot or to
    /// an unknown place.
    Leaves,
    Invalid,
}

impl From<&Insn> for Decoded {
    fn from(insn: &Insn) -> Self {
        let exit = match insn.flow {
            Flow::Next
            | Flow::Call(_)
            | Flow::CallSlot(_)
            | Flow::CallIndirect
            | Flow::CallRegister(_) => Exit::Next,
            Flow::Jump(_) => Exit::Jump,
            Flow::Branch(_) => Exit::Branch,
            Flow::JumpMemory(_)
            | Flow::JumpRegister(_)
            | Flow::JumpAdd { .. }
            | Flow::JumpTable { .. } => Exit::Indirect,
            Flow::JumpSlot(_) | Flow::JumpIndirect | Flow::Return | Flow::Stop => Exit::Leaves,
            Flow::Invalid => Exit::Invalid,
        };
        Self {
            len: insn.len,
            exit,
            falls: insn.falls,
        }
    }
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
        self.budget = self.budget.saturating_sub(1);
        let insn = self.decoder.decode(bytes, addr);
        Some(self.slot_targets(insn))
    }

    /// `insn`, with a call or jump through a slot that holds a function of
    /// this binary made direct: a MIPS GOT slot holds its function's address
    /// until the loader relocates it.
    fn slot_targets(&self, mut insn: Insn) -> Insn {
        if self.decoder.slots_hold_targets() {
            let target = |slot: u64| {
                let to = self.memory.read(slot, self.decoder.address_width())?;
                (!self.imports.contains_key(&slot) && self.memory.is_code(to)).then_some(to)
            };
            insn.flow = match insn.flow {
                Flow::CallSlot(slot) => target(slot).map_or(insn.flow, Flow::Call),
                Flow::JumpSlot(slot) => target(slot).map_or(insn.flow, Flow::Jump),
                flow => flow,
            };
        }
        insn
    }

    /// Record a function start inside code, found `how`: the function's
    /// own entry, when `addr` is one past the start (64-bit ELFv2's local
    /// entry). The entry, when it is new.
    fn add_entry(&mut self, addr: u64, how: Found, most: usize) -> Option<u64> {
        let addr = self.decoder.global_entry(addr, &self.memory);
        if let Some(found) = self.entries.get_mut(&addr) {
            *found |= how;
            return None;
        }
        if !self.memory.is_code(addr) {
            return None;
        }
        let inferred = Found::CALL | Found::SWEEP | Found::TAIL_CALL | Found::POINTER;
        // Pools hold aligned words; Thumb code addresses carry bit 0.
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

    /// Linear sweep of every code segment for direct calls into code,
    /// direct jumps to code that starts a frame, and code only a function
    /// starts with (64-bit ELFv2's global entry). (Code after `int3` padding
    /// is no sign of a function: MSVC aligns jump targets inside functions
    /// with it.) Windows of bytes as random as compressed or encrypted data
    /// (a packer's payload kept in `.text`) are skipped: what decodes there
    /// is noise, and its calls go nowhere real.
    fn sweep(&mut self, most: usize) {
        // Each byte once, however many segments claim it.
        let segments: Vec<(u64, &[u8])> = self
            .memory
            .spans()
            .filter(|span| span.executable)
            .map(|span| (span.addr, span.bytes))
            .collect();
        if self.decoder.literals_behind() {
            for &(base, bytes) in &segments {
                self.collect_literals(base, bytes);
            }
        }
        for (base, bytes) in segments {
            if !self.sweep_segment(base, bytes, most) {
                return;
            }
        }
    }

    /// Sweep the code segment at `base`; false when the budget ran out.
    fn sweep_segment(&mut self, base: u64, bytes: &[u8], most: usize) -> bool {
        let step = usize::try_from(self.decoder.alignment()).unwrap_or(1);
        let mode = self.decoder.sweep_mode();
        // Pools found in a pass before this one (sets whose literals sit
        // behind the code that reads them), or else as the sweep meets the
        // code ahead of them.
        let behind = self.decoder.literals_behind();
        self.decoder.reset();
        let mut offset = 0_usize;
        let mut window = usize::MAX;
        // Literal-pool words ahead, which hold data.
        let mut pools: BTreeSet<u64> = BTreeSet::new();
        // Whether only padding and pools have followed a pool or the end of
        // a block: the code after that starts a function when it sets up a
        // frame (one nothing calls, in a static binary). Only on sets with
        // pools, whose frames are distinctive.
        let mut after_end = false;
        while let Some(rest) = bytes.get(offset..).filter(|rest| !rest.is_empty()) {
            if offset / WINDOW != window {
                window = offset / WINDOW;
                let start = window.saturating_mul(WINDOW);
                let end = start.saturating_add(WINDOW);
                if bytes.get(start..end).is_some_and(random) {
                    offset = end;
                    self.decoder.reset();
                    continue;
                }
            }
            let addr = base.wrapping_add(offset as u64) | mode;
            // A literal-pool word: skip it as data, the way code after it
            // would.
            if behind && addr.is_multiple_of(4) && self.pools.contains(&addr) {
                offset = offset.saturating_add(4);
                self.decoder.reset();
                after_end = true;
                continue;
            }
            while pools
                .first()
                .is_some_and(|&pool| pool.saturating_add(4) <= addr)
            {
                pools.pop_first();
            }
            if let Some(&pool) = pools.first().filter(|&&pool| pool <= addr) {
                self.pools.insert(pool);
                offset = offset.saturating_add(step);
                self.decoder.reset();
                after_end = true;
                continue;
            }
            if !behind && let Some(pool) = self.decoder.literal(rest, addr) {
                pools.insert(pool);
            }
            let Some(insn) = self.decode(rest, addr) else {
                return false;
            };
            self.seed_from(rest, addr, &insn, after_end, most);
            after_end = (after_end && insn.pad)
                || (!pools.is_empty() || !self.pools.is_empty())
                    && matches!(
                        insn.flow,
                        Flow::Return | Flow::Jump(_) | Flow::JumpRegister(_) | Flow::Stop
                    )
                    && !insn.falls;
            let len = usize::try_from(insn.len).unwrap_or(usize::MAX).max(step);
            offset = offset.saturating_add(len);
        }
        true
    }

    /// The function starts the sweep finds at `insn`, at `addr`, whose
    /// bytes start `code`: a frame set up where one may start (after the
    /// end of a block, when `after_end`), a direct call, or a direct jump to
    /// code that sets up a frame.
    fn seed_from(&mut self, code: &[u8], addr: u64, insn: &Insn, after_end: bool, most: usize) {
        if let Some(entry) = self.decoder.entry_of(code, addr) {
            self.add_entry(entry, Found::SWEEP, most);
        } else if (after_end || self.decoder.calls_open_frames())
            && addr.is_multiple_of(self.decoder.function_alignment())
            && self.decoder.starts_frame(code)
        {
            self.add_entry(addr, Found::SWEEP, most);
        }
        let frames = |work: &Self, target| {
            work.memory
                .code(target)
                .is_some_and(|code| work.decoder.starts_frame(code))
        };
        // A small negative integer in a literal pool decodes as a call a
        // few bytes back (Arm's `0xfbfffffc`, `blx` six bytes back): no
        // function calls just behind itself. (A call to itself is `bl .`, a
        // weak symbol left unresolved; a call just ahead may be real: musl's
        // `_start` calls the `_start_c` that follows it.) The sweep reads
        // one Arm mode; a call into the other (a `blx` from A32) is more
        // often a data word (`0xfafafafa`) than code, and a walk follows the
        // real ones.
        let here = addr & !1;
        let near = |target: u64| target < here && here.wrapping_sub(target) <= NEAR_BEHIND;
        let mode = self.decoder.sweep_mode();
        match insn.flow {
            Flow::Call(target)
                if (!self.decoder.calls_open_frames() || frames(self, target))
                    && !near(target)
                    && target & 1 == mode =>
            {
                self.add_entry(target, Found::SWEEP, most);
            }
            Flow::Jump(target) if !self.decoder.frames_late() && frames(self, target) => {
                self.add_entry(target, Found::TAIL_CALL, most);
            }
            _ => {}
        }
    }

    /// The import slot the code at `addr` does nothing but jump through.
    fn thunk(&mut self, addr: u64) -> Option<u64> {
        if let Some(&known) = self.thunks.get(&addr) {
            return known;
        }
        // A copy decodes it, so the state of a walk under way stays as it
        // is. A stub's few instructions, decoded once, come out of no budget.
        let mut decoder = self.decoder.clone();
        decoder.reset();
        let mut found = None;
        let mut at = addr;
        for _ in 0..STUB_INSNS {
            let Some(bytes) = self.memory.code(at) else {
                break;
            };
            let insn = self.slot_targets(decoder.decode(bytes, at));
            match insn.flow {
                Flow::JumpSlot(slot) => {
                    found = self.imports.contains_key(&slot).then_some(slot);
                    break;
                }
                Flow::Next if insn.pad || decoder.stub_arithmetic() => {
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
    /// Nothing else marks a call as final: the callers of a stripped wrapper
    /// of `abort` run on into what follows the call.
    fn never_returns(&mut self, target: u64, next: u64) -> bool {
        if self.named_noreturn(target) {
            return true;
        }
        // The delay slot, then two instructions.
        let mut decoder = self.decoder.clone();
        let mut at = next;
        let mut nothing = false;
        for i in 0..2_u8.saturating_add(u8::from(self.decoder.delay_slots())) {
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
                self.return_budget = self.return_budget.saturating_sub(1);
                let Some(bytes) = self.memory.code(addr) else {
                    return true;
                };
                let insn = decoder.decode(bytes, addr);
                let callee_returns = |work: &mut Self, to: u64| {
                    !work.named_noreturn(to) && work.may_return(to, depth.saturating_sub(1))
                };
                let ends = match insn.flow {
                    Flow::Next | Flow::CallIndirect | Flow::CallRegister(_) => false,
                    Flow::Branch(to) => {
                        pending.push(to);
                        false
                    }
                    Flow::Call(to) => !callee_returns(self, to),
                    Flow::CallSlot(slot) => self.noreturn.contains(&slot),
                    // A jump to another function's start: a tail call, which
                    // returns when that function does. Either way, this
                    // path goes no further.
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
        let mut walk = Walk::new(entry);
        // Landing pads sit beneath the entry, so the body claims its own
        // code first; each starts a block nothing branches to.
        let fresh = Tracker::new(self.decoder.address_width());
        for &pad in self.handlers.get(&entry).into_iter().flatten().rev() {
            if !self.entries.contains_key(&pad)
                && self.memory.is_code(pad)
                && walk.leaders.insert(pad)
            {
                walk.pending.push((pad, fresh.clone()));
            }
        }
        walk.pending.push((entry, fresh));
        let extent = self.extents.get(&entry).copied();
        // How far into the extent the search for unreached code has come.
        let mut cursor = entry;
        loop {
            while let Some((start, tracker)) = walk.pending.pop() {
                self.walk_block(&mut walk, start, tracker);
            }
            // After a jump to targets not known, code the unwind table gives
            // this function that no path reached is reached from there: the
            // cases of a table without a bound (a switch on an enum the
            // compiler knows the range of).
            let Some(end) = extent.filter(|_| walk.unresolved > 0) else {
                break;
            };
            let Some(gap) = self.unreached(entry, end, &mut cursor, &walk.insns) else {
                break;
            };
            walk.leaders.insert(gap);
            walk.pending
                .push((gap, Tracker::new(self.decoder.address_width())));
        }
        self.finish(walk)
    }

    /// Walk the block at `start`, with the register values `tracker` holds
    /// on the path that found it, to its end: the block's own terminator,
    /// code walked before, or another function's start.
    fn walk_block(&mut self, walk: &mut Walk, start: u64, mut tracker: Tracker) {
        let mut addr = start;
        self.decoder.reset();
        // Whether the last instruction walked runs into `addr`, other than
        // by returning from a call (which may never return).
        let mut falls = false;
        // An address, and the first function start at or past it (the top
        // of the address space when none is). No start is added while a
        // function is explored, so none lies between them until the walk
        // leaves that span: one search per start passed, not one per
        // instruction.
        let ahead = |work: &Self, addr: u64| {
            let start = work.entries.range(addr..).next();
            (addr, start.map_or(u64::MAX, |(&start, _)| start))
        };
        let (mut from, mut next_start) = ahead(self, addr);
        loop {
            // One search finds whether `addr` was walked and where it goes.
            let Entry::Vacant(slot) = walk.insns.entry(addr) else {
                return;
            };
            if addr < from || next_start < addr {
                (from, next_start) = ahead(self, addr);
            }
            if addr != walk.entry
                && next_start == addr
                && let Some(&found) = self.entries.get(&addr)
            {
                // Code that runs straight into a start known only from
                // unwind data continues there: a compiler that shrink-wraps
                // a function gives its parts their own unwind entries.
                // Anything else there is another function.
                if !(falls && found == Found::UNWIND) || self.explored.contains(&addr) {
                    return;
                }
                self.entries.remove(&addr);
                if walk.referenced.contains(&addr) {
                    walk.leaders.insert(addr);
                }
            }
            let Some(bytes) = self.memory.code(addr) else {
                return;
            };
            let Some(insn) = self.decode(bytes, addr) else {
                return;
            };
            slot.insert(Decoded::from(&insn));
            // Padding after a call that never returns runs into nothing.
            if !insn.pad {
                falls = insn.falls || matches!(insn.flow, Flow::Next | Flow::Branch(_));
            }
            if let Note::Address { addr: to, .. } = insn.note
                && self.decoder.notes_pointers()
                && to.is_multiple_of(self.decoder.alignment())
                && to != walk.entry
                && self.memory.is_code(to)
            {
                walk.pointers.push(to);
            }
            self.track(&insn, &mut tracker);
            let next = addr.wrapping_add(u64::from(insn.len));
            if !self.step(walk, addr, next, &insn, &mut tracker) {
                return;
            }
            // A conditional return or jump ends its block; the code after
            // it, reached when the condition fails, starts one.
            if insn.falls {
                walk.leaders.insert(next);
            }
            addr = next;
        }
    }

    /// Carry what `insn` does to registers into `tracker`. Branches and
    /// calls only read registers; what a call changes, [`Self::step`]
    /// forgets. A compare-and-branch bounds a case value too, and a delay
    /// slot runs before a call or jump arrives.
    fn track(&self, insn: &Insn, tracker: &mut Tracker) {
        let delayed = self.decoder.delay_slots()
            && matches!(
                insn.flow,
                Flow::Call(_) | Flow::CallIndirect | Flow::CallSlot(_) | Flow::Jump(_)
            );
        if !(matches!(insn.flow, Flow::Next | Flow::Branch(_))
            || matches!(insn.note, Note::Value { .. })
            || delayed)
        {
            return;
        }
        let note = match insn.note {
            Note::Fetch {
                reg,
                mem,
                size,
                signed,
            } => self
                .fetched(tracker, mem, size, signed)
                .map_or(Note::Write(reg), |addr| Note::Address { reg, addr }),
            note => note,
        };
        tracker.note(note);
    }

    /// The address a load of `size` bytes from `mem` reads, when `mem` is
    /// a slot of this binary that holds one (written there, or by the
    /// loader).
    fn fetched(&self, tracker: &Tracker, mem: Mem, size: u8, signed: bool) -> Option<u64> {
        let slot = tracker
            .fixed(mem)
            .filter(|slot| !self.imports.contains_key(slot))?;
        let value = match self.memory.read(slot, size) {
            Some(0) | None => self.rebased.get(&slot).copied(),
            value => value,
        }?;
        Some(if signed {
            table::sign_extend(value, size)
        } else {
            value
        })
    }

    /// Follow `insn`, at `addr`, out of its block: record what it calls,
    /// branches and jumps to, and queue its targets in this function.
    /// Whether the walk goes on to `next`.
    fn step(
        &mut self,
        walk: &mut Walk,
        addr: u64,
        next: u64,
        insn: &Insn,
        tracker: &mut Tracker,
    ) -> bool {
        // A register holding a fixed address of code: a call there.
        let flow = match insn.flow {
            Flow::CallRegister(reg) => tracker
                .held(reg)
                .filter(|&to| self.memory.is_code(to))
                .map_or(Flow::CallIndirect, Flow::Call),
            flow => flow,
        };
        // A jump through a register holding a fixed address of code: a tail
        // call, as code of this function would be reached by a direct
        // branch (musl's PowerPC start code computes the next stage's
        // address from the PC; s390x `larl %r1, f; br %r1`).
        if let Flow::JumpRegister(reg) = flow
            && let Some(to) = tracker
                .held(reg)
                .filter(|&to| to != walk.entry && self.memory.is_code(to))
        {
            walk.refer(addr, Dest::Code(to), RefKind::Jump);
            walk.tails.push(to);
            return insn.falls;
        }
        match flow {
            Flow::Next => {}
            Flow::CallIndirect | Flow::CallRegister(_) => {
                tracker.call(self.decoder.call_preserved());
            }
            Flow::Call(to) => {
                walk.mains.extend(self.main(walk.entry, to, next, tracker));
                tracker.call(self.decoder.call_preserved());
                // A PC thunk returns the address after the call.
                let thunk = self
                    .memory
                    .code(to)
                    .and_then(|code| self.decoder.pc_thunk(code, addr, next));
                if let Some(note) = thunk {
                    tracker.note(note);
                }
                walk.refer(addr, Dest::Code(to), RefKind::Call);
                walk.calls.push(to);
                if self.never_returns(to, next) {
                    walk.ends.insert(addr);
                    return false;
                }
            }
            Flow::CallSlot(slot) => {
                walk.mains
                    .extend(self.main(walk.entry, slot, next, tracker));
                tracker.call(self.decoder.call_preserved());
                walk.refer(addr, self.slot(slot), RefKind::Call);
                if self.noreturn.contains(&slot) {
                    walk.ends.insert(addr);
                    return false;
                }
            }
            Flow::Branch(to) => {
                walk.refer(addr, Dest::Code(to), RefKind::Branch);
                self.reach(walk, to, tracker);
                // The fall-through starts a block; this walk decodes it.
                walk.leaders.insert(next);
            }
            Flow::Jump(to) => {
                walk.refer(addr, Dest::Code(to), RefKind::Jump);
                self.reach(walk, to, tracker);
                return false;
            }
            Flow::JumpSlot(slot) => {
                walk.refer(addr, self.slot(slot), RefKind::Jump);
                return insn.falls;
            }
            Flow::JumpMemory(_)
            | Flow::JumpRegister(_)
            | Flow::JumpAdd { .. }
            | Flow::JumpTable { .. } => {
                let mut targets = self.table_targets(addr, flow, tracker);
                // Each case is a reference and a block to queue: charged as
                // an instruction, so a table read by one jump costs what
                // its cases would.
                if targets.len() > self.budget {
                    targets.truncate(self.budget);
                    self.truncated = true;
                }
                self.budget = self.budget.saturating_sub(targets.len());
                walk.cases
                    .insert(addr, u32::try_from(targets.len()).unwrap_or(u32::MAX));
                if targets.is_empty() {
                    walk.unresolved = walk.unresolved.saturating_add(1);
                }
                for to in targets {
                    walk.refer(addr, Dest::Code(to), RefKind::Case);
                    self.reach(walk, to, tracker);
                }
                return insn.falls;
            }
            Flow::JumpIndirect => {
                walk.unresolved = walk.unresolved.saturating_add(1);
                return insn.falls;
            }
            Flow::Invalid => {
                walk.invalid = walk.invalid.saturating_add(1);
                return false;
            }
            Flow::Return | Flow::Stop => return insn.falls,
        }
        true
    }

    /// Where a transfer through the memory slot at `addr` goes.
    fn slot(&self, addr: u64) -> Dest {
        Dest::Slot {
            addr,
            import: self.imports.get(&addr).copied().flatten(),
        }
    }

    /// Queue `to`, reached with the register values in `tracker`, as a
    /// block of the function `walk` explores; a jump to another function's
    /// start is a tail call, and queues nothing.
    fn reach(&self, walk: &mut Walk, to: u64, tracker: &Tracker) {
        let local = to == walk.entry || !self.entries.contains_key(&to);
        if local && self.memory.is_code(to) && walk.leaders.insert(to) {
            walk.pending.push((to, tracker.clone()));
        }
    }

    /// The case targets of the indirect jump at `addr`, as far as `tracker`
    /// knows its table. An unbounded table ends before a target past
    /// another function's start: the next table, of the next function
    /// (glibc's printf variants).
    fn table_targets(&self, addr: u64, flow: Flow, tracker: &Tracker) -> Vec<u64> {
        let Some(table) = tracker.jump(flow) else {
            return Vec::new();
        };
        let mut targets = table.targets(&self.memory, self.table_entries);
        if !table.bounded() {
            let crosses = |to: u64| {
                let (low, high) = (addr.min(to), addr.max(to));
                low < high
                    && self
                        .entries
                        .range(low.wrapping_add(1)..=high)
                        .next()
                        .is_some()
            };
            if let Some(end) = targets.iter().position(|&to| crosses(to)) {
                targets.truncate(end);
            }
        }
        targets
    }

    /// The function `walk` explored, from its instructions.
    fn finish(&mut self, mut walk: Walk) -> Explored {
        let entry = walk.entry;
        let (blocks, edges, exits) = self.graph(&walk);
        // McCabe's: edges - blocks + 2 per exit, as a count.
        let complexity = u64::from(edges)
            .saturating_add(2 * u64::from(exits))
            .saturating_sub(u64::from(blocks));
        let low = walk.insns.keys().next().copied().unwrap_or(entry);
        let high = walk
            .insns
            .iter()
            .map(|(&addr, insn)| addr.saturating_add(u64::from(insn.len)))
            .max()
            .unwrap_or(entry);
        walk.refs.sort_by_key(|r| (r.from, r.addr()));
        // The references outlive the walk, in the recovery returned: not the
        // room their vector grew to.
        walk.refs.shrink_to_fit();
        let thunk = self.thunk(entry);
        Explored {
            function: Function {
                entry,
                // Filled in once every function is known.
                name: None,
                size: high.saturating_sub(low),
                blocks,
                complexity: u32::try_from(complexity).unwrap_or(u32::MAX),
                refs: walk.refs,
            },
            detail: Detail {
                edges,
                thunk,
                // Filled in once every caller is known.
                found: Found::default(),
            },
            calls: walk.calls,
            mains: walk.mains,
            pointers: walk.pointers,
            tails: walk.tails,
            runs: runs(&walk.insns),
            invalid: walk.invalid,
            unresolved: walk.unresolved,
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
        insns: &BTreeMap<u64, Decoded>,
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
    fn graph(&self, walk: &Walk) -> (u32, u32, u32) {
        let Walk {
            entry,
            insns,
            leaders,
            ends,
            cases,
            ..
        } = walk;
        let entry = *entry;
        // The instructions in address order, each with whether a block
        // starts there: a block's next instruction is then nearly always
        // the next element, found without a search.
        let mut starts = leaders.iter().copied().peekable();
        let insns: Vec<(u64, Decoded, bool)> = insns
            .iter()
            .map(|(&addr, &insn)| {
                while starts.next_if(|&leader| leader < addr).is_some() {}
                (addr, insn, starts.next_if_eq(&addr).is_some())
            })
            .collect();
        let find = |addr: u64, hint: usize| match insns.get(hint) {
            Some(&(at, ..)) if at == addr => Some(hint),
            _ => insns.binary_search_by_key(&addr, |&(at, ..)| at).ok(),
        };
        let (mut blocks, mut edges, mut exits) = (0_u32, 0_u32, 0_u32);
        let firsts = insns
            .iter()
            .enumerate()
            .filter_map(|(i, &(.., leader))| leader.then_some(i));
        for first in firsts {
            blocks = blocks.saturating_add(1);
            let mut at = first;
            while let Some(&(addr, insn, _)) = insns.get(at) {
                // A conditional return or jump also runs into the next block.
                let falls = u32::from(insn.falls);
                let (out, exit) = match insn.exit {
                    Exit::Jump => (1, false),
                    Exit::Branch => (2, false),
                    Exit::Indirect => (
                        cases.get(&addr).copied().unwrap_or(0).saturating_add(falls),
                        true,
                    ),
                    Exit::Leaves => (falls, true),
                    Exit::Invalid => (0, true),
                    // A call that never returns.
                    Exit::Next if ends.contains(&addr) => (0, true),
                    // On to the next instruction: the block ends where
                    // another starts, or the code does.
                    Exit::Next => {
                        let next = addr.wrapping_add(u64::from(insn.len));
                        match find(next, at.saturating_add(1)) {
                            Some(found) if insns.get(found).is_some_and(|&(.., leader)| leader) => {
                                (1, false)
                            }
                            Some(found) => {
                                at = found;
                                continue;
                            }
                            // Falls into the next function.
                            None if next != entry && self.entries.contains_key(&next) => (1, false),
                            None => (0, true),
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
fn runs(insns: &BTreeMap<u64, Decoded>) -> Vec<(u64, u64)> {
    let mut runs: Vec<(u64, u64)> = Vec::new();
    for (&addr, insn) in insns.iter().filter(|(_, insn)| insn.exit != Exit::Invalid) {
        let end = addr.saturating_add(u64::from(insn.len));
        match runs.last_mut() {
            Some(last) if last.1 >= addr => last.1 = last.1.max(end),
            _ => runs.push((addr, end)),
        }
    }
    // Kept with the recovery, for the walk over calls.
    runs.shrink_to_fit();
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
            *count = count.saturating_add(1);
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
