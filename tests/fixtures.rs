//! Recovery on real binaries. Each fixture in `testdata/` is a compressed
//! binary (`NAME.zst`), where it came from (`NAME.md`), what rizin found in
//! it (`NAME.rizin.json.zst`, written by `funktion-ab --save`), and what
//! funktion finds (`NAME.golden`): one line per function, with rizin's
//! blocks and complexity beside funktion's, and every function only rizin
//! found, with the reason. An improvement and a regression both show as a
//! diff of the golden; `FUNKTION_BLESS=1 cargo test --test fixtures`
//! rewrites the goldens to accept one.
//!
//! Each fixture also makes claims: the gap it was added for, stated as an
//! assertion, so blessing cannot quietly reopen it.

// A test fails by panicking.
#![allow(clippy::panic, clippy::indexing_slicing)]

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::path::PathBuf;

use funktion::{Found, Image, Recovery, RefKind};

/// What rizin found at one entry.
struct Theirs {
    name: String,
    blocks: u64,
    complexity: u64,
}

struct Outcome<'a> {
    image: Image<'a>,
    recovery: Recovery,
    rizin: BTreeMap<u64, Theirs>,
}

impl Outcome<'_> {
    fn found(&self, way: Found) -> usize {
        self.recovery
            .functions
            .iter()
            .filter(|f| f.found.contains(way))
            .count()
    }

    fn cases(&self) -> usize {
        self.recovery
            .functions
            .iter()
            .flat_map(|f| &f.refs)
            .filter(|r| r.kind == RefKind::Case)
            .count()
    }

    fn entries(&self) -> HashMap<u64, &funktion::Function> {
        self.recovery
            .functions
            .iter()
            .map(|f| (f.entry, f))
            .collect()
    }

    /// The function whose first-to-last byte span holds `addr`, other than
    /// one starting there.
    fn inside(&self, addr: u64) -> Option<u64> {
        self.recovery
            .functions
            .iter()
            .filter(|f| f.entry < addr && addr < f.entry.saturating_add(f.size))
            .map(|f| f.entry)
            .max()
    }

    /// Rizin's entries in executable code that funktion did not find, and
    /// that lie in no function funktion recovered.
    fn missed(&self) -> Vec<u64> {
        let ours = self.entries();
        self.rizin
            .keys()
            .copied()
            .filter(|&entry| {
                is_code(&self.image, entry)
                    && !ours.contains_key(&entry)
                    && self.inside(entry).is_none()
            })
            .collect()
    }

    /// Shared functions with the same number of blocks, among those rizin
    /// walks the way funktion does: without landing pads (rizin skips
    /// them), and without a rizin "function" inside (rizin split them).
    fn same_blocks_without_pads(&self) -> (usize, usize) {
        let mut skip: std::collections::HashSet<u64> =
            self.image.handlers.iter().map(|h| h.function).collect();
        let ours = self.entries();
        skip.extend(
            self.rizin
                .keys()
                .filter(|entry| !ours.contains_key(entry))
                .filter_map(|&entry| self.inside(entry)),
        );
        let (mut same, mut shared) = (0, 0);
        for function in &self.recovery.functions {
            if let Some(theirs) = self.rizin.get(&function.entry)
                && !skip.contains(&function.entry)
            {
                shared += 1;
                same += usize::from(theirs.blocks == u64::from(function.blocks));
            }
        }
        (same, shared)
    }
}

fn is_code(image: &Image<'_>, addr: u64) -> bool {
    image.segments.iter().any(|segment| {
        segment.executable
            && addr
                .checked_sub(segment.addr)
                .is_some_and(|offset| offset < segment.bytes.len() as u64)
    })
}

fn testdata(file: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("testdata")
        .join(file)
}

fn read_zst(file: &str) -> Vec<u8> {
    let path = testdata(file);
    let compressed = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    zstd::decode_all(&compressed[..]).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn rizin(name: &str) -> BTreeMap<u64, Theirs> {
    let text = read_zst(&format!("{name}.rizin.json.zst"));
    let value: serde_json::Value = serde_json::from_slice(&text).unwrap_or_default();
    value["functions"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|row| {
            let field = |i: usize| row.get(i).and_then(serde_json::Value::as_u64);
            Some((
                field(0)?,
                Theirs {
                    name: row.get(1)?.as_str()?.to_owned(),
                    blocks: field(3)?,
                    complexity: field(4)?,
                },
            ))
        })
        .collect()
}

/// The golden text: a summary, then why rizin found what funktion did not,
/// then every function.
fn golden(outcome: &Outcome<'_>) -> String {
    let functions = &outcome.recovery.functions;
    let ours = outcome.entries();
    let mut extents: Vec<(u64, u64)> = functions
        .iter()
        .map(|f| (f.entry, f.entry.saturating_add(f.size)))
        .collect();
    extents.sort_unstable();
    let inside = |entry: u64| {
        let i = extents.partition_point(|&(start, _)| start <= entry);
        i.checked_sub(1)
            .and_then(|i| extents.get(i))
            .filter(|&&(_, end)| entry < end)
            .map(|&(start, _)| start)
    };

    let mut text = String::new();
    let shared = functions
        .iter()
        .filter(|f| outcome.rizin.contains_key(&f.entry))
        .count();
    let same_blocks = functions
        .iter()
        .filter(|f| {
            outcome
                .rizin
                .get(&f.entry)
                .is_some_and(|t| t.blocks == u64::from(f.blocks))
        })
        .count();
    let (same_unpadded, unpadded) = outcome.same_blocks_without_pads();
    let _ = writeln!(
        text,
        "# funktion: {} functions, {} bytes of code covered, {} landing pads, {} cases",
        functions.len(),
        outcome.recovery.covered,
        outcome.image.handlers.len(),
        outcome.cases(),
    );
    let _ = writeln!(
        text,
        "# rizin: {} functions; {shared} shared, {same_blocks} with the same blocks ({same_unpadded} of {unpadded} without landing pads)",
        outcome.rizin.len(),
    );
    for (&entry, theirs) in &outcome.rizin {
        if ours.contains_key(&entry) {
            continue;
        }
        let why = if !is_code(&outcome.image, entry) {
            "not code".to_owned()
        } else if let Some(start) = inside(entry) {
            format!("inside {start:#x}")
        } else {
            "missed".to_owned()
        };
        let _ = writeln!(text, "only rizin {entry:#x} {}: {why}", theirs.name);
    }
    for function in functions {
        let cases = function
            .refs
            .iter()
            .filter(|r| r.kind == RefKind::Case)
            .count();
        let theirs = outcome.rizin.get(&function.entry).map_or_else(
            || "-".to_owned(),
            |t| format!("{}/{}", t.blocks, t.complexity),
        );
        let _ = writeln!(
            text,
            "{:#x} size={} blocks={} edges={} cc={} cases={cases} found={:?} rizin={theirs}",
            function.entry,
            function.size,
            function.blocks,
            function.edges,
            function.complexity,
            function.found,
        );
    }
    text
}

fn check(name: &str, claims: impl Fn(&Outcome<'_>)) {
    let bytes = read_zst(&format!("{name}.zst"));
    let image = funktion::object::image(&bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
    let mut recovery = funktion::recover(&image);
    // Thumb entries carry their mode in bit 0; rizin's are even.
    if image.arch == funktion::Arch::Arm {
        for function in &mut recovery.functions {
            function.entry &= !1;
        }
    }
    let outcome = Outcome {
        image,
        recovery,
        rizin: rizin(name),
    };
    assert!(!outcome.recovery.truncated, "{name}: recovery hit a limit");
    let actual = golden(&outcome);
    let path = testdata(&format!("{name}.golden"));
    if std::env::var_os("FUNKTION_BLESS").is_some() {
        std::fs::write(&path, &actual).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    } else {
        let expected = std::fs::read_to_string(&path).unwrap_or_default();
        if expected != actual {
            let old: std::collections::HashSet<&str> = expected.lines().collect();
            let new: std::collections::HashSet<&str> = actual.lines().collect();
            let mut diff = String::new();
            for line in expected.lines().filter(|l| !new.contains(l)).take(20) {
                let _ = writeln!(diff, "- {line}");
            }
            for line in actual.lines().filter(|l| !old.contains(l)).take(20) {
                let _ = writeln!(diff, "+ {line}");
            }
            panic!(
                "{name}: recovery differs from {} (FUNKTION_BLESS=1 accepts it):\n{diff}",
                path.display()
            );
        }
    }
    claims(&outcome);
}

/// Every function rizin found in code, funktion finds, or holds inside one
/// of its own, except the listed entries, each with its reason.
fn finds_rizin_except(outcome: &Outcome<'_>, except: &[(u64, &str)]) {
    let missed: Vec<u64> = outcome
        .missed()
        .into_iter()
        .filter(|entry| !except.iter().any(|(known, _)| known == entry))
        .collect();
    assert!(
        missed.is_empty(),
        "missed {} of rizin's: {missed:x?}",
        missed.len()
    );
}

fn finds_all_of_rizin(outcome: &Outcome<'_>) {
    finds_rizin_except(outcome, &[]);
}

/// A relocatable object: sections placed as rizin places them, symbols at
/// offset zero kept, calls linked through their relocations.
#[test]
fn aarch64_object() {
    check("go-relocation-test-gcc482-aarch64.obj", finds_all_of_rizin);
}

#[test]
fn x86_64_object() {
    check("cycle.elf", finds_all_of_rizin);
}

/// A large A64 object: every function a symbol, every call a relocation.
#[test]
fn aarch64_race_object() {
    check("race_linux_arm64.syso", |outcome| {
        finds_all_of_rizin(outcome);
        let calls = outcome
            .recovery
            .functions
            .iter()
            .flat_map(|f| &f.refs)
            .filter(|r| r.kind == RefKind::Call)
            .count();
        assert!(calls > 1000, "only {calls} calls: relocations not applied?");
    });
}

/// A static executable: landing pads from `.gcc_except_table` belong to
/// their functions, and `main` is found from what `_start` passes.
#[test]
fn elf_x86_64_static() {
    check("apply-seccomp", |outcome| {
        assert!(!outcome.image.handlers.is_empty(), "no landing pads");
        assert_eq!(outcome.found(Found::MAIN), 1, "no main");
        finds_all_of_rizin(outcome);
    });
}

/// C++ (built without exceptions): the PLT stubs are functions, called or
/// not, and jump tables are read.
#[test]
fn elf_x86_64_cxx() {
    check("classic-level-linux-x64.node", |outcome| {
        assert!(outcome.found(Found::STUB) > 0, "no PLT stubs");
        assert!(outcome.cases() > 0, "no jump tables");
        finds_rizin_except(
            outcome,
            &[(
                0x1_6f26,
                "the `push; jmp` half of a lazy PLT entry, where its GOT slot first points",
            )],
        );
    });
}

/// A64 C++: the PLT, with its 32-byte header.
#[test]
fn elf_arm64_cxx() {
    check("classic-level-linux-arm64.node", |outcome| {
        assert!(outcome.found(Found::STUB) > 0, "no PLT stubs");
    });
}

/// A universal Mach-O: the x86-64 slice (rizin's choice too), and its
/// `__stubs`.
#[test]
fn macho_universal_cxx() {
    check("classic-level-darwin.node", |outcome| {
        assert_eq!(outcome.image.arch, funktion::Arch::X86_64);
        assert!(outcome.found(Found::STUB) > 0, "no __stubs");
    });
}

/// 32-bit position-independent code: jump tables at GOT-relative offsets.
#[test]
fn i386_pic() {
    check("libe_sqlite3-android-x86.so", |outcome| {
        assert!(outcome.cases() > 1000, "only {} cases", outcome.cases());
        let (same, shared) = outcome.same_blocks_without_pads();
        assert!(
            same * 100 >= shared * 90,
            "blocks agree on {same} of {shared}"
        );
    });
}

/// A Mach-O object: calls linked through their branch relocations, so an
/// unlinked `bl 0` is no call to itself.
#[test]
fn macho_arm64_object() {
    check("race_darwin_arm64.syso", |outcome| {
        let ours = outcome.recovery.functions.len();
        let theirs = outcome.rizin.len();
        assert!(
            ours <= theirs + theirs / 50,
            "{ours} functions to rizin's {theirs}"
        );
        assert!(
            !outcome.image.imports.is_empty(),
            "undefined symbols got no slots"
        );
    });
}

/// MSVC A64: unwind entries for fragments (`end_c`) start no function, and
/// shrink-wrapped parts join the function that runs into them.
#[test]
fn pe_arm64_msvc() {
    check("e_sqlite3-win-arm64.dll", |outcome| {
        let ours = outcome.recovery.functions.len();
        let theirs = outcome.rizin.len();
        assert!(
            ours <= theirs + theirs / 20,
            "{ours} functions to rizin's {theirs}"
        );
        let (same, shared) = outcome.same_blocks_without_pads();
        assert!(
            same * 100 >= shared * 90,
            "blocks agree on {same} of {shared}"
        );
        assert!(outcome.cases() > 500, "only {} A64 cases", outcome.cases());
    });
}

/// What Go's `runtime.debugCallV2` runs after a `brk` that a debugger
/// resumes from: no instruction reaches it.
const DEBUG_CALL: &str = "runtime.debugCallV2's code after a `brk` a debugger resumes from";

/// Go on Windows A64: no `.pdata`, and a function table with no section of
/// its own whose header leaves the text start to the loader.
#[test]
fn pe_arm64_go() {
    check("does-nothing-windows-arm64.exe", |outcome| {
        let named = outcome.found(Found::SYMBOL);
        assert!(named > 2000, "only {named} functions from the Go table");
        finds_rizin_except(outcome, &[(0x1_4007_b2a8, DEBUG_CALL)]);
    });
}

/// Go on macOS A64 with the function table's magic number overwritten, as
/// garble does.
#[test]
fn macho_arm64_go_garbled() {
    check("does-nothing-darwin-arm64-garbled", |outcome| {
        let named = outcome.found(Found::SYMBOL);
        assert!(named > 2000, "only {named} functions from the Go table");
        finds_rizin_except(outcome, &[(0x1_0007_ac08, DEBUG_CALL)]);
    });
}

/// Bytes of code that some recovered function's instructions cover, as a
/// share of all code, in percent.
fn coverage(outcome: &Outcome<'_>) -> u64 {
    outcome.recovery.covered * 100 / outcome.recovery.code.max(1)
}

/// Go on 32-bit Arm (A32): `add pc, lr, #0` returns, and the zero words Go
/// leaves after calls that never return decode as padding.
#[test]
fn elf_arm_go() {
    check("does-nothing-linux-arm", |outcome| {
        assert_eq!(outcome.image.arch, funktion::Arch::Arm);
        let named = outcome.found(Found::SYMBOL);
        assert!(named > 2000, "only {named} functions from the Go table");
        finds_all_of_rizin(outcome);
        let (same, shared) = outcome.same_blocks_without_pads();
        assert!(
            same * 100 >= shared * 95,
            "blocks agree on {same} of {shared}"
        );
        assert!(coverage(outcome) >= 95, "covers {}%", coverage(outcome));
        assert_eq!(outcome.recovery.invalid, 0, "zero words stop paths");
    });
}

/// Go on big-endian MIPS: the function table read in the file's byte
/// order, delay slots joined to their branches.
#[test]
fn elf_mips_go() {
    check("does-nothing-linux-mips", |outcome| {
        assert_eq!(outcome.image.arch, funktion::Arch::Mips);
        let named = outcome.found(Found::SYMBOL);
        assert!(named > 2000, "only {named} functions from the Go table");
        assert!(coverage(outcome) >= 99, "covers {}%", coverage(outcome));
        // Rizin starts a function in the epilogue after each `jal
        // runtime.deferreturn`, which the Go runtime resumes at and no
        // instruction reaches, and in the dead epilogue after each `jal
        // runtime.exit`. Every other function rizin finds, funktion finds or
        // holds.
        let missed = outcome.missed();
        assert!(
            missed.len() <= 36,
            "missed {} of rizin's: {missed:x?}",
            missed.len()
        );
    });
}

/// Go on IBM Z. Rizin finds next to nothing here; the function table and
/// the code covered stand in.
#[test]
fn elf_s390x_go() {
    check("does-nothing-linux-s390x", |outcome| {
        assert_eq!(outcome.image.arch, funktion::Arch::S390x);
        let named = outcome.found(Found::SYMBOL);
        assert!(named > 2000, "only {named} functions from the Go table");
        assert!(coverage(outcome) >= 97, "covers {}%", coverage(outcome));
        // Calls to `runtime.throw`, `runtime.panicIndex` and the like never
        // return: the padding after them is no code.
        assert!(
            outcome.recovery.invalid <= 11,
            "{} invalid",
            outcome.recovery.invalid
        );
    });
}

/// GCC Thumb-2: entries in Thumb mode, an A32 PLT whose stubs resolve to
/// their slots.
#[test]
fn elf_thumb_c() {
    check("libe_sqlite3-linux-arm.so", |outcome| {
        assert_eq!(outcome.image.arch, funktion::Arch::Arm);
        // Each stub jumps through its GOT slot; a slot an import fills makes
        // the stub that import's thunk. (Most stubs here call the library's
        // own exported functions, whose slots name no import.)
        let imports: std::collections::HashSet<u64> =
            outcome.image.imports.iter().map(|i| i.slot).collect();
        let stubs: Vec<&funktion::Function> = outcome
            .recovery
            .functions
            .iter()
            .filter(|f| f.found.contains(Found::STUB) && !f.refs.is_empty())
            .collect();
        assert!(stubs.len() > 200, "only {} PLT stubs", stubs.len());
        for stub in &stubs {
            let slot = stub.refs[0].to;
            assert_eq!(stub.refs[0].kind, RefKind::Jump, "{:#x}", stub.entry);
            if imports.contains(&slot) {
                assert_eq!(stub.thunk, Some(slot), "stub {:#x}", stub.entry);
            }
        }
        assert!(stubs.iter().filter(|s| s.thunk.is_some()).count() > 20);
        let (same, shared) = outcome.same_blocks_without_pads();
        assert!(shared > 2600, "only {shared} functions shared with rizin");
        assert!(
            same * 100 >= shared * 97,
            "blocks agree on {same} of {shared}"
        );
        // `tbb`/`tbh` tables, bounded by the `cmp` before them.
        let cases: usize = outcome
            .recovery
            .functions
            .iter()
            .map(|f| f.refs.iter().filter(|r| r.kind == RefKind::Case).count())
            .sum();
        assert!(cases > 1800, "only {cases} cases");
        // Rizin's others are mostly literal pools it decodes as code.
        let missed = outcome.missed();
        assert!(missed.len() <= 25, "missed {}: {missed:x?}", missed.len());
    });
}

/// `calls.c` (see `calls-arm.o.md`) built for another instruction set: its
/// four functions and no others, each of the eight calls linked to one of
/// them or to the import slot of `puts`, `abort` or `helper`.
fn links_calls(outcome: &Outcome<'_>) {
    let functions = &outcome.recovery.functions;
    let entries: Vec<u64> = functions.iter().map(|f| f.entry).collect();
    assert_eq!(entries.len(), 4, "functions at {entries:x?}");
    assert!(functions.iter().all(|f| f.found.contains(Found::SYMBOL)));
    let slots: HashMap<u64, &str> = outcome
        .image
        .imports
        .iter()
        .map(|i| (i.slot, i.name.as_str()))
        .collect();
    let mut imported = Vec::new();
    let mut calls = 0;
    for function in functions {
        for call in function.refs.iter().filter(|r| r.kind == RefKind::Call) {
            calls += 1;
            // Thumb targets carry bit 0; the entries here do not.
            let to = call.to & !1;
            assert_ne!(to, function.entry, "unlinked call at {:#x}", call.from);
            match slots.get(&call.to) {
                Some(name) => imported.push(*name),
                None => assert!(entries.contains(&to), "call {:#x} -> {to:#x}", call.from),
            }
        }
    }
    assert_eq!(calls, 8);
    imported.sort_unstable();
    assert_eq!(imported, ["abort", "helper", "puts"]);
}

#[test]
fn arm_objects() {
    check("calls-arm.o", links_calls);
    check("calls-thumb.o", links_calls);
}

#[test]
fn mips_objects() {
    check("calls-mips.o", links_calls);
    check("calls-mips-static.o", links_calls);
    check("calls-mips64.o", links_calls);
}

/// MIPS shared libraries: calls through GOT slots, named by the GOT's
/// layout; a slot of a function in the library holds its address.
#[test]
fn mips_got_calls() {
    check("calls-mips.so", links_calls);
    check("calls-mips64el.so", links_calls);
}

#[test]
fn s390x_object() {
    check("calls-s390x.o", links_calls);
}

#[test]
fn sparc_objects() {
    check("calls-sparc.o", links_calls);
    check("calls-sparc64.o", links_calls);
}

/// Jump-table cases across all functions.
fn cases(outcome: &Outcome<'_>) -> usize {
    outcome
        .recovery
        .functions
        .iter()
        .flat_map(|f| &f.refs)
        .filter(|r| r.kind == RefKind::Case)
        .count()
}

/// The functions funktion and rizin share, and on how many of them, as a
/// percentage, they agree on blocks (landing pads aside).
fn agreement(outcome: &Outcome<'_>) -> (usize, usize) {
    let (same, shared) = outcome.same_blocks_without_pads();
    (shared, same * 100 / shared.max(1))
}

/// FreeBSD's Clang build. Where blocks differ, rizin mostly runs on past a
/// call that never returns (`__stack_chk_fail`).
#[test]
fn freebsd() {
    check("libsqlite3-freebsd-amd64.so", |outcome| {
        finds_all_of_rizin(outcome);
        let (shared, same) = agreement(outcome);
        assert!(shared > 2150 && same >= 85, "{same}% of {shared}");
    });
}

/// OpenBSD on A64 starts each function with `bti c`; rizin splits it off
/// into a function of its own, with the rest a function 4 bytes on. On
/// x86-64 OpenBSD's PLT keeps its lazy-binding entries in `.plt` and the
/// stubs calls go to in `.plt.sec`.
#[test]
fn openbsd() {
    check("libsqlite3-openbsd-arm64.so", |outcome| {
        finds_all_of_rizin(outcome);
        let entries: std::collections::HashSet<u64> =
            outcome.recovery.functions.iter().map(|f| f.entry).collect();
        let split = outcome
            .rizin
            .keys()
            .filter(|&&theirs| !entries.contains(&theirs) && entries.contains(&(theirs - 4)))
            .count();
        assert!(split > 2000, "only {split} of rizin's split after `bti c`");
    });
    check("sqlite3-openbsd-amd64", |outcome| {
        finds_all_of_rizin(outcome);
        let (shared, same) = agreement(outcome);
        assert!(shared >= 868 && same >= 99, "{same}% of {shared}");
    });
}

#[test]
fn netbsd() {
    check("libsqlite3-netbsd-arm64.so", |outcome| {
        finds_all_of_rizin(outcome);
        let (shared, same) = agreement(outcome);
        assert!(shared > 2550 && same >= 99, "{same}% of {shared}");
    });
}

#[test]
fn illumos() {
    check("sqlite3-illumos-amd64", |outcome| {
        let missed = outcome.missed();
        assert!(missed.len() <= 1, "missed {missed:x?}");
        let (shared, same) = agreement(outcome);
        assert!(shared > 650 && same >= 98, "{same}% of {shared}");
    });
}

/// Sun Studio's 32-bit SPARC: constant pools in `.text` (rizin's `entry0`
/// is one), text relocations, leaf tail calls through `%g1`, and a PLT
/// whose reserved header is zeros in the file.
#[test]
fn solaris_sparc() {
    check("libsqlite3-solaris-sparc.so", |outcome| {
        let missed = outcome.missed();
        assert!(missed.len() <= 2, "missed {missed:x?}");
        assert!(
            outcome.recovery.invalid <= 10,
            "{}",
            outcome.recovery.invalid
        );
        let (shared, same) = agreement(outcome);
        assert!(shared > 3350 && same >= 70, "{same}% of {shared}");
        // Sun Studio's tables: `rd %pc` plus a constant is the table, which
        // holds offsets from itself (`ld [%i5+%l6], %l7; jmp %l7+%l6`).
        assert!(cases(outcome) > 1400, "only {} cases", cases(outcome));
        // Constant pools (`___const_seg_*` objects in `.text`) are data:
        // `___const_seg_900004301` at 0xaa70 held a call target before.
        let entries: Vec<u64> = outcome.recovery.functions.iter().map(|f| f.entry).collect();
        assert!(!entries.contains(&0xaad4) && !entries.contains(&0xa5708));
    });
}

/// GCC's SPARC V9: the PLT's entries branch to a header the dynamic linker
/// writes, zeros in the file, and tail calls go through `call f; restore`.
#[test]
fn linux_sparc64() {
    check("libsqlite3-linux-sparc64.so", |outcome| {
        let missed = outcome.missed();
        assert!(missed.len() <= 5, "missed {missed:x?}");
        assert!(
            outcome.recovery.invalid <= 1,
            "{}",
            outcome.recovery.invalid
        );
        let (shared, same) = agreement(outcome);
        assert!(shared > 3400 && same >= 95, "{same}% of {shared}");
        // GCC's tables: the GOT pointer (`sethi; call` the PC thunk; `add`)
        // less a constant is the table, of offsets from itself.
        assert!(cases(outcome) > 1200, "only {} cases", cases(outcome));
    });
}

/// GCC's MIPS64 and s390x. Blocks differ by rizin's reading: it ends a
/// MIPS block before a branch's delay slot, and runs on through s390x's
/// conditional returns (`bler %r14`) as if they did not leave.
#[test]
fn c_mips64_and_s390x() {
    check("libe_sqlite3-linux-mips64.so", |outcome| {
        finds_all_of_rizin(outcome);
        assert!(agreement(outcome).0 > 2450);
        // GCC's PIC tables: `sltiu` bounds the case, a GOT page entry plus
        // `daddiu` is the table, `dsll; daddu; ld` reads an offset from
        // `_gp`, which `$gp` or a register holding it adds back.
        assert!(cases(outcome) > 2600, "only {} cases", cases(outcome));
        // Calls to local functions go through a GOT page entry plus the low
        // bits (`ld $t9, %got_page(f)($gp); daddiu $t9, $t9, %got_ofst(f);
        // jalr $t9`): resolved, they find most functions as call targets.
        assert!(
            outcome.found(Found::CALL) > 1600,
            "{}",
            outcome.found(Found::CALL)
        );
    });
    check("libe_sqlite3-linux-s390x.so", |outcome| {
        finds_all_of_rizin(outcome);
        assert_eq!(agreement(outcome).0, outcome.rizin.len());
        // GCC's tables: `clijh` bounds the case, `lg` reads an 8-byte
        // offset from the table, `b 0(%rE,%rT)` adds the two.
        assert!(cases(outcome) > 2400, "only {} cases", cases(outcome));
    });
}

/// A stripped, static uClibc MIPS-I executable (an IoT bot): `$gp` from
/// the `.got` section, and the bot's routines found from the function
/// pointers the GOT holds.
#[test]
fn mips_uclibc_static() {
    check("bot-mips-uclibc-static", |outcome| {
        assert_eq!(outcome.image.arch, funktion::Arch::Mips);
        assert!(coverage(outcome) >= 95, "covers {}%", coverage(outcome));
        let pointers = outcome.found(Found::POINTER);
        assert!(
            pointers > 100,
            "only {pointers} functions from GOT pointers"
        );
        // Rizin starts these two in a `jr` delay slot; the functions around
        // them nothing funktion sees reaches.
        finds_rizin_except(
            outcome,
            &[
                (0x40_7274, "delay slot of 0x407270"),
                (0x40_bd28, "delay slot of 0x40bd24"),
            ],
        );
        assert_eq!(outcome.recovery.invalid, 0);
    });
}

/// A static uClibc bot for SuperH: calls through literal pools, `.init`
/// and `.fini` calling with `braf` and `lds r0, pr`, and the bot's routines
/// reached only through code addresses in literal pools.
#[test]
fn superh_uclibc_static() {
    check("bot-sh-uclibc-static", |outcome| {
        assert_eq!(outcome.image.arch, funktion::Arch::SuperH);
        assert!(coverage(outcome) >= 75, "covers {}%", coverage(outcome));
        let pointers = outcome.found(Found::POINTER);
        assert!(
            pointers > 20,
            "only {pointers} functions from literal pools"
        );
        finds_rizin_except(
            outcome,
            &[(0x40_b288, "inside the string \"/dev/watchdog\"")],
        );
        // `.fini` calls with `braf` and returns past the literal after it.
        let fini = outcome.entries().get(&0x40_b1c0).map(|f| f.size);
        assert!(matches!(fini, Some(1..64)), ".fini: {fini:?} bytes");
        assert!(outcome.recovery.invalid <= 1);
    });
}

/// MSVC's Windows on 32-bit Arm: Thumb-2 entries from `.pdata`, and calls
/// to imports through slots loaded from literal pools.
#[test]
fn pe_armnt() {
    check("e_sqlite3-win-arm.dll", |outcome| {
        assert_eq!(outcome.image.arch, funktion::Arch::Arm);
        // A case target rizin takes for a function.
        finds_rizin_except(outcome, &[(0x100c_745e, "a case of 0x100a813a")]);
        let (same, shared) = outcome.same_blocks_without_pads();
        assert!(
            shared > 2300 && same * 100 >= shared * 95,
            "{same} of {shared}"
        );
        let slots: std::collections::HashSet<u64> =
            outcome.image.imports.iter().map(|i| i.slot).collect();
        let imported = outcome
            .recovery
            .functions
            .iter()
            .flat_map(|f| &f.refs)
            .filter(|r| r.kind == RefKind::Call && slots.contains(&r.to))
            .count();
        assert!(imported > 140, "only {imported} calls to imports");
    });
}
