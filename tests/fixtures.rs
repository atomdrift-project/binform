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
    let recovery = funktion::recover(&image);
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
