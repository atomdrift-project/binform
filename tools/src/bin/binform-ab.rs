//! Compare binform with rizin, file by file.
//!
//! ```text
//! binform-ab [parse] [--rizin PATH] [--script CMDS] [--timeout SECS] [--jobs N] [--save DIR] PATH...
//! ```
//!
//! `parse` compares the layout instead: binform's sections, imports and
//! exports against rizin's `iSj`, `iij` and `iEj`, name by name.
//!
//! Directories are walked. Each supported executable is analysed by both
//! tools; one JSON line per file reports the function-level agreement and the
//! file-level aggregates a consumer derives from either (average and maximum
//! complexity, basic blocks, huge/tiny/leaf function counts, calls), and a
//! summary follows on stderr.
//!
//! Without `--script`, rizin runs the analysis a production consumer would:
//! `aa; aac` for PE on x86, `aaa` when nothing but entry points names a
//! function, and `aa; aac; aap` otherwise.
//!
//! `--save DIR` also writes what rizin found in each file to
//! `DIR/NAME.rizin.json.zst`, for the fixture tests to compare against.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use binform::diagnostics::{is_code, named};
use binform::{Arch, RefKind};
use serde_json::{Value, json};

struct Options {
    /// Compare layouts (`parse`) rather than functions.
    parse: bool,
    rizin: PathBuf,
    script: Option<String>,
    timeout: Duration,
    jobs: usize,
    save: Option<PathBuf>,
    paths: Vec<PathBuf>,
}

fn options() -> Result<Options, String> {
    let mut options = Options {
        parse: false,
        rizin: PathBuf::from("rizin"),
        script: None,
        timeout: Duration::from_secs(600),
        jobs: std::thread::available_parallelism().map_or(4, |n| n.get()),
        save: None,
        paths: Vec::new(),
    };
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = || args.next().ok_or(format!("{arg} needs a value"));
        match arg.as_str() {
            "--rizin" => options.rizin = PathBuf::from(value()?),
            "--script" => options.script = Some(value()?),
            "--timeout" => {
                let secs = value()?.parse().map_err(|e| format!("--timeout: {e}"))?;
                options.timeout = Duration::from_secs(secs);
            }
            "--jobs" => options.jobs = value()?.parse().map_err(|e| format!("--jobs: {e}"))?,
            "--save" => options.save = Some(PathBuf::from(value()?)),
            "parse" if options.paths.is_empty() && !options.parse => options.parse = true,
            _ if arg.starts_with("--") => return Err(format!("unknown option {arg}")),
            _ => options.paths.push(PathBuf::from(arg)),
        }
    }
    if options.paths.is_empty() {
        return Err(
            "usage: binform-ab [parse] [--rizin PATH] [--script CMDS] [--timeout SECS] [--jobs N] PATH..."
                .into(),
        );
    }
    Ok(options)
}

fn main() -> ExitCode {
    let options = match options() {
        Ok(options) => options,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::from(2);
        }
    };
    let mut files = Vec::new();
    for path in &options.paths {
        walk(path, &mut files);
    }
    files.sort();

    let next = AtomicUsize::new(0);
    let reports = Mutex::new(Vec::new());
    std::thread::scope(|scope| {
        for _ in 0..options.jobs.max(1) {
            scope.spawn(|| {
                while let Some(file) = files.get(next.fetch_add(1, Ordering::Relaxed)) {
                    let report = if options.parse {
                        compare_layout(&options, file)
                    } else {
                        compare(&options, file)
                    };
                    if let Some(report) = report {
                        println!("{report}");
                        if let Ok(mut reports) = reports.lock() {
                            reports.push(report);
                        }
                    }
                }
            });
        }
    });
    let reports = reports.into_inner().unwrap_or_default();
    if options.parse {
        summarize_layout(&reports);
    } else {
        summarize(&reports);
    }
    ExitCode::SUCCESS
}

fn walk(path: &Path, files: &mut Vec<PathBuf>) {
    if path.is_dir() {
        let Ok(entries) = std::fs::read_dir(path) else {
            return;
        };
        for entry in entries.flatten() {
            walk(&entry.path(), files);
        }
    } else if path.is_file() {
        files.push(path.to_path_buf());
    }
}

/// The aggregates a consumer derives from a function table.
#[derive(Default)]
struct Shape {
    functions: usize,
    complexity_sum: u64,
    complexity_max: u64,
    blocks: u64,
    huge: usize,
    tiny: usize,
    leaf: usize,
    calls: usize,
}

impl Shape {
    fn add(&mut self, complexity: u64, blocks: u64, refs: usize, calls: usize) {
        self.functions += 1;
        self.complexity_sum += complexity;
        self.complexity_max = self.complexity_max.max(complexity);
        self.blocks += blocks;
        self.huge += usize::from(blocks >= 50);
        self.tiny += usize::from(blocks == 1);
        self.leaf += usize::from(refs == 0);
        self.calls += calls;
    }

    fn json(&self) -> Value {
        let mean = |sum: u64| {
            if self.functions == 0 {
                0.0
            } else {
                sum as f64 / self.functions as f64
            }
        };
        json!({
            "functions": self.functions,
            "avg_complexity": mean(self.complexity_sum),
            "max_complexity": self.complexity_max,
            "avg_basic_blocks": mean(self.blocks),
            "basic_block_count": self.blocks,
            "huge": self.huge,
            "tiny": self.tiny,
            "leaf": self.leaf,
            "calls": self.calls,
        })
    }
}

/// One rizin `aflj` row, as consumers read it.
struct RizinFunction {
    name: String,
    size: u64,
    blocks: u64,
    complexity: u64,
}

fn compare(options: &Options, file: &Path) -> Option<Value> {
    let bytes = std::fs::read(file).ok()?;
    let started = Instant::now();
    let image = binform::parse(&bytes).ok()?;
    let (mut recovery, diagnostics) =
        binform::diagnostics::functions(&image, &binform::Limits::DEFAULT);
    // Thumb entries carry their mode in bit 0; rizin's are the even
    // addresses of their first instructions.
    if image.arch == Some(Arch::Arm) {
        for function in &mut recovery.functions {
            function.entry &= !1;
        }
    }
    let native_ms = started.elapsed().as_secs_f64() * 1e3;

    let script = options
        .script
        .clone()
        .unwrap_or_else(|| default_script(&bytes, &image));
    let started = Instant::now();
    let rizin = run_rizin(options, file, &script);
    let rizin_ms = started.elapsed().as_secs_f64() * 1e3;

    let mut native_shape = Shape::default();
    for function in &recovery.functions {
        let calls = function
            .refs
            .iter()
            .filter(|r| r.kind == RefKind::Call)
            .count();
        // Rizin's `callrefs` leave out conditional branches and jumps
        // through memory.
        let refs = function
            .refs
            .iter()
            .filter(|r| match r.kind {
                RefKind::Branch => false,
                RefKind::Jump => is_code(&image, r.to),
                RefKind::Call | RefKind::Case => true,
            })
            .count();
        native_shape.add(
            u64::from(function.complexity),
            u64::from(function.blocks),
            refs,
            calls,
        );
    }
    let mut report = json!({
        "path": file.display().to_string(),
        "arch": image.arch.map(|arch| format!("{arch:?}")),
        "script": script,
        "native_ms": native_ms,
        "rizin_ms": rizin_ms,
        "native": native_shape.json(),
        "code": recovery.code,
        "covered": recovery.covered,
        "invalid": recovery.invalid,
        "unresolved": recovery.unresolved,
        "truncated": recovery.truncated,
    });
    let Some(rows) = rizin else {
        report["rizin"] = Value::Null;
        return Some(report);
    };
    if let Some(dir) = &options.save
        && let Err(error) = save(dir, file, &script, &rows)
    {
        eprintln!("binform-ab: saving {}: {error}", file.display());
    }

    let mut rizin_shape = Shape::default();
    let mut by_entry: HashMap<u64, RizinFunction> = HashMap::new();
    for row in &rows {
        let get = |key: &str| row.get(key).and_then(Value::as_u64).unwrap_or(0);
        let refs = row.get("callrefs").and_then(Value::as_array);
        let calls = refs.map_or(0, |refs| {
            refs.iter()
                .filter(|r| r.get("type").and_then(Value::as_str) == Some("CALL"))
                .count()
        });
        rizin_shape.add(get("cc"), get("nbbs"), refs.map_or(0, Vec::len), calls);
        by_entry.insert(
            get("offset"),
            RizinFunction {
                name: row
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                size: get("size"),
                blocks: get("nbbs"),
                complexity: get("cc"),
            },
        );
    }
    let (mut shared, mut same_blocks, mut same_complexity, mut same_size) = (0, 0, 0, 0);
    // Rizin does not walk landing pads: a function with one has blocks it
    // lacks, so those are compared apart.
    let padded: HashSet<u64> = recovery
        .functions
        .iter()
        .zip(&diagnostics)
        .filter(|(_, diagnostic)| diagnostic.padded)
        .map(|(function, _)| function.entry)
        .collect();
    let (mut shared_padded, mut same_blocks_padded) = (0, 0);
    // Functions only binform found, by how it found them.
    let mut only_native: BTreeMap<String, usize> = BTreeMap::new();
    for (function, diagnostic) in recovery.functions.iter().zip(&diagnostics) {
        if let Some(theirs) = by_entry.get(&function.entry) {
            shared += 1;
            let same = theirs.blocks == u64::from(function.blocks);
            if padded.contains(&function.entry) {
                shared_padded += 1;
                same_blocks_padded += usize::from(same);
            }
            same_blocks += usize::from(same);
            same_complexity += usize::from(theirs.complexity == u64::from(function.complexity));
            same_size += usize::from(theirs.size == function.size);
        } else {
            *only_native.entry(diagnostic.found.join("|")).or_default() += 1;
        }
    }
    // Functions only rizin found: each needs a reason.
    let native: HashSet<u64> = recovery.functions.iter().map(|f| f.entry).collect();
    let mut only_rizin: Vec<(u64, &str)> = by_entry
        .iter()
        .filter(|(entry, _)| !native.contains(entry))
        .map(|(&entry, theirs)| (entry, theirs.name.as_str()))
        .collect();
    only_rizin.sort_unstable();
    // Those that start inside a function binform recovered (its first to
    // last byte): a fragment of it, to rizin, or a function it overlaps.
    let mut extents: Vec<(u64, u64)> = recovery
        .functions
        .iter()
        .map(|f| (f.entry, f.entry.saturating_add(f.size)))
        .collect();
    extents.sort_unstable();
    let within = |entry: u64| {
        let i = extents.partition_point(|&(start, _)| start <= entry);
        i > 0 && entry < extents[i - 1].1
    };
    let inside = only_rizin.iter().filter(|&&(entry, _)| within(entry)).count();
    // The rest that start in an executable section: rizin also makes
    // functions of the strings and tables in `.rodata` or the headers when
    // an executable segment maps them, which no recovery should match.
    let code: Vec<&binform::Section> = image.sections.iter().filter(|s| s.executable).collect();
    let in_code = |entry: u64| {
        code.is_empty()
            || code
                .iter()
                .any(|s| entry >= s.addr && entry - s.addr < s.size)
    };
    let outside_code = only_rizin
        .iter()
        .filter(|&&(entry, _)| !within(entry) && in_code(entry))
        .count();
    report["rizin"] = rizin_shape.json();
    report["shared"] = json!(shared);
    // Counted from the lists themselves: `shared` pairs entries, and an
    // entry both sides list twice would make the differences underflow.
    report["only_rizin"] = json!(only_rizin.len());
    report["only_native"] = json!(recovery.functions.len().saturating_sub(shared));
    report["only_native_found"] = json!(only_native);
    report["only_rizin_functions"] = only_rizin
        .iter()
        .map(|(entry, name)| json!({"entry": entry, "name": name}))
        .collect();
    report["same_blocks"] = json!(same_blocks);
    report["same_complexity"] = json!(same_complexity);
    report["same_size"] = json!(same_size);
    report["shared_padded"] = json!(shared_padded);
    report["same_blocks_padded"] = json!(same_blocks_padded);
    report["only_rizin_inside"] = json!(inside);
    report["only_rizin_code"] = json!(outside_code);
    Some(report)
}

/// Write rizin's functions in `file` as `[offset, name, size, blocks,
/// complexity]` rows, one per line, sorted by offset and compressed.
fn save(dir: &Path, file: &Path, script: &str, rows: &[Value]) -> std::io::Result<()> {
    let mut functions: Vec<(u64, String, u64, u64, u64)> = rows
        .iter()
        .map(|row| {
            let get = |key: &str| row.get(key).and_then(Value::as_u64).unwrap_or(0);
            let name = row.get("name").and_then(Value::as_str).unwrap_or_default();
            (
                get("offset"),
                name.to_owned(),
                get("size"),
                get("nbbs"),
                get("cc"),
            )
        })
        .collect();
    functions.sort_unstable();
    let mut text = format!("{{\"script\": {},\n\"functions\": [\n", json!(script));
    for (i, function) in functions.iter().enumerate() {
        let comma = if i + 1 < functions.len() { "," } else { "" };
        text.push_str(&format!("{}{comma}\n", json!(function)));
    }
    text.push_str("]}\n");
    let name = file.file_name().unwrap_or_default().to_string_lossy();
    let path = dir.join(format!("{name}.rizin.json.zst"));
    std::fs::write(path, zstd::encode_all(text.as_bytes(), 19)?)
}

fn default_script(bytes: &[u8], image: &binform::Binary<'_>) -> String {
    let pe = bytes.starts_with(b"MZ");
    let named = named(image);
    if pe && matches!(image.arch, Some(Arch::X86 | Arch::X86_64)) {
        "aa; aac".into()
    } else if !named {
        "aaa".into()
    } else {
        "aa; aac; aap".into()
    }
}

/// Rizin's `aflj` after `script`, or `None` when it failed or timed out.
fn run_rizin(options: &Options, file: &Path, script: &str) -> Option<Vec<Value>> {
    let text = rizin_output(options, file, &format!("{script}; aflj"))?;
    let start = text.find('[')?;
    serde_json::from_str(&text[start..]).ok()
}

/// What rizin prints for `commands`, or `None` when it failed or timed out.
fn rizin_output(options: &Options, file: &Path, commands: &str) -> Option<String> {
    let mut child = Command::new(&options.rizin)
        .args([
            "-NN",
            "-q",
            "-T",
            "-z",
            "-e",
            "scr.color=0",
            "-e",
            "log.level=3",
            "-e",
            "analysis.vars=false",
            "-c",
        ])
        .arg(commands)
        .arg(file)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let mut stdout = child.stdout.take()?;
    let reader = std::thread::spawn(move || {
        let mut out = Vec::new();
        let _ = stdout.read_to_end(&mut out);
        out
    });
    let deadline = Instant::now() + options.timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(2)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    let out = reader.join().ok()?;
    status.filter(std::process::ExitStatus::success)?;
    Some(String::from_utf8_lossy(&out).into_owned())
}

/// A name as both tools can agree on it: rizin numbers Mach-O sections
/// (`0.__TEXT.__text`) and drops the underscore (and the Objective-C class
/// prefix) from Mach-O imports, which binform spells as the binary does.
fn normal(table: &str, macho: bool, rizin: bool, name: &str) -> String {
    if !macho {
        return name.to_owned();
    }
    match table {
        "sections" if rizin => name
            .split_once('.')
            .filter(|(index, _)| index.bytes().all(|b| b.is_ascii_digit()))
            .map_or(name, |(_, rest)| rest)
            .to_owned(),
        "imports" if !rizin => {
            let name = name.strip_prefix("_OBJC_CLASS_$_").unwrap_or(name);
            name.strip_prefix('_').unwrap_or(name).to_owned()
        }
        _ => name.to_owned(),
    }
}

/// binform's layout against rizin's `iSj`, `iij` and `iEj`.
fn compare_layout(options: &Options, file: &Path) -> Option<Value> {
    let bytes = std::fs::read(file).ok()?;
    let started = Instant::now();
    let bin = binform::parse(&bytes).ok()?;
    let native_ms = started.elapsed().as_secs_f64() * 1e3;
    let macho = bin.format == binform::Format::MachO;
    let started = Instant::now();
    let output = rizin_output(
        options,
        file,
        "e bin.demangle=false; iSj; echo ===SEP===; iij; echo ===SEP===; iEj",
    );
    let rizin_ms = started.elapsed().as_secs_f64() * 1e3;
    let mut report = json!({
        "path": file.display().to_string(),
        "format": format!("{:?}", bin.format),
        "arch": bin.arch.map(|arch| format!("{arch:?}")),
        "native_ms": native_ms,
        "rizin_ms": rizin_ms,
    });
    let Some(output) = output else {
        report["rizin"] = Value::Null;
        return Some(report);
    };
    let tables: Vec<Vec<Value>> = output
        .split("===SEP===")
        .map(|block| {
            block
                .find('[')
                .and_then(|start| serde_json::from_str(&block[start..]).ok())
                .unwrap_or_default()
        })
        .collect();
    let ours: [Vec<String>; 3] = [
        bin.sections.iter().map(|s| s.name.clone()).collect(),
        bin.imports.iter().map(|i| i.name.clone()).collect(),
        bin.exports.iter().map(|e| e.name.clone()).collect(),
    ];
    for (i, table) in ["sections", "imports", "exports"].into_iter().enumerate() {
        let theirs: HashSet<String> = tables
            .get(i)
            .into_iter()
            .flatten()
            .filter_map(|row| row["name"].as_str())
            .filter(|name| !name.is_empty())
            .map(|name| normal(table, macho, true, name))
            .collect();
        let mine: HashSet<String> = ours[i]
            .iter()
            .filter(|name| !name.is_empty())
            .map(|name| normal(table, macho, false, name))
            .collect();
        let mut only_rizin: Vec<&String> = theirs.difference(&mine).collect();
        let mut only_native: Vec<&String> = mine.difference(&theirs).collect();
        only_rizin.sort();
        only_native.sort();
        report[table] = json!({
            "rizin": theirs.len(),
            "native": mine.len(),
            "shared": theirs.intersection(&mine).count(),
            "only_rizin": only_rizin.iter().take(8).collect::<Vec<_>>(),
            "only_native": only_native.iter().take(8).collect::<Vec<_>>(),
        });
    }
    // Shared sections whose address, size or permissions differ.
    let mut differ = Vec::new();
    for row in tables.first().into_iter().flatten() {
        let Some(name) = row["name"].as_str() else {
            continue;
        };
        let name = normal("sections", macho, true, name);
        let Some(section) = bin.sections.iter().find(|s| s.name == name) else {
            continue;
        };
        let perm = row["perm"].as_str().unwrap_or("");
        // Rizin gives a section no loader maps the address -1.
        let mapped = section.readable || section.writable || section.executable;
        let addr = if mapped { section.addr } else { u64::MAX };
        let same = row["vaddr"].as_u64() == Some(addr)
            && row["vsize"].as_u64() == Some(section.size)
            && row["size"].as_u64() == Some(section.file_size)
            && perm.contains('x') == section.executable
            && perm.contains('w') == section.writable;
        if !same {
            differ.push(name);
        }
    }
    report["sections"]["differ"] = json!(differ);
    // Import libraries, where both name one.
    let libraries: HashMap<String, String> = tables
        .get(1)
        .into_iter()
        .flatten()
        .filter_map(|row| {
            let name = normal("imports", macho, true, row["name"].as_str()?);
            Some((name, row["libname"].as_str()?.to_owned()))
        })
        .collect();
    let library_differ = bin
        .imports
        .iter()
        .filter_map(|import| {
            let theirs = libraries.get(&normal("imports", macho, false, &import.name))?;
            let mine = import.library.as_deref()?;
            (!theirs.eq_ignore_ascii_case(mine))
                .then(|| format!("{}: {mine} / {theirs}", import.name))
        })
        .take(8)
        .collect::<Vec<_>>();
    report["imports"]["library_differ"] = json!(library_differ);
    Some(report)
}

fn summarize_layout(reports: &[Value]) {
    let compared: Vec<&Value> = reports
        .iter()
        .filter(|r| r["sections"].is_object())
        .collect();
    eprintln!(
        "files compared: {} (rizin failed on {})",
        compared.len(),
        reports.len() - compared.len()
    );
    let sum = |key: &str| -> f64 { compared.iter().filter_map(|r| r[key].as_f64()).sum() };
    eprintln!(
        "time: binform {:.1} ms, rizin {:.1} s",
        sum("native_ms"),
        sum("rizin_ms") / 1e3
    );
    for table in ["sections", "imports", "exports"] {
        let total =
            |key: &str| -> u64 { compared.iter().filter_map(|r| r[table][key].as_u64()).sum() };
        let disagree = compared
            .iter()
            .filter(|r| {
                r[table]["only_rizin"]
                    .as_array()
                    .is_some_and(|a| !a.is_empty())
                    || r[table]["only_native"]
                        .as_array()
                        .is_some_and(|a| !a.is_empty())
            })
            .count();
        eprintln!(
            "{table}: rizin {}, binform {}, shared {}; files that disagree: {disagree}",
            total("rizin"),
            total("native"),
            total("shared"),
        );
    }
    let differ = compared
        .iter()
        .filter(|r| {
            r["sections"]["differ"]
                .as_array()
                .is_some_and(|a| !a.is_empty())
        })
        .count();
    eprintln!("files with shared sections whose layout differs: {differ}");
}

fn summarize(reports: &[Value]) {
    let compared: Vec<&Value> = reports.iter().filter(|r| !r["rizin"].is_null()).collect();
    let sum = |key: &str| -> f64 { compared.iter().filter_map(|r| r[key].as_f64()).sum() };
    let native_fns: f64 = compared
        .iter()
        .filter_map(|r| r["native"]["functions"].as_f64())
        .sum();
    let rizin_fns: f64 = compared
        .iter()
        .filter_map(|r| r["rizin"]["functions"].as_f64())
        .sum();
    let shared = sum("shared");
    let ratio = |a: f64, b: f64| if b == 0.0 { 0.0 } else { 100.0 * a / b };
    eprintln!(
        "files compared: {} (rizin failed on {})",
        compared.len(),
        reports.len() - compared.len()
    );
    eprintln!(
        "time: binform {:.1} s, rizin {:.1} s",
        sum("native_ms") / 1e3,
        sum("rizin_ms") / 1e3
    );
    eprintln!(
        "functions: rizin {rizin_fns}, binform {native_fns}, shared {shared} ({:.1}% of rizin's, {:.1}% of binform's)",
        ratio(shared, rizin_fns),
        ratio(shared, native_fns)
    );
    eprintln!(
        "on shared entries: same blocks {:.1}%, same complexity {:.1}%, same size {:.1}%",
        ratio(sum("same_blocks"), shared),
        ratio(sum("same_complexity"), shared),
        ratio(sum("same_size"), shared)
    );
    let padded = sum("shared_padded");
    eprintln!(
        "  without landing pads: same blocks {:.1}% of {}; with them (rizin skips pads): {:.1}% of {padded}",
        ratio(
            sum("same_blocks") - sum("same_blocks_padded"),
            shared - padded
        ),
        shared - padded,
        ratio(sum("same_blocks_padded"), padded),
    );
    eprintln!(
        "only rizin: {} entries, {} of them inside a function binform recovered",
        sum("only_rizin"),
        sum("only_rizin_inside")
    );
    let mut found: BTreeMap<String, u64> = BTreeMap::new();
    for report in &compared {
        if let Some(ways) = report["only_native_found"].as_object() {
            for (how, count) in ways {
                *found.entry(how.clone()).or_default() += count.as_u64().unwrap_or(0);
            }
        }
    }
    eprintln!("only binform, by how it found them: {found:?}");
    for report in &compared {
        let Some(missed) = report["only_rizin_functions"].as_array() else {
            continue;
        };
        if missed.is_empty() {
            continue;
        }
        let names: Vec<String> = missed
            .iter()
            .take(8)
            .map(|m| {
                let entry = m["entry"].as_u64().unwrap_or(0);
                format!("{entry:#x} {}", m["name"].as_str().unwrap_or(""))
            })
            .collect();
        eprintln!(
            "only rizin, {} in {}: {}",
            missed.len(),
            report["path"].as_str().unwrap_or(""),
            names.join(", ")
        );
    }
    for key in [
        "avg_complexity",
        "max_complexity",
        "avg_basic_blocks",
        "huge",
        "tiny",
        "leaf",
    ] {
        let close = compared
            .iter()
            .filter(|r| {
                let (a, b) = (
                    r["native"][key].as_f64().unwrap_or(0.0),
                    r["rizin"][key].as_f64().unwrap_or(0.0),
                );
                (a - b).abs() <= 0.05 * b.abs().max(1.0)
            })
            .count();
        eprintln!("{key}: within 5% on {close} of {} files", compared.len());
    }
}
