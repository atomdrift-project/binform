//! Compare funktion with rizin, file by file.
//!
//! ```text
//! funktion-ab [--rizin PATH] [--script CMDS] [--timeout SECS] [--jobs N] [--save DIR] PATH...
//! ```
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

use funktion::{Arch, Origin, RefKind};
use serde_json::{Value, json};

struct Options {
    rizin: PathBuf,
    script: Option<String>,
    timeout: Duration,
    jobs: usize,
    save: Option<PathBuf>,
    paths: Vec<PathBuf>,
}

fn options() -> Result<Options, String> {
    let mut options = Options {
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
            _ if arg.starts_with("--") => return Err(format!("unknown option {arg}")),
            _ => options.paths.push(PathBuf::from(arg)),
        }
    }
    if options.paths.is_empty() {
        return Err(
            "usage: funktion-ab [--rizin PATH] [--script CMDS] [--timeout SECS] [--jobs N] PATH..."
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
                    if let Some(report) = compare(&options, file) {
                        println!("{report}");
                        if let Ok(mut reports) = reports.lock() {
                            reports.push(report);
                        }
                    }
                }
            });
        }
    });
    summarize(&reports.into_inner().unwrap_or_default());
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
    let image = funktion::object::image(&bytes).ok()?;
    let mut recovery = funktion::recover(&image);
    // Thumb entries carry their mode in bit 0; rizin's are the even
    // addresses of their first instructions.
    if image.arch == Arch::Arm {
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
        "arch": format!("{:?}", image.arch),
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
        eprintln!("funktion-ab: saving {}: {error}", file.display());
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
    let padded: HashSet<u64> = image.handlers.iter().map(|h| h.function).collect();
    let (mut shared_padded, mut same_blocks_padded) = (0, 0);
    // Functions only funktion found, by how it found them.
    let mut only_native: BTreeMap<String, usize> = BTreeMap::new();
    for function in &recovery.functions {
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
            let how: Vec<&str> = function.found.names().collect();
            *only_native.entry(how.join("|")).or_default() += 1;
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
    // Those that start inside a function funktion recovered (its first to
    // last byte): a fragment of it, to rizin, or a function it overlaps.
    let mut extents: Vec<(u64, u64)> = recovery
        .functions
        .iter()
        .map(|f| (f.entry, f.entry.saturating_add(f.size)))
        .collect();
    extents.sort_unstable();
    let inside = only_rizin
        .iter()
        .filter(|&&(entry, _)| {
            let i = extents.partition_point(|&(start, _)| start <= entry);
            i > 0 && entry < extents[i - 1].1
        })
        .count();
    report["rizin"] = rizin_shape.json();
    report["shared"] = json!(shared);
    report["only_rizin"] = json!(by_entry.len() - shared);
    report["only_native"] = json!(recovery.functions.len() - shared);
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

fn is_code(image: &funktion::Image<'_>, addr: u64) -> bool {
    image.segments.iter().any(|segment| {
        segment.executable
            && addr
                .checked_sub(segment.addr)
                .is_some_and(|offset| offset < segment.bytes.len() as u64)
    })
}

fn default_script(bytes: &[u8], image: &funktion::Image<'_>) -> String {
    let pe = bytes.starts_with(b"MZ");
    let named = image.seeds.iter().any(|seed| {
        !matches!(
            seed.origin,
            Origin::Entry | Origin::Init(_) | Origin::Fini(_) | Origin::Tls(_)
        )
    });
    if pe && matches!(image.arch, Arch::X86 | Arch::X86_64) {
        "aa; aac".into()
    } else if !named {
        "aaa".into()
    } else {
        "aa; aac; aap".into()
    }
}

/// Rizin's `aflj` after `script`, or `None` when it failed or timed out.
fn run_rizin(options: &Options, file: &Path, script: &str) -> Option<Vec<Value>> {
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
        .arg(format!("{script}; aflj"))
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
    let text = String::from_utf8_lossy(&out);
    let start = text.find('[')?;
    serde_json::from_str(&text[start..]).ok()
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
        "time: funktion {:.1} s, rizin {:.1} s",
        sum("native_ms") / 1e3,
        sum("rizin_ms") / 1e3
    );
    eprintln!(
        "functions: rizin {rizin_fns}, funktion {native_fns}, shared {shared} ({:.1}% of rizin's, {:.1}% of funktion's)",
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
        "only rizin: {} entries, {} of them inside a function funktion recovered",
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
    eprintln!("only funktion, by how it found them: {found:?}");
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
