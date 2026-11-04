//! Print what binform reads from each file named on the command line, one
//! JSON object per file:
//!
//! ```text
//! binform functions FILE...   its functions, blocks and references
//! binform layout FILE...      its sections, imports and exports
//! binform calls FILE...       its call and syscall sites, with arguments
//! ```

use std::process::ExitCode;

use binform::{Binary, Dest, RefKind, Target};
use serde_json::{Value, json};

const USAGE: &str = "usage: binform functions|layout|calls FILE...";

type Report = Result<Value, Box<dyn std::error::Error>>;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let verb: fn(&str) -> Report = match args.next().as_deref() {
        Some("functions") => functions,
        Some("layout") => layout,
        Some("calls") => calls,
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    let paths: Vec<String> = args.collect();
    if paths.is_empty() {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    }
    let mut status = ExitCode::SUCCESS;
    for path in &paths {
        match verb(path) {
            Ok(value) => println!("{value}"),
            Err(error) => {
                eprintln!("binform: {path}: {error}");
                status = ExitCode::FAILURE;
            }
        }
    }
    status
}

fn arch(bin: &Binary<'_>) -> Option<String> {
    bin.arch().map(|arch| format!("{arch:?}"))
}

fn functions(path: &str) -> Report {
    let bytes = std::fs::read(path)?;
    let bin = binform::parse(&bytes)?;
    let (recovery, diagnostics) = binform::diagnostics::recover(&bin, &binform::Limits::DEFAULT);
    let functions: Vec<Value> = recovery
        .functions
        .iter()
        .zip(&diagnostics)
        .map(|(f, d)| {
            let refs: Vec<Value> = f
                .refs
                .iter()
                .map(|r| {
                    let kind = match r.kind {
                        RefKind::Call => "call",
                        RefKind::Jump => "jump",
                        RefKind::Branch => "branch",
                        RefKind::Case => "case",
                        _ => "other",
                    };
                    let slot = matches!(r.to, Dest::Slot { .. });
                    json!({
                        "from": r.from,
                        "to": r.addr(),
                        "slot": slot,
                        "kind": kind,
                        "name": recovery.name(&bin, r.to),
                    })
                })
                .collect();
            json!({
                "entry": f.entry,
                "name": f.name,
                "size": f.size,
                "blocks": f.blocks,
                "edges": d.edges,
                "complexity": f.complexity,
                "thunk": d.thunk,
                "found": d.found,
                "padded": d.padded,
                "refs": refs,
            })
        })
        .collect();
    Ok(json!({
        "path": path,
        "arch": arch(&bin),
        "code": recovery.code,
        "covered": recovery.covered,
        "invalid": recovery.invalid,
        "unresolved": recovery.unresolved,
        "truncated": recovery.truncated,
        "functions": functions,
    }))
}

fn calls(path: &str) -> Report {
    let bytes = std::fs::read(path)?;
    let bin = binform::parse(&bytes)?;
    let recovery = binform::recover(&bin, &binform::Limits::DEFAULT);
    let value = |v: &binform::Value| match v {
        binform::Value::Int(n) => json!(n),
        binform::Value::Mem { addr, bytes } => json!({
            "addr": addr,
            "bytes": bytes,
        }),
        _ => Value::Null,
    };
    // Every target has the same shape: what kind it is, its address or
    // number where it has one, and its name where it has one.
    let sites: Vec<Value> = binform::calls(&bin, &recovery)
        .iter()
        .map(|c| {
            let (kind, number, name) = match c.target {
                Target::Syscall(n) => ("syscall", n, n.and_then(|n| bin.syscall(n))),
                Target::Import(i) => (
                    "import",
                    None,
                    bin.imports().get(i).map(|m| m.name.as_str()),
                ),
                Target::Addr(a) => (
                    "call",
                    Some(a),
                    recovery.function(a).and_then(|f| f.name.as_deref()),
                ),
                _ => ("indirect", None, None),
            };
            json!({
                "addr": c.addr,
                "target": {"kind": kind, "value": number, "name": name},
                "args": c.args.iter().map(value).collect::<Vec<_>>(),
            })
        })
        .collect();
    Ok(json!({
        "path": path,
        "arch": arch(&bin),
        "calls": sites,
    }))
}

fn layout(path: &str) -> Report {
    let bytes = std::fs::read(path)?;
    let bin = binform::parse(&bytes)?;
    let flag = |set: bool, c: char| if set { c } else { '-' };
    let sections: Vec<Value> = bin
        .sections()
        .iter()
        .map(|s| {
            json!({
                "name": s.name,
                "addr": s.addr,
                "size": s.size,
                "offset": s.offset,
                "file_size": s.file_size,
                "perm": format!(
                    "{}{}{}",
                    flag(s.readable, 'r'),
                    flag(s.writable, 'w'),
                    flag(s.executable, 'x')
                ),
            })
        })
        .collect();
    let imports: Vec<Value> = bin
        .imports()
        .iter()
        .map(|i| {
            json!({
                "name": i.name,
                "library": i.library,
                "ordinal": i.ordinal,
                "slot": i.slot,
                "delayed": i.delayed,
            })
        })
        .collect();
    let exports: Vec<Value> = bin
        .exports()
        .iter()
        .map(|e| json!({"name": e.name, "addr": e.addr, "forward": e.forward}))
        .collect();
    Ok(json!({
        "path": path,
        "format": format!("{:?}", bin.format()),
        "arch": arch(&bin),
        "entry": bin.entry(),
        "sections": sections,
        "imports": imports,
        "exports": exports,
    }))
}
