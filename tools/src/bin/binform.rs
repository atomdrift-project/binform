//! Print what binform reads from each file named on the command line, one
//! JSON object per file: its functions (`binform [functions] FILE...`), its
//! layout (`binform parse FILE...`), or its call and syscall sites
//! (`binform calls FILE...`).

use std::process::ExitCode;

use serde_json::json;

fn main() -> ExitCode {
    let mut paths: Vec<String> = std::env::args().skip(1).collect();
    let verb = match paths.first().map(String::as_str) {
        Some("parse") => layout,
        Some("functions") => dump,
        Some("calls") => calls,
        _ => {
            paths.insert(0, String::new());
            dump
        }
    };
    paths.remove(0);
    if paths.is_empty() {
        eprintln!("usage: binform [parse|functions|calls] FILE...");
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

fn dump(path: &str) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let bytes = std::fs::read(path)?;
    let image = binform::parse(&bytes)?;
    let (recovery, diagnostics) =
        binform::diagnostics::functions(&image, &binform::Limits::DEFAULT);
    let functions: Vec<serde_json::Value> = recovery
        .functions
        .iter()
        .zip(&diagnostics)
        .map(|(f, d)| {
            let refs: Vec<serde_json::Value> = f
                .refs
                .iter()
                .map(|r| {
                    let kind = match r.kind {
                        binform::RefKind::Call => "call",
                        binform::RefKind::Jump => "jump",
                        binform::RefKind::Branch => "branch",
                        binform::RefKind::Case => "case",
                    };
                    json!({
                        "from": r.from,
                        "to": r.to,
                        "kind": kind,
                        "name": recovery.name(&image, r.to),
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
        "arch": image.arch.map(|arch| format!("{arch:?}")),
        "code": recovery.code,
        "covered": recovery.covered,
        "invalid": recovery.invalid,
        "unresolved": recovery.unresolved,
        "truncated": recovery.truncated,
        "functions": functions,
    }))
}

fn calls(path: &str) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let bytes = std::fs::read(path)?;
    let bin = binform::parse(&bytes)?;
    let funcs = binform::functions(&bin, &binform::Limits::DEFAULT);
    let value = |v: &binform::Value| match v {
        binform::Value::Unknown => serde_json::Value::Null,
        binform::Value::Int(n) => json!(n),
        binform::Value::Mem { addr, bytes } => json!({
            "addr": addr,
            "bytes": bytes.iter().map(|b| b.map(serde_json::Value::from)
                .unwrap_or(serde_json::Value::Null)).collect::<Vec<_>>(),
        }),
    };
    let sites: Vec<serde_json::Value> = binform::calls(&bin, &funcs)
        .iter()
        .map(|c| {
            let (kind, name) = match c.target {
                binform::Target::Syscall(n) => ("syscall", json!({"number": n, "name": bin.syscall(n)})),
                binform::Target::Import(i) => ("import", json!(bin.imports.get(i).map(|m| &m.name))),
                binform::Target::Addr(a) => ("call", json!(a)),
                binform::Target::Unknown => ("indirect", serde_json::Value::Null),
            };
            json!({
                "addr": c.addr,
                "kind": kind,
                "target": name,
                "args": c.args.iter().map(value).collect::<Vec<_>>(),
            })
        })
        .collect();
    Ok(json!({
        "path": path,
        "arch": bin.arch.map(|arch| format!("{arch:?}")),
        "calls": sites,
    }))
}

fn layout(path: &str) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let bytes = std::fs::read(path)?;
    let bin = binform::parse(&bytes)?;
    let sections: Vec<serde_json::Value> = bin
        .sections
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
                    if s.readable { 'r' } else { '-' },
                    if s.writable { 'w' } else { '-' },
                    if s.executable { 'x' } else { '-' }
                ),
            })
        })
        .collect();
    let imports: Vec<serde_json::Value> = bin
        .imports
        .iter()
        .map(
            |i| json!({"name": i.name, "library": i.library, "ordinal": i.ordinal, "slot": i.slot}),
        )
        .collect();
    let exports: Vec<serde_json::Value> = bin
        .exports
        .iter()
        .map(|e| json!({"name": e.name, "addr": e.addr, "forward": e.forward}))
        .collect();
    Ok(json!({
        "path": path,
        "format": format!("{:?}", bin.format),
        "arch": bin.arch.map(|arch| format!("{arch:?}")),
        "entry": bin.entry,
        "sections": sections,
        "imports": imports,
        "exports": exports,
    }))
}
