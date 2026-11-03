//! Print the functions binform recovers from each file named on the command
//! line, one JSON object per file.

use std::process::ExitCode;

use serde_json::json;

fn main() -> ExitCode {
    let paths: Vec<String> = std::env::args().skip(1).collect();
    if paths.is_empty() {
        eprintln!("usage: binform FILE...");
        return ExitCode::from(2);
    }
    let mut status = ExitCode::SUCCESS;
    for path in &paths {
        match dump(path) {
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
        "arch": format!("{:?}", image.arch),
        "code": recovery.code,
        "covered": recovery.covered,
        "invalid": recovery.invalid,
        "unresolved": recovery.unresolved,
        "truncated": recovery.truncated,
        "functions": functions,
    }))
}
