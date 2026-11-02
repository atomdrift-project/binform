//! Print the functions funktion recovers from each file named on the command
//! line, one JSON object per file.

use std::process::ExitCode;

use serde_json::json;

fn main() -> ExitCode {
    let paths: Vec<String> = std::env::args().skip(1).collect();
    if paths.is_empty() {
        eprintln!("usage: funktion FILE...");
        return ExitCode::from(2);
    }
    let mut status = ExitCode::SUCCESS;
    for path in &paths {
        match dump(path) {
            Ok(value) => println!("{value}"),
            Err(error) => {
                eprintln!("funktion: {path}: {error}");
                status = ExitCode::FAILURE;
            }
        }
    }
    status
}

fn dump(path: &str) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let bytes = std::fs::read(path)?;
    let image = funktion::object::image(&bytes)?;
    let recovery = funktion::recover(&image);
    let functions: Vec<serde_json::Value> = recovery
        .functions
        .iter()
        .map(|f| {
            let refs: Vec<serde_json::Value> = f
                .refs
                .iter()
                .map(|r| {
                    let kind = match r.kind {
                        funktion::RefKind::Call => "call",
                        funktion::RefKind::Jump => "jump",
                        funktion::RefKind::Branch => "branch",
                        funktion::RefKind::Case => "case",
                    };
                    json!({"from": r.from, "to": r.to, "kind": kind})
                })
                .collect();
            json!({
                "entry": f.entry,
                "size": f.size,
                "blocks": f.blocks,
                "edges": f.edges,
                "complexity": f.complexity,
                "thunk": f.thunk,
                "found": f.found.names().collect::<Vec<_>>(),
                "refs": refs,
            })
        })
        .collect();
    Ok(json!({
        "path": path,
        "arch": format!("{:?}", image.arch),
        "seeds": image.seeds.len(),
        "imports": image.imports.len(),
        "covered": recovery.covered,
        "truncated": recovery.truncated,
        "functions": functions,
    }))
}
