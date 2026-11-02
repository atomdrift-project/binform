//! Measure CIL method bodies: `funktion-cil FILE < offsets`, one file offset
//! of a method header per line (decimal or `0x` hex); one JSON line each.

use std::io::BufRead;
use std::process::ExitCode;

use serde_json::json;

fn main() -> ExitCode {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: funktion-cil FILE < offsets");
        return ExitCode::from(2);
    };
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("funktion-cil: {path}: {error}");
            return ExitCode::FAILURE;
        }
    };
    for line in std::io::stdin().lock().lines().map_while(Result::ok) {
        let line = line.trim();
        let offset = match line.strip_prefix("0x") {
            Some(hex) => usize::from_str_radix(hex, 16).ok(),
            None => line.parse().ok(),
        };
        let Some(offset) = offset else { continue };
        let body = bytes
            .get(offset..)
            .and_then(funktion::cil::body)
            .map(|b| {
                json!({
                    "size": b.size,
                    "instructions": b.instructions,
                    "blocks": b.blocks,
                    "edges": b.edges,
                    "complexity": b.complexity,
                })
            });
        println!("{}", json!({"offset": offset, "body": body}));
    }
    ExitCode::SUCCESS
}
