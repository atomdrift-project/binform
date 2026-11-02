//! Common Intermediate Language method bodies (ECMA-335 partition II §25.4
//! and partition III).
//!
//! A managed method needs no recovery: metadata gives each body's address,
//! the body's header gives its length, and the code holds nothing but
//! instructions, so it decodes linearly. What remains is its control-flow
//! graph, measured as for native functions.

use std::collections::BTreeSet;

/// The control-flow graph of one method body, measured as for a native
/// [`Function`](crate::Function).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Body {
    /// Bytes of code, excluding the header and exception clauses.
    pub size: u32,
    /// Instructions, counting a prefix (`tail.`, `constrained.`) as one.
    pub instructions: u32,
    /// Basic blocks reachable from the start or an exception handler.
    pub blocks: u32,
    /// Control-flow edges between blocks, one per `switch` case and one for
    /// its fall-through.
    pub edges: u32,
    /// McCabe complexity, `edges - blocks + 2 * exits`.
    pub complexity: u32,
}

/// Where control goes after one instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Flow {
    Next,
    Jump(i64),
    Branch(i64),
    /// A `switch`: its targets are in `Insn::cases`.
    Switch,
    /// `ret`, `throw`, `rethrow`, `jmp`, `endfinally`, `endfilter`.
    Exit,
}

struct Insn {
    at: usize,
    next: usize,
    flow: Flow,
    /// The case targets of a `switch`.
    cases: Vec<i64>,
}

/// Measure the method body whose header starts `bytes`. `None` when the
/// header, the code or an exception clause is malformed.
#[must_use]
pub fn body(bytes: &[u8]) -> Option<Body> {
    let (code, handlers) = split(bytes)?;
    let insns = decode(code)?;
    let starts: BTreeSet<usize> = insns.iter().map(|insn| insn.at).collect();
    let target = |offset: i64| {
        usize::try_from(offset)
            .ok()
            .filter(|offset| starts.contains(offset))
    };
    let index = |offset: usize| insns.binary_search_by_key(&offset, |insn| insn.at).ok();

    // Every block start, then the blocks reachable from the code's start and
    // from each handler, which the runtime enters on an exception.
    let mut leaders = BTreeSet::from([0]);
    for &handler in &handlers {
        leaders.insert(target(i64::from(handler))?);
    }
    for insn in &insns {
        let targets = match insn.flow {
            Flow::Jump(to) | Flow::Branch(to) => vec![to],
            Flow::Switch => insn.cases.clone(),
            Flow::Next | Flow::Exit => continue,
        };
        for to in targets {
            leaders.insert(target(to)?);
        }
        if !matches!(insn.flow, Flow::Jump(_)) {
            leaders.insert(insn.next);
        }
    }

    let mut seen = BTreeSet::new();
    let mut pending = vec![0];
    pending.extend(handlers.iter().filter_map(|&h| usize::try_from(h).ok()));
    let (mut blocks, mut edges, mut exits) = (0_u32, 0_u32, 0_u32);
    while let Some(leader) = pending.pop() {
        if !seen.insert(leader) {
            continue;
        }
        let Some(mut i) = index(leader) else {
            // Falls off the end of the code: an exit.
            continue;
        };
        blocks = blocks.saturating_add(1);
        let successors: Vec<usize> = loop {
            let insn = insns.get(i)?;
            let to = |offset: i64| target(offset).map_or(Vec::new(), |to| vec![to]);
            let out = match insn.flow {
                Flow::Next if leaders.contains(&insn.next) => vec![insn.next],
                Flow::Next if insn.next >= code.len() => Vec::new(),
                Flow::Next => {
                    i += 1;
                    continue;
                }
                Flow::Jump(offset) => to(offset),
                Flow::Branch(offset) => [to(offset), vec![insn.next]].concat(),
                Flow::Switch => insn
                    .cases
                    .iter()
                    .filter_map(|&offset| target(offset))
                    .chain([insn.next])
                    .collect(),
                Flow::Exit => Vec::new(),
            };
            break out;
        };
        let successors: Vec<usize> = successors
            .into_iter()
            .filter(|&to| to < code.len())
            .collect();
        edges = edges.saturating_add(u32::try_from(successors.len()).unwrap_or(u32::MAX));
        if successors.is_empty() {
            exits = exits.saturating_add(1);
        }
        pending.extend(successors);
    }
    let complexity = (i64::from(edges) - i64::from(blocks) + 2 * i64::from(exits)).max(0);
    Some(Body {
        size: u32::try_from(code.len()).ok()?,
        instructions: u32::try_from(insns.len()).ok()?,
        blocks,
        edges,
        complexity: u32::try_from(complexity).unwrap_or(u32::MAX),
    })
}

/// The code of a method body, and the offsets where its exception handlers
/// and filters begin.
fn split(bytes: &[u8]) -> Option<(&[u8], Vec<u32>)> {
    let first = *bytes.first()?;
    match first & 3 {
        // Tiny: the length is in the header byte; no exception clauses.
        2 => Some((bytes.get(1..1 + usize::from(first >> 2))?, Vec::new())),
        3 => {
            let flags = u16::from_le_bytes([first, *bytes.get(1)?]);
            let header = usize::from(flags >> 12) * 4;
            let size = usize::try_from(u32_at(bytes, 4)?).ok()?;
            if header < 12 {
                return None;
            }
            let end = header.checked_add(size)?;
            let code = bytes.get(header..end)?;
            let more = flags & 0x8 != 0;
            Some((
                code,
                if more {
                    handlers(bytes, end)?
                } else {
                    Vec::new()
                },
            ))
        }
        _ => None,
    }
}

/// The handler and filter starts in the exception-clause sections that
/// follow the code, at the next 4-byte boundary after `end`.
fn handlers(bytes: &[u8], end: usize) -> Option<Vec<u32>> {
    let mut at = end.checked_add(3)? & !3;
    let mut starts = Vec::new();
    loop {
        let kind = *bytes.get(at)?;
        let fat = kind & 0x40 != 0;
        let (size, clause) = if fat {
            (u32_at(bytes, at)? >> 8, 24)
        } else {
            (u32::from(*bytes.get(at + 1)?), 12)
        };
        let size = usize::try_from(size).ok()?;
        let clauses = bytes.get(at + 4..at.checked_add(size)?)?;
        if kind & 0x1 != 0 {
            for clause in clauses.chunks_exact(clause) {
                let field = |offset: usize, wide: usize| {
                    let bytes = clause.get(offset..offset + wide)?;
                    Some(bytes.iter().rev().fold(0, |v, &b| v << 8 | u32::from(b)))
                };
                let (flags, handler, filter) = if fat {
                    (field(0, 4)?, field(12, 4)?, field(20, 4)?)
                } else {
                    (field(0, 2)?, field(5, 2)?, field(8, 4)?)
                };
                starts.push(handler);
                if flags & 0x1 != 0 {
                    starts.push(filter);
                }
            }
        }
        if kind & 0x80 == 0 {
            return Some(starts);
        }
        at = at.checked_add(size.max(4))?.checked_add(3)? & !3;
    }
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

/// Every instruction of `code`, or `None` if any does not decode.
fn decode(code: &[u8]) -> Option<Vec<Insn>> {
    let mut insns = Vec::new();
    let mut at = 0;
    while at < code.len() {
        let (op, start) = match *code.get(at)? {
            0xfe => (0xfe00 | u16::from(*code.get(at + 1)?), at + 2),
            op => (u16::from(op), at + 1),
        };
        let operand = |wide: usize| code.get(start..start.checked_add(wide)?);
        let short = || Some(i64::from(i8::from_le_bytes(operand(1)?.try_into().ok()?)));
        let long = || Some(i64::from(i32::from_le_bytes(operand(4)?.try_into().ok()?)));
        let mut cases = Vec::new();
        let (wide, flow) = match op {
            0x2b | 0xde => (1, Flow::Jump(short()?)),
            0x38 | 0xdd => (4, Flow::Jump(long()?)),
            0x2c..=0x37 => (1, Flow::Branch(short()?)),
            0x39..=0x44 => (4, Flow::Branch(long()?)),
            0x45 => {
                let n = usize::try_from(u32_at(code, start)?).ok()?;
                let table = operand(n.checked_mul(4)?.checked_add(4)?)?;
                let next = i64::try_from(start + table.len()).ok()?;
                for case in table.get(4..)?.chunks_exact(4) {
                    let offset = i32::from_le_bytes(case.try_into().ok()?);
                    cases.push(next + i64::from(offset));
                }
                (table.len(), Flow::Switch)
            }
            0x27 => (4, Flow::Exit),
            0x2a | 0x7a | 0xdc | 0xfe11 | 0xfe1a => (0, Flow::Exit),
            _ => (operand_width(op)?, Flow::Next),
        };
        operand(wide)?;
        let next = start + wide;
        // Branch offsets count from the next instruction.
        let flow = match flow {
            Flow::Jump(offset) => Flow::Jump(i64::try_from(next).ok()? + offset),
            Flow::Branch(offset) => Flow::Branch(i64::try_from(next).ok()? + offset),
            flow => flow,
        };
        insns.push(Insn {
            at,
            next,
            flow,
            cases,
        });
        at = next;
    }
    Some(insns)
}

/// Operand bytes of an instruction that does not transfer control, or
/// `None` for an opcode ECMA-335 does not define.
fn operand_width(op: u16) -> Option<usize> {
    Some(match op {
        0x00..=0x0d | 0x14..=0x1e | 0x25 | 0x26 | 0x46..=0x6e | 0x76 | 0x82..=0x8b | 0x8e => 0,
        0x90..=0xa2 | 0xb3..=0xba | 0xc3 | 0xd1..=0xdb | 0xdf | 0xe0 => 0,
        0x0e..=0x13 | 0x1f => 1,
        0x20 | 0x22 | 0x28 | 0x29 | 0x6f..=0x75 | 0x79 | 0x7b..=0x81 | 0x8c | 0x8d | 0x8f => 4,
        0xa3..=0xa5 | 0xc2 | 0xc6 | 0xd0 => 4,
        0x21 | 0x23 => 8,
        0xfe00..=0xfe05 | 0xfe0f | 0xfe13 | 0xfe14 | 0xfe17 | 0xfe18 | 0xfe1d | 0xfe1e => 0,
        0xfe12 | 0xfe19 => 1,
        0xfe09..=0xfe0e => 2,
        0xfe06 | 0xfe07 | 0xfe15 | 0xfe16 | 0xfe1c => 4,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tiny-format body around `code`.
    fn tiny(code: &[u8]) -> Vec<u8> {
        let mut bytes = vec![u8::try_from(code.len() << 2 | 2).unwrap_or(0)];
        bytes.extend_from_slice(code);
        bytes
    }

    fn measure(bytes: &[u8]) -> (u32, u32, u32) {
        body(bytes).map_or((0, 0, 0), |b| (b.blocks, b.edges, b.complexity))
    }

    #[test]
    fn straight_line() {
        // ldarg.0; ret
        assert_eq!(measure(&tiny(&[0x02, 0x2a])), (1, 0, 1));
    }

    #[test]
    fn if_else() {
        // ldarg.0; brfalse.s +2; ldc.i4.1; ret; ldc.i4.0; ret
        let code = [0x02, 0x2c, 0x02, 0x17, 0x2a, 0x16, 0x2a];
        // Three blocks, two edges, two exits.
        assert_eq!(measure(&tiny(&code)), (3, 2, 3));
    }

    #[test]
    fn loop_back() {
        // 0: ldarg.0; 1: brtrue.s -3 (to 0); 3: ret
        let code = [0x02, 0x2d, 0xfd, 0x2a];
        assert_eq!(measure(&tiny(&code)), (2, 2, 2));
    }

    #[test]
    fn switch_counts_cases_and_fall_through() {
        // ldarg.0; switch (2) +1 +2; ret; ret; ret
        let mut code = vec![0x02, 0x45, 2, 0, 0, 0];
        code.extend_from_slice(&1_i32.to_le_bytes());
        code.extend_from_slice(&2_i32.to_le_bytes());
        code.extend_from_slice(&[0x2a, 0x2a, 0x2a]);
        // Blocks: the switch, then one `ret` each; three edges, three exits.
        assert_eq!(measure(&tiny(&code)), (4, 3, 5));
    }

    #[test]
    fn handlers_are_entered() {
        // 0: nop; 1: leave.s +3   (try)
        // 3: pop; 4: leave.s 0    (catch, entered by the runtime)
        // 6: ret
        // in a fat header with one small exception clause.
        let code = [0x00, 0xde, 0x03, 0x26, 0xde, 0x00, 0x2a];
        let mut bytes = vec![0x0b, 0x30, 8, 0];
        bytes.extend_from_slice(&u32::try_from(code.len()).unwrap_or(0).to_le_bytes());
        bytes.extend_from_slice(&[0; 4]);
        bytes.extend_from_slice(&code);
        bytes.push(0); // pad to 4
        // Small EH section: kind, size, reserved; one clause.
        bytes.extend_from_slice(&[0x01, 16, 0, 0]);
        bytes.extend_from_slice(&[0, 0, 0, 0, 3, 3, 0, 3]);
        bytes.extend_from_slice(&0x0100_0001_u32.to_le_bytes());
        // Three blocks, both leaves reaching the one exit.
        assert_eq!(measure(&bytes), (3, 2, 1));
    }

    #[test]
    fn rejects_malformed() {
        assert_eq!(body(&[]), None);
        // Undefined opcode 0x24.
        assert_eq!(body(&tiny(&[0x24])), None);
        // Branch into the middle of an instruction.
        assert_eq!(body(&tiny(&[0x2b, 0xff, 0x2a])), None);
        // Truncated operand.
        assert_eq!(body(&tiny(&[0x20, 0x01])), None);
        // A switch claiming more cases than there are bytes.
        assert_eq!(body(&tiny(&[0x45, 0xff, 0xff, 0xff, 0x7f])), None);
    }
}
