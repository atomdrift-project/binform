//! Tests that need recovery's diagnostics: how each function was found, the
//! import a stub jumps to, its edge count. [`recover`] joins each
//! [`Function`](crate::Function) with them.

mod fixtures;
mod synthetic;

use crate::functions::Detail;
use crate::{Binary, Dest, Found, Limits, Ref};

/// A function with its diagnostics.
#[derive(Clone, Debug)]
pub(crate) struct Recovered {
    pub(crate) entry: u64,
    pub(crate) name: Option<String>,
    pub(crate) size: u64,
    pub(crate) blocks: u32,
    pub(crate) complexity: u32,
    pub(crate) refs: Vec<Ref>,
    pub(crate) edges: u32,
    pub(crate) thunk: Option<u64>,
    pub(crate) found: Found,
}

pub(crate) struct Recovery {
    pub(crate) functions: Vec<Recovered>,
    pub(crate) code: u64,
    pub(crate) covered: u64,
    pub(crate) invalid: u64,
    pub(crate) unresolved: u64,
    pub(crate) truncated: bool,
}

impl Recovery {
    pub(crate) fn function(&self, addr: u64) -> Option<&Recovered> {
        self.functions.iter().find(|f| f.entry == addr)
    }

    pub(crate) fn target_name<'a>(&'a self, bin: &'a Binary<'_>, to: Dest) -> Option<&'a str> {
        match to {
            Dest::Code(addr) => self.function(addr)?.name.as_deref(),
            Dest::Slot { addr, .. } => Some(bin.import(addr)?.1.name.as_str()),
        }
    }
}

pub(crate) fn recover(bin: &Binary<'_>) -> Recovery {
    let (all, details) = crate::functions::recover(bin, &Limits::DEFAULT);
    let functions = all
        .functions
        .into_iter()
        .zip(details)
        .map(
            |(
                f,
                Detail {
                    edges,
                    thunk,
                    found,
                },
            )| Recovered {
                entry: f.entry,
                name: f.name,
                size: f.size,
                blocks: f.blocks,
                complexity: f.complexity,
                refs: f.refs,
                edges,
                thunk,
                found,
            },
        )
        .collect();
    Recovery {
        functions,
        code: all.code,
        covered: all.covered,
        invalid: all.invalid,
        unresolved: all.unresolved,
        truncated: all.truncated,
    }
}
