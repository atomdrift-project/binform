//! What binform's own tools (`binform`, `binform-ab`) print beside the
//! functions: how each was found, the import a stub jumps to, its edges.
//! No consumer reads these, so they are not part of the API and change
//! without notice.

use crate::functions::Detail;
use crate::{Binary, Functions, Limits, Origin};

/// One function's diagnostics, in [`Functions::functions`] order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Diagnostic {
    /// Control-flow edges between the function's blocks.
    pub edges: u32,
    /// For a stub that only jumps through an import slot, the slot.
    pub thunk: Option<u64>,
    /// The ways the entry was found (`"symbol"`, `"call"`, `"sweep"`, ...).
    pub found: Vec<&'static str>,
    /// Whether the function has landing pads, which rizin does not walk.
    pub padded: bool,
}

/// [`crate::functions`](fn@crate::functions), with each function's diagnostics.
#[must_use]
pub fn functions(bin: &Binary<'_>, limits: &Limits) -> (Functions, Vec<Diagnostic>) {
    let (functions, details) = crate::functions::recover(bin, limits);
    let diagnostics = functions
        .functions
        .iter()
        .zip(details)
        .map(
            |(
                f,
                Detail {
                    edges,
                    thunk,
                    found,
                },
            )| Diagnostic {
                edges,
                thunk,
                found: found.names().collect(),
                padded: bin.handlers.iter().any(|h| h.function == f.entry),
            },
        )
        .collect();
    (functions, diagnostics)
}

/// Whether `addr` lies in an executable segment.
#[must_use]
pub fn is_code(bin: &Binary<'_>, addr: u64) -> bool {
    bin.segments.iter().any(|segment| {
        segment.executable
            && addr
                .checked_sub(segment.addr)
                .is_some_and(|offset| offset < segment.bytes.len() as u64)
    })
}

/// Whether the binary names functions: some start came from a symbol, an
/// export or function starts, not only the entry point and loader tables.
#[must_use]
pub fn named(bin: &Binary<'_>) -> bool {
    bin.seeds.iter().any(|seed| {
        !matches!(
            seed.origin,
            Origin::Entry | Origin::Init(_) | Origin::Fini(_) | Origin::Tls(_)
        )
    })
}
