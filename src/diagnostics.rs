//! What recovery knows about each function beyond [`Function`]: how it was
//! found, the import a stub jumps to, its edges. For inspecting recovery
//! (binform's own tools print these); behind the `diagnostics` feature, and
//! outside the stable API: they change without a major version.
//!
//! [`Function`]: crate::Function

use crate::functions::Detail;
use crate::{Binary, Limits, Origin, Recovery};

/// One function's diagnostics, in [`Recovery::functions`] order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Diagnostic {
    /// Control-flow edges between the function's blocks.
    pub edges: u32,
    /// For a stub that only jumps through an import slot, the slot.
    pub thunk: Option<u64>,
    /// The ways the entry was found (`"SYMBOL"`, `"CALL"`, `"SWEEP"`, ...).
    pub found: Vec<&'static str>,
    /// Whether the function has landing pads (exception handlers), which
    /// its blocks include.
    pub padded: bool,
}

/// [`crate::recover`], with each function's diagnostics.
#[must_use]
pub fn recover(bin: &Binary<'_>, limits: &Limits) -> (Recovery, Vec<Diagnostic>) {
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
    bin.is_code(addr)
}

/// Whether the binary names functions: some start came from a symbol, an
/// export or function starts, not only the entry point and loader tables.
#[must_use]
pub fn named(bin: &Binary<'_>) -> bool {
    bin.seeds
        .iter()
        .any(|seed| !matches!(seed.origin, Origin::Entry | Origin::Loader))
}
