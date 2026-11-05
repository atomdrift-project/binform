//! The bounds on what a file's headers can make the readers do. A count,
//! size or chain in a header is the file's word, not the truth: each is cut
//! to the most a real binary needs, so a hostile file costs time and memory
//! in proportion to its size, never to what it claims.

/// Entries read from any one table: symbols, sections, program headers,
/// relocations, dynamic entries, exception data, version records.
pub(super) const TABLE: u64 = 1 << 20;

/// Relocation entries read from all of an object's tables together.
/// Section headers may point many tables at the same bytes.
pub(super) const RELOCATIONS: usize = 1 << 21;

/// Bytes of an object's sections copied so relocations can be applied to
/// them. Overlapping section headers may claim the file many times over.
pub(super) const LINKED_BYTES: usize = 1 << 28;

/// Mach-O load commands walked.
pub(super) const LOAD_COMMANDS: u64 = 1 << 16;

/// Mach-O sections read across all segment commands.
pub(super) const SECTIONS: usize = 1 << 16;

/// Descriptors read from a PE import or delay-load import table.
pub(super) const DESCRIPTORS: u64 = 1 << 12;

/// Entries read from one PE import descriptor's lookup table.
pub(super) const THUNKS: u64 = 1 << 16;

/// PE import lookup-table entries read across both import tables.
/// Descriptors may share one lookup table, so a few kilobytes can claim
/// billions; real binaries import thousands at most.
pub(super) const IMPORTS: usize = 1 << 18;

/// Name bytes copied out of each of a file's symbol, import, export, bind
/// and Go function tables. Every entry may name the same long string; real
/// tables hold well under a megabyte of names.
pub(super) const NAME_BYTES: usize = 32 << 20;

/// The longest LEB128 number read, in bytes: ten hold 64 bits, and
/// encoders pad one to a few more at most.
pub(super) const LEB128: usize = 32;

/// The longest name read: symbol, section, library or function.
pub(super) const NAME_LEN: usize = 1 << 12;

/// PE TLS callbacks read.
pub(super) const TLS_CALLBACKS: u64 = 1 << 12;

/// Links followed in a chain of x64 unwind data.
pub(super) const UNWIND_CHAIN: usize = 32;

/// Nodes visited in a Mach-O export trie.
pub(super) const TRIE_NODES: usize = 1 << 20;

/// Stubs read from one PLT, or from all of a Mach-O file's stub sections.
pub(super) const STUBS: usize = 1 << 16;

/// Entries read from one initializer or finalizer array.
pub(super) const INITIALIZERS: usize = 1 << 16;

/// Functions read from a Go function table.
pub(super) const GO_FUNCTIONS: usize = 1 << 21;

/// Candidate Go function table headers tried in a PE file's data, which has
/// no section that names the table.
pub(super) const GO_HEADERS: usize = 1 << 12;

/// Landing pads read from one LSDA.
pub(super) const PADS: usize = 1 << 14;

/// Call-site records read across all of a file's LSDAs.
pub(super) const CALL_SITES: usize = 1 << 22;

/// Landing pads kept across all of a file's functions.
pub(super) const HANDLERS: usize = 1 << 20;
