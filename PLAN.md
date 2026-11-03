# binform

funktion becomes binform: a library that answers, in-process and in
milliseconds, the questions filefacts and stng shell out to rizin for. It
does only what rizin does for those two tools, and nothing rizin does not.

## The hard edge

If rizin does not provide it as a feature, binform does not either. The
features are what the two consumers read today:

| rizin                                  | reads                                                         | binform             |
|----------------------------------------|---------------------------------------------------------------|---------------------|
| `aa; aac; aap` / `aalg` / `aaa`, `aflj` | name, offset, size, cc, nbbs, callrefs (from, to, type, name) | `functions`         |
| `iSj`                                  | name, vaddr, vsize, paddr, size, perm                         | `parse`             |
| `iij`                                  | name, libname, ordinal, plt                                   | `parse`             |
| `iEj`                                  | name, vaddr                                                   | `parse`             |
| `/at xor; /at lea`, `aoj 1 @ addr`     | instruction addresses, a `lea`'s pointer                      | `search`            |
| `s entry0; pdf`                        | text, scanned for `connect` and `sockaddr_in` stores          | `search`            |
| `izzj`, `isj`                          | strings, symbol names                                         | dropped (see below) |

Rizin's string search (`librz/bin/bfile_string.c`, `librz/util/str_search.c`)
is a context-free byte scan with encoding guesses. It knows nothing about
how a string is used. Over stng's own testdata, everything it added to
stng's output was a respelling (`imp.` prefixes, `func.<addr>` names, Go
names with their length byte) or noise. stng's extractor is already the
better `izz`; binform has no strings module.

## Principles

- **Three functions, three structs.** `parse`, `functions`, `search`.
  Each is a pure function: bytes in, data out. No I/O, no threads, no
  global state, no panics; work bounded by `Limits` because input is
  hostile.
- **The caller pays for what it calls.** That is the whole "how much
  work" story. No lazy fields, no `OnceLock`, no builder of options. A
  consumer wanting only the layout calls `parse` and stops.
- **Data, not objects.** Public fields, `Default`, `Clone`, `Debug`,
  `PartialEq`. Methods are lookups by address, nothing more. Only the
  fields the table above shows a consumer reading.
- **Rizin's rules for layout.** Partial results over errors: sections
  synthesised from segments when headers are stripped, a damaged table
  read as far as it goes. `Error` is for when there is nothing to return.
- **Caching and parallelism are the caller's.** filefacts keys its disk
  cache on `binform::VERSION`; scan parallelises over files.
- **A `match`, not a registry.** A new instruction set or format is one
  file and two `match` arms the compiler checks for exhaustiveness.
- **Efficiency by not doing things.** The fast path is the absence of
  work: one header walk, one sweep per code segment, one decode per
  instruction, no copies of the input (`Binary` borrows `bytes`), no
  strings built unless a name exists.

## API

```rust
pub const VERSION: &str;                                          // for cache keys

pub fn parse(bytes: &[u8]) -> Result<Binary<'_>, Error>;
pub fn functions(bin: &Binary<'_>, limits: &Limits) -> Functions;
pub fn search(bin: &Binary<'_>, fns: &Functions) -> Hits;

pub struct Binary<'a> {
    pub format: Format,              // Elf, Pe, MachO
    pub arch: Option<Arch>,          // None: an ISA binform does not decode; layout only
    pub entry: Option<u64>,
    pub sections: Vec<Section>,
    pub imports: Vec<Import>,        // one per symbol
    pub exports: Vec<Export>,
    // private: segments, seeds, slots, extents, handlers, got, rebased —
    // what `functions` needs and no consumer reads.
}
pub struct Section { pub name: String, pub addr: u64, pub size: u64,
                     pub offset: u64, pub file_size: u64,
                     pub readable: bool, pub writable: bool, pub executable: bool }
pub struct Import  { pub name: String, pub library: Option<String>,
                     pub ordinal: Option<u16>, pub slot: Option<u64> }
pub struct Export  { pub name: String, pub addr: u64, pub forward: Option<String> }

pub struct Functions {
    pub functions: Vec<Function>,    // entry order
    pub code: u64, pub covered: u64, pub invalid: u64, pub unresolved: u64,
    pub truncated: bool,
}
pub struct Function { pub entry: u64, pub name: Option<String>, pub size: u64,
                      pub blocks: u32, pub complexity: u32, pub refs: Vec<Ref> }
pub struct Ref { pub from: u64, pub to: u64, pub kind: RefKind }   // Call, Jump, Branch, Case

pub struct Hits { pub xor: Vec<u64>, pub lea: Vec<(u64, u64)>,     // (insn, pointer)
                  pub connect: Vec<Sockaddr> }
pub struct Sockaddr { pub ip: [u8; 4], pub port: u16, pub at: u64 }

pub struct Limits { pub functions: usize, pub instructions: usize, pub table_entries: usize }
impl Limits { pub const DEFAULT: Self; pub const QUICK: Self; }

impl Section      { pub fn mapped(&self) -> bool; }
impl Binary<'_>   { pub fn import(&self, slot: u64) -> Option<&str>;
                    pub fn section_at(&self, addr: u64) -> Option<&Section>;
                    pub fn offset(&self, addr: u64) -> Option<u64>; }   // vaddr → file
impl Functions    { pub fn function(&self, entry: u64) -> Option<&Function>;
                    pub fn name(&self, bin: &Binary, to: u64) -> Option<&str>; }
```

Removed from today's funktion: the public hand-fillable `Image` (no
caller fills one), `Found`, `Function::thunk` and `edges` (no consumer
reads them; `thunk` folds into `name`), `recover`/`recover_with`
(renamed), and `cil` (rizin builds no CIL graphs; it moves to filefacts
beside `pe/clr`).

## Tree

```
binform/
  Cargo.toml            no features: parse is the library
  PLAN.md  README.md  TODO.md
  src/lib.rs            the API above; nothing else public
  src/diagnostics.rs    #[doc(hidden)]: found/thunk/edges/pads for the two tools only
  src/layout/           parse
    mod.rs              format sniff → elf | pe | macho; rizin's lenient rules; Error
    elf.rs  pe.rs  macho.rs
    relocate.rs         ELF .o linking
    eh.rs               .eh_frame / .pdata extents and landing pads
    gopclntab.rs        Go function table
    read.rs             bounded integer reads
  src/functions/        functions
    mod.rs              seeds from Binary, sweep, queue, walk, Functions assembly
    table.rs            jump tables
  src/isa/              one decoder per instruction set, used by functions and search
    mod.rs              Insn, Flow, Note, Mem: the per-ISA contract; Arch → decoder `match`
    x86.rs arm.rs arm64.rs mips.rs ppc.rs riscv.rs loongarch.rs s390x.rs sparc.rs
    superh.rs m68k.rs openrisc.rs microblaze.rs arc.rs csky.rs xtensa.rs
  src/search.rs         xor / lea / connect over recovered functions
  tools/
    binform             `binform [parse|functions|search] FILE...` → JSON, one object per file
    binform-ab          each verb against rizin's command over a corpus; `--save` fixtures
  testdata/             real binaries (compressed) + golden JSON per verb; hostile ones parse-only
  src/tests/            unit-level: fixtures.rs (golden diff, `BINFORM_BLESS=1` to accept),
                        synthetic.rs (hand-assembled idioms); they read crate-private seeds
```

## Consumers

```
filefacts::open(bytes)
  goblin                         native facts, unchanged
  binform::parse                 every executable; replaces iSj/iij/iEj when goblin found none
  binform::functions             when the admission policy says so; metrics, Function and Call symbols
  binform::search                when stng will run; → stng::ExternalHints { xor_key_offsets, connect_addrs }
  stng::extract_strings_from_object(object, bytes, opts.with_hints(hints))
```

- filefacts → binform, filefacts → stng, stng CLI → binform. stng's library
  keeps `ExternalHints` as its seam and never depends on binform. The stng
  CLI repeats filefacts' dozen lines of glue rather than depending on it.
- filefacts' `functions.rs` already holds the one concrete shape all
  downstream code reads; it becomes a thin adapter over `binform::Functions`.
- rizin leaves filefacts entirely (`rizin.rs`, `rizin/process.rs`,
  `rizin/recovery.rs`, ~2300 lines plus 2000 of tests, the process-group
  and timeout machinery, `--no-rizin`, `FILEFACTS_RIZIN_*`). The disk cache
  key swaps `rizin=<version>|policy=…` for `binform=<VERSION>`.
- stng CLI deletes `cli/rizin.rs` and its cache (~1100 lines).

## Steps

Each step ships on its own, with its own test, and leaves every consumer
building.

### 1. Rename

funktion → binform in crate, tool, paths, docs, golden headers. GitHub
repo rename is the owner's. filefacts' `Cargo.toml` points at the new URL.
No behaviour change: `cargo test` before and after identical.

### 2. Restructure

Move files into `layout/`, `functions/`, `isa/`. `parse` replaces
`object::image`; `functions` replaces `recover_with`; the public `Image`
becomes private `Binary` fields. Drop `Found`, `thunk`, `edges` from the
public type; drop `cil` (copy to filefacts first). Test: golden files
byte-identical except the removed fields; `funktion-ab` agreement numbers
unchanged.

### 3. Layout surface

**Done.** `Section`, `Import` (with `library`, `ordinal`), `Export`
(with `forward`), `entry` and `format` on `Binary`, for all three formats.
Decisions taken while building it:

- No `Import::stub`. Rizin's `plt` is a per-architecture guess; binform's
  functions already name each stub after its import, so a caller that
  wants the stub has it in `Functions`.
- `Import::ordinal` is a PE import's real ordinal. Rizin's is a row
  index. Names stay `Ordinal_n`: filefacts already resolves the DLLs whose
  ordinals are stable (`pe/ordinals.rs`), so binform does not ship rizin's
  3 MB ordinal database.
- `arch` is `Option`: a file of an instruction set binform does not decode
  (eBPF, M*Core, Nios II, IA-64, MIPS-FPU and PowerPC PE) parses to its
  layout, and `functions` returns nothing for it. `Error::Arch` is gone.
- ELF sections come from the section headers only. Rizin's `iS` does not
  synthesise them from program headers either (those are `iSS`), and
  filefacts reads rizin's sections on the PE path alone.
- PE sections follow rizin's per-section rules (`sect_N` for no name,
  memory size rounded up to the section alignment, file offset down to
  the file alignment), not its entry-point fix-up, which renames or marks
  sections executable for display (`blob`; IA-64's `.rdata`).
- Exports: ELF's defined `GLOBAL` symbols (weak ones are no exports, as
  rizin says); PE's export directory, forwarders and ordinal-only exports
  included, COFF symbols not (filefacts discarded those from rizin);
  Mach-O's external symbols that are not private, merged with the export
  trie (all a stripped dylib has).

The original notes:


- ELF: sections from headers; from program headers when the table is
  missing, empty, or names no code (packers). Imports from `.dynsym` +
  relocations; `stub` from the PLT walk funktion already does.
- PE: sections from the table as far as it parses; imports from the
  import and delay-import directories (ordinals kept); exports with
  forwarders skipped; `.NET`-only images parse with empty functions.
- Mach-O: sections from segments; imports from binds and lazy binds;
  exports from the export trie; universal files choose one slice (today's
  rule, matched against filefacts' `native_arch_only`).

Test: `binform-ab parse` over `testdata/`, stng's binaries and
`exotic_binaries`, diffing against `iSj`/`iij`/`iEj` name-by-name. Accept
differences only where rizin is wrong and the fixture notes say why.
Then filefacts reads `Binary` instead of rizin's tables; its
`*.recovered_*_count` metrics keep their names.

Result over both corpora (328 files, binform 0.9 s against rizin's 68 s):
every file parses; every remaining difference is one of these, each
rizin's doing: names it sanitises (`/` and control characters, a leading
`__` on ELF section names, doubled escapes in Go names) or demangles;
`.group_0x…` and `blob` sections it invents; ordinals it resolves from its
database; ELF imports it finds none of (relocations it does not read on
ARCv2, m68k, MIPS, PowerPC, SuperH, SPARC, s390x); dynamic symbols it
cannot count without a hash table; COFF symbols it lists as Go PE exports;
object files it lays out at its own addresses; Objective-C metaclass
imports it folds into their class. filefacts now fills empty import,
export and section views from binform (`formats/common.rs::apply_native`),
so a file binform answers no longer loses the tables rizin used to add.

### 4. stng CLI drops strings from rizin

Remove `izzj`/`isj`. Fix the Go source-path blob (NUL-joined paths emitted
as one string) that the comparison exposed. Test: diff the CLI's JSON
over stng's testdata before and after; the only losses are `imp.`/`func.`
respellings and sub-8-byte junk.

### 5. search

Over the functions already recovered (no second sweep): xor instructions,
`lea`-class address builds (`lea`, `adrp; add`, `auipc; addi`, `l32r`,
…) with the pointer they build, and `connect` in the entry function
(`sockaddr_in` stores: port and address immediates). Reuses `isa/`'s
constant tracker; adds one `Note::Xor` per decoder, x86/x86-64/AArch64/Arm
first. Test: `binform-ab search` against `/at xor`, `/at lea`+`aoj` and
the `pdf` parse on stng's XOR and connect samples; stng's golden TSV
unchanged with hints from binform instead of rizin. Then filefacts fills
`ExternalHints`, and stng CLI deletes `cli/rizin.rs`.

### 6. Delete rizin from filefacts

After the step-3 and step-5 A/Bs are accepted. Instruction sets binform
lacks (BPF, M*Core, Nios II, IA-64, …) get a `isa/` file when a sample
turns up, not a fallback; until then such a file has layout and no
functions, as resource-only DLLs do today.

## Efficiency

What is measured, and the budgets that count as regressions:

- **Corpus A/B** (`binform-ab`, both corpora, 328 files): wall time per
  verb; today functions-first already cut filefacts' recovery from 458 s
  to 97 s over that set, with rizin left on 3 files.
- **`parse`**: tens of microseconds to a few milliseconds; never reads
  code. Anything that walks code (`.eh_frame`, Go tables, PLT stubs) is
  computed in `functions`, so a layout-only caller never pays for it.
- **`functions`**: one linear sweep per code segment, one decode per
  instruction, bounded by `Limits`. `Limits::QUICK` is 1/64 of the default
  budget for scanners that prefer `truncated` to latency.
- **`search`**: a second pass over the instructions of recovered
  functions, not a second sweep; nothing allocated for a function with
  no hit.
- **Memory**: `Binary` borrows; the only owned data are names and the
  recovered tables. No `String` for an unnamed function (`fcn.<addr>` is
  the consumer's spelling).
- **No threads, no subprocesses, no temp files**: the gains filefacts sees
  are mostly from not starting rizin.

## Out of scope

Strings (stng), CIL graphs (filefacts), emulation or XOR decoding (stng's
interpreters), disassembly text, anything rizin does that neither
consumer reads. Instruction sets without a sample in hand.
