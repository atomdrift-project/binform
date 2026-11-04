# Design

binform recovers functions, basic blocks, complexity, references and call
sites from ELF, PE and Mach-O machine code, and reads the layout tables
(sections, imports, exports) that recovery needs. It reports what code
mechanically does, per instruction set; what that means is for the caller to
decide.

## Rules

- **Pure functions.** `parse`, `recover` and `calls` take bytes or what
  an earlier call returned, and return data. No I/O, no threads, no
  subprocesses, no temporary files, no global state.
- **Input is hostile.** Library code does not panic, index unchecked or
  overflow (`unsafe` is forbidden, and the clippy lints in `Cargo.toml`
  enforce the rest). Every read is bounded by the file. Every table walk is
  bounded by a named budget in `src/layout/limits.rs`, and yields what it
  read before the budget ran out. Recovery is bounded by `Limits`, and
  `Recovery::truncated` says when they cut it short.
- **Partial results over errors.** A damaged table is read as far as it
  goes. `Error` is for a file with nothing to return. A file of an
  instruction set binform does not decode parses to its layout, with
  `arch()` `None`, and `recover` returns nothing for it.
- **The caller pays for what it calls.** No lazy fields, no `OnceLock`, no
  option builders. A caller that wants the layout calls `parse` and stops.
  `parse` reads tables, including those that seed recovery (`.eh_frame`,
  Go's function table), but never decodes an instruction; decoding, PLT
  stubs included, is `recover`'s.
- **Data, not objects.** Output types have public fields and derive
  `Clone`, `Debug` and `PartialEq` (and `Default` where it means something);
  they are `#[non_exhaustive]`, so a field can be added without a major
  version. `Binary` is the exception: what recovery reads from it must stay
  consistent, so callers read it through accessors. Methods are lookups by
  address or name.
- **Caching and parallelism are the caller's.** `binform::VERSION` is there
  to key a cache on; a caller scanning many files parallelises over files.
- **A `match`, not a registry.** A new instruction set or format is one
  file under `src/isa/` (or `src/layout/`) and arms in the `match`es the
  compiler checks for exhaustiveness.
- **An instruction set needs a sample.** A decoder is added when a real
  binary of that set is in hand to test it on, not before.

## API

The public surface is in `src/lib.rs` and nothing else is public, except
`binform::diagnostics`, behind the `diagnostics` feature: per-function
detail for inspecting recovery (the tools in `tools/` use it), not part of
the stable API.

- `parse(&[u8]) -> Result<Binary, Error>`: format, `arch`, entry point,
  sections, imports, exports. `Binary` borrows the input.
- `recover(&Binary, &Limits) -> Recovery`: functions in entry order,
  each with entry, name, size, blocks, complexity and references (call,
  jump, branch, case, each to a `Dest`: code, or a memory slot and the
  import it holds); and the totals of code bytes, bytes covered, invalid
  instructions and unresolved jumps.
- `calls(&Binary, &Recovery) -> Vec<Call>`: every call and syscall site in
  the recovered functions, with its arguments' values where they are known:
  a constant, or a pointer and the bytes behind it.
- `Limits::DEFAULT` is a bound no real binary reaches; `Limits::QUICK` is a
  64th of its instruction budget, for callers that prefer `truncated` to
  latency.

An unnamed function has `name: None`; spelling it (`fcn.<addr>`, say) is the
caller's choice.

## Layout

- Sections are the section headers' and report their values unaltered: a
  PE section's sizes unrounded, a nameless one nameless, the flag word as
  the header holds it. ELF sections are not synthesised from program
  headers.
- PE imports are every address-table entry, duplicates included, with
  delay-load entries marked `delayed`. `Import::ordinal` is the real PE
  ordinal; an import by ordinal only is named `Ordinal_n`, and binform ships
  no ordinal-to-name database.
- Mach-O imports are one per symbol. The library comes from the two-level
  ordinal, else from dyld's bind opcodes or the chained-fixup import
  table.
- ELF exports are the defined `GLOBAL`, `WEAK` and `GNU_UNIQUE` symbols of
  the dynamic table, and of a relocatable object's static table; a static
  executable's `.symtab` is no export table. PE exports are the export
  directory, forwarders and ordinal-only exports included, COFF symbols not.
  Mach-O exports are the external, non-private symbols merged with the
  export trie, whose re-exports forward to `stem.symbol`.
- A relocatable ELF object's sections are placed at addresses of binform's
  choosing (as a reference disassembler places them) and its relocations
  applied, so calls reach their callees.
- A universal Mach-O file is read as one slice: x86-64, else A64, else the
  first slice of an instruction set binform decodes. The choice does not
  depend on the host.

## Efficiency

The fast path is the absence of work.

- `parse`: one walk of the headers and tables; tens of microseconds to a few
  milliseconds.
- `recover`: one linear sweep per code segment, one decode per
  instruction, bounded by `Limits`.
- `calls`: a second pass over the instructions of the recovered functions,
  not a second sweep, with one small register and stack model per function
  that resets at every join and barrier, so a value is reported only where
  it holds. It is empty for an instruction set with no value tracker.
- Memory: no copy of the input; the only owned data are names and the
  recovered tables. No `String` is built for a function without a name.

## Out of scope

Strings, CIL (.NET) method graphs, emulation, unpacking or decoding of
obfuscated data, and disassembly text.
