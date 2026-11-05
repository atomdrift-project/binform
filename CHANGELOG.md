# Changelog

Notable changes to binform. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions
follow [Semantic Versioning](https://semver.org/).

## [0.9.1] - 2026-11-05

### Security

- A file could make two imports claim one slot, passing `connect` off as something harmless; such slots now name nothing.
- A syscall number with junk in its high 32 bits no longer hides its name on x86-64 and arm64 Linux.
- Overlapping segments, endless LEB128 runs and export tries with shared nodes no longer cost quadratic time.
- Names repeated across relocations, version records and re-exports now count against the name budget, so copies stay bounded.
- Repeated Mach-O symbol table commands and shared `.eh_frame` CIEs are now parsed once, not once per mention.
- Each jump table case now costs one instruction of budget, so a shared table cannot multiply recovery work.
- Relocating an object copies at most twice the file's size in section bytes, whatever its headers claim.
- The `binform-ab` tool no longer writes through a planted temporary-file link, and it refuses zstd bombs.

### Fixes

- The `calls` walk no longer carries register values from another function's code; it starts afresh at that function's entry.
- Data inside a function's address span is no longer decoded as instructions, so it yields no phantom call sites.

### Optimizations

- x86 decoding reuses one `iced-x86` decoder across instructions instead of building a new one for each.
- Function recovery keeps a compact record per instruction, a twelfth the size, and walks blocks without repeated searches.
- Conditional Arm instructions now cost as much as unconditional ones, however full the stack frame.
- The `calls` walk visits join points in order and keeps one record per site, without a final sort.

## [0.9.0] - 2026-11-04

The first public release.

- `parse(&[u8]) -> Result<Binary, Error>` reads ELF, PE and Mach-O headers,
  thin or universal, into a `Binary`: format, instruction set, entry point,
  sections, imports and exports, read through accessors.
- `recover(&Binary, &Limits) -> Recovery` recovers functions, basic blocks,
  complexity and references. A reference's `Dest` is code, or a memory slot
  and the import the loader writes there.
- `calls(&Binary, &Recovery) -> Vec<Call>` reads the arguments of each call
  and syscall site on x86, x86-64, Arm and A64, and resolves calls through
  import slots and stubs to `Target::Import`.
- Public enums and output structs are `#[non_exhaustive]`. `Arch` and
  `Format` display as toolchains name them (`x86-64`, `ppc64le`, `Mach-O`).
- Per-function diagnostics are behind the `diagnostics` feature, outside
  the stable API.
- Every count a header claims is cut to the bytes that hold it and to a
  budget, so a file costs work in proportion to its size. The library has
  no `unsafe` and no overflowing arithmetic, and CI fuzzes `parse` and
  `recover`.
