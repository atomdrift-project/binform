# Changelog

Notable changes to binform. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions
follow [Semantic Versioning](https://semver.org/).

## [0.9.0] - Unreleased

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
