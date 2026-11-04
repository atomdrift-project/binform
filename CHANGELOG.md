# Changelog

All notable changes to binform are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions
follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

The first public release.

### API

- `parse(&[u8]) -> Result<Binary, Error>` reads ELF, PE and Mach-O (thin
  or universal) headers. `Binary`'s layout is read through accessors:
  `format()`, `arch()`, `entry()`, `sections()`, `imports()`, `exports()`,
  `section_at`, `offset`, `import(slot)`, `syscall` and `syscall_number`.
- `recover(&Binary, &Limits) -> Recovery` recovers functions, blocks,
  complexity and references. A reference's `Dest` is code, or a memory
  slot and the import the loader writes there. `Ref::new` builds one
  outside the crate, as tests of a consumer need.
- `calls(&Binary, &Recovery) -> Vec<Call>` reads each call and syscall
  site's arguments on x86, x86-64, Arm and A64, resolving calls through
  import slots and stubs to `Target::Import`. An unknown syscall number is
  `Target::Syscall(None)`.
- `Error` is an enum: `Truncated`, `BadMagic`, `Unsupported`,
  `NotExecutable`.
- Public enums and output structs are `#[non_exhaustive]`.
- `Export::addr` is `None` for a Mach-O re-export.
- Per-function diagnostics (how each entry was found, stub slots, edges)
  are behind the `diagnostics` feature, outside the stable API.

### Reliability

- Every count a header claims is cut to the bytes that hold it and to a
  named bound in `layout::limits`. Relocation tables, copies of patched
  object sections, Mach-O load commands and sections, PE import and export
  tables, Go function tables, unwind records and exception tables each
  share one budget per file, so a file costs work in proportion to its
  size.
- No arithmetic in the library overflows (`clippy::arithmetic_side_effects`
  is enforced); a jump table that names its own jump no longer panics.
- Fuzz targets for `parse` and for `recover` with `calls`, run in CI.

### Recovery

- Decoding a stub no longer resets the state of the walk under way.
- Arm64 call tracking reads loads, pairs, the zero register and negative
  `adrp` correctly; Arm and Thumb tracking decodes register lists,
  literal loads and conditional execution; x86 tracks `push`/`pop`.
- LSDAs are read in the file's byte order.
- Xtensa's wide `nop`, SPARC's `jmp %rN + imm` and SuperH's delay-slot notes
  are read correctly.
