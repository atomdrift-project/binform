# testdata

Real binaries for the fixture tests in `src/tests/fixtures.rs`. Many are
malware. Each is stored zstd-compressed (`NAME.zst`) and is only ever
parsed: treat every file here as hostile, and never decompress one to run
it.

For each fixture `NAME`:

- `NAME.zst`: the binary, compressed.
- `NAME.md`: where it came from (source, SHA-256, size, license), the
  idioms it exercises, and what its test claims.
- `NAME.golden`: binform's output, one line per function (entry, size,
  blocks, edges, complexity, jump-table cases, how it was found), with the
  reference's blocks and complexity beside each shared function, a summary
  of the agreement at the top, and a line for every function only the
  reference found, saying why binform has none there.
- `NAME.rizin.json.zst`: a frozen listing of the functions rizin 0.8.2
  found (entry, name, size, blocks, complexity, and the analysis commands
  used). The tests read it as an independent oracle; rizin is never run by
  the tests.

`chained-fixups-ios-arm64.zst` is a layout fixture only, read by a test in
`src/layout/`; it has neither golden nor reference listing.

## Blessing

The tests fail when binform's output differs from a golden, and print the
changed lines. When the change is an improvement, accept it:

    BINFORM_BLESS=1 cargo test fixtures

Then read the golden diff before committing it. Blessing rewrites only the
goldens: each fixture's claims (assertions in `src/tests/fixtures.rs`) still
have to hold.

## Adding a fixture

1. Compress the binary into this directory: `zstd -19 NAME -o
   testdata/NAME.zst`.
2. Write the reference listing. With rizin 0.8.2 on `PATH` (or named by
   `--rizin`), run:

       cargo run --release -p binform-tools --bin binform-ab -- --save testdata testdata/NAME.zst

   `binform-ab` decompresses the file to a temporary file for rizin and
   writes `testdata/NAME.rizin.json.zst`. The analysis commands are
   chosen per file unless `--script` gives them, and are recorded in the
   listing.
3. Write `NAME.md` in the form of the others: what the binary is and what
   it tests, then source, SHA-256, size and license, and, for malware, a
   line saying so.
4. Add a `#[test]` to `src/tests/fixtures.rs` that calls
   `check("NAME", |outcome| ...)` with the claims the fixture is there for,
   for example `finds_every_reference_function`.
5. Create the golden with `BINFORM_BLESS=1 cargo test fixtures`, and check
   it.
