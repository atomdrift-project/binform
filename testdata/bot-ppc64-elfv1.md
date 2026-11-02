# bot-ppc64-elfv1

A dynamically linked 64-bit big-endian PowerPC executable (the ELFv1 ABI).

The entry point and the function symbols name descriptors in `.opd` (code address, TOC pointer, environment), not code; each descriptor stands for a function. Imports are called through PLT stubs funktion does not read yet (`ld r12, n(r2); mtctr r12; bctr`).

- Source: `ppc64/bad-04742415150d557d7337b7f614d75b04dd712d2480f88073bde187e5815744dd` from a malware corpus (an `exotic_binaries` collection)
- SHA-256: `04742415150d557d7337b7f614d75b04dd712d2480f88073bde187e5815744dd`
- Size: 75496 bytes (8345 compressed)
- **Malware:** this file is hostile. It is kept compressed and only ever parsed; never run it.

`bot-ppc64-elfv1.rizin.json.zst` holds what rizin 0.8.2 found (`funktion-ab --save`);
`bot-ppc64-elfv1.golden` holds what funktion finds (`FUNKTION_BLESS=1 cargo test --test fixtures`).
