# winnt-ppc.exe

A Windows NT executable for little-endian 32-bit PowerPC (PE machine `0x1f0`), the byte order NT ran PowerPC in.

Decoded by the PowerPC decoder in little-endian mode (`PowerPcEl`). rizin 0.8.2 finds 77 functions; binform 116, its first ones at rizin's addresses.

- Source: `pe-ppc/bad-57590` from a malware corpus (an `exotic_binaries` collection)
- SHA-256: `ef786d3873aa3025d6439827f16870111c2d7415ce19f9c05ce96ca12b521a3d`
- Size: 225248 bytes (192901 compressed)
- **Malware:** this file is hostile. It is kept compressed and only ever parsed; never run it.

`winnt-ppc.exe.rizin.json.zst` holds what rizin 0.8.2 found (`binform-ab --save`);
`winnt-ppc.exe.golden` holds what binform finds (`BINFORM_BLESS=1 cargo test --test fixtures`).
