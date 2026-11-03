# classic-level-darwin.node

A universal Mach-O (x86-64 and A64). binform reads the first slice it decodes, x86-64, as rizin does. Covers `__stubs` entries and landing pads from the LSDAs `__unwind_info` names.

- Source: the `classic-level` 3.0.0 npm package (Level/classic-level), its prebuilds as bundled in the `augment.vscode-augment` 0.893.1 VSIX under `extension/out/prebuilds/`
- Path in the source: `prebuilds/darwin-x64+arm64/classic-level.node`
- SHA-256: `e311fd4aadf58e151dcb19b0144fbbb468ef08fb73d77bca806e7320725ef26c`
- Size: 712624 bytes (231113 compressed)
- License: MIT (classic-level); it links LevelDB and Snappy, both BSD-3-Clause

`classic-level-darwin.node.rizin.json.zst` holds what rizin 0.8.2 found (`binform-ab --save`);
`classic-level-darwin.node.golden` holds what binform finds (`BINFORM_BLESS=1 cargo test --test fixtures`).
