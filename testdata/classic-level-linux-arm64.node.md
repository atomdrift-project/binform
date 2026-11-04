# classic-level-linux-arm64.node

The same C++ for A64: landing pads, the PLT (a 32-byte header), and A64 jump tables, which rizin does not resolve.

- Source: the `classic-level` 3.0.0 npm package (Level/classic-level), its prebuilds as bundled in the `augment.vscode-augment` 0.893.1 VSIX under `extension/out/prebuilds/`
- Path in the source: `prebuilds/linux-arm64/classic-level.armv8.node`
- SHA-256: `d81eaacbec70a75c872c5da37e0dd8e7b3d65b565a1b55953b7b4b532608bfb0`
- Size: 452056 bytes (166803 compressed)
- License: MIT (classic-level); it links LevelDB and Snappy, both BSD-3-Clause

`classic-level-linux-arm64.node.rizin.json.zst` holds what rizin 0.8.2 found (`binform-ab --save`);
`classic-level-linux-arm64.node.golden` holds what binform finds (`BINFORM_BLESS=1 cargo test fixtures`).
