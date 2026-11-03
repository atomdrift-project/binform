# classic-level-linux-x64.node

C++ (LevelDB in a Node addon), x86-64 glibc: landing pads from `.gcc_except_table`, PLT stubs (`.plt`, `.plt.sec`), and jump tables.

- Source: the `classic-level` 3.0.0 npm package (Level/classic-level), its prebuilds as bundled in the `augment.vscode-augment` 0.893.1 VSIX under `extension/out/prebuilds/`
- Path in the source: `prebuilds/linux-x64/classic-level.node`
- SHA-256: `48843c7375f755db2b80d37bc26b075b74df584820b26dd1dc9cd7b323575143`
- Size: 480800 bytes (174618 compressed)
- License: MIT (classic-level); it links LevelDB and Snappy, both BSD-3-Clause

`classic-level-linux-x64.node.rizin.json.zst` holds what rizin 0.8.2 found (`binform-ab --save`);
`classic-level-linux-x64.node.golden` holds what binform finds (`BINFORM_BLESS=1 cargo test --test fixtures`).
