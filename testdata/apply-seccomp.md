# apply-seccomp

A static x86-64 glibc executable: landing pads from `.gcc_except_table` (in its C++ runtime parts), and `main`, which only the argument `_start` passes to `__libc_start_main` names.

- Source: the `@vscode/sandbox-runtime` module as bundled in VSCodium 1.126.04524 for macOS x64 (`VSCodium-vscodium-1.126.04524-VSCodium-darwin-x64-1.126.04524.zip`); built with GCC 11.4.0 (Ubuntu 22.04)
- Path in the source: `VSCodium.app/Contents/Resources/app/node_modules/@vscode/sandbox-runtime/vendor/seccomp/x64/apply-seccomp`
- SHA-256: `c3c42b6b79d7298ef6fdadb36955350a7fe8ef1a1cfa900b7346191a6dada86f`
- Size: 831952 bytes (303900 compressed)
- License: MIT (VSCodium); the binary statically links glibc (LGPL-2.1) and libgcc

`apply-seccomp.rizin.json.zst` holds what rizin 0.8.2 found (`binform-ab --save`);
`apply-seccomp.golden` holds what binform finds (`BINFORM_BLESS=1 cargo test fixtures`).
