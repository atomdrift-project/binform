# calls-riscv64.o

An ELF relocatable object: 64-bit RISC-V, position-independent, built for linker relaxation, so even branches within `.text` are relocated (`R_RISCV_BRANCH`, `R_RISCV_RVC_JUMP`) and every call is an `auipc; jalr` pair (`R_RISCV_CALL_PLT`). Four functions (`entry`, `other`, and the static `check` and `twice`) call each other and three undefined functions (`puts`, `abort`, `helper`). Unlinked, every call reads as a call to itself; linked, each reaches its callee or an import slot. Rizin 0.8.2 does not link calls in these objects, so the claims are binform's own.

- Source: `calls.c` below (the same as `calls-mips.o`'s), built by `zig cc` 0.16.0 (from the `ziglang` PyPI package): `zig cc -target riscv64-linux-musl -O2 -fno-inline -fPIC -mrelax -c calls.c -o calls-riscv64.o`
- SHA-256: `1330a2e2037aee303ec0d798b60f675e9899751ac03ff0fbf85059e8326e664d`
- Size: 10008 bytes (2117 compressed)
- License: public domain (written for binform)

```c
extern int puts(const char *);
extern void abort(void);
extern int helper(int);
static __attribute__((noinline)) int twice(int x) { return helper(x) * 2; }
static __attribute__((noinline)) int check(int x) { if (x < 0) abort(); return twice(x) + 1; }
int entry(int x) { puts("hi"); return check(x) + twice(x + 1); }
int other(int x) { return entry(x) - check(x); }
```

`calls-riscv64.o.rizin.json.zst` holds what rizin 0.8.2 found (`binform-ab --save`);
`calls-riscv64.o.golden` holds what binform finds (`BINFORM_BLESS=1 cargo test --test fixtures`).
