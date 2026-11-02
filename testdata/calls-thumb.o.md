# calls-thumb.o

An ELF relocatable object: Thumb-2; calls are `R_ARM_THM_CALL`, and calls to imports become `blx` to A32 slots. Four functions (`entry`, `other`, and the static `check` and `twice`) call each other and three undefined functions (`puts`, `abort`, `helper`). Unlinked, every call reads as a call to itself; linked, each reaches its callee or an import slot. Rizin 0.8.2 does not link calls in these objects, so the claims are funktion's own.

- Source: `calls.c` below, built by `zig cc` 0.16.0 (from the `ziglang` PyPI package): `zig cc -target thumb-linux-musleabihf -O2 -fno-inline -c calls.c`
- SHA-256: `46874b85a9dae2c90717ab6f2747b38989e81a3d825051b0ca36f4f4c3e83ed0`
- Size: 3396 bytes (1405 compressed)
- License: public domain (written for funktion)

```c
extern int puts(const char *);
extern void abort(void);
extern int helper(int);
static __attribute__((noinline)) int twice(int x) { return helper(x) * 2; }
static __attribute__((noinline)) int check(int x) { if (x < 0) abort(); return twice(x) + 1; }
int entry(int x) { puts("hi"); return check(x) + twice(x + 1); }
int other(int x) { return entry(x) - check(x); }
```

`calls-thumb.o.rizin.json.zst` holds what rizin 0.8.2 found (`funktion-ab --save`);
`calls-thumb.o.golden` holds what funktion finds (`FUNKTION_BLESS=1 cargo test --test fixtures`).
