# bot-s390x-static-pie

A static-pie, stripped s390x executable (GCC 11.2.1) whose `.text` holds an encrypted payload: about 370 KB of near-random bytes ahead of 110 KB of real code.

Only `.init`, `.fini`, the entry point and the dynamic symbols name code. The linear sweep must not start functions in the payload (byte entropy above 7.8 bits a byte, where machine code stays under 7.2), and tail calls (`jg`) to code that saves registers (`stmg %rN, %r15, d(%r15)`) start functions of their own. rizin 0.8.2 finds 4 functions.

- Source: `s390x/bad-00b6e99b5b9ef561cb7608c55c41942c74b5d872f169470ded0b9f5b4327f85c` from a malware corpus (an `exotic_binaries` collection); three other copies in it are the same size and parse the same
- SHA-256: `00b6e99b5b9ef561cb7608c55c41942c74b5d872f169470ded0b9f5b4327f85c`
- Size: 502120 bytes (423228 compressed)
- **Malware:** this file is hostile. It is kept compressed and only ever parsed; never run it.

`bot-s390x-static-pie.rizin.json.zst` holds what rizin 0.8.2 found (`binform-ab --save`);
`bot-s390x-static-pie.golden` holds what binform finds (`BINFORM_BLESS=1 cargo test fixtures`).
