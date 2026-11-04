# Security

binform is built to read untrusted binaries. Any input that makes it
panic, run without bound, or use memory out of proportion to its size is a
bug we treat as a security issue.

Please report one privately, through GitHub's "Report a vulnerability"
button on this repository's Security tab, with the input (or a way to
build it) and the binform version. We aim to answer within a week.

Inputs that are only slow within the configured `Limits`, or that recover
wrong functions, are ordinary bugs: open an issue.
