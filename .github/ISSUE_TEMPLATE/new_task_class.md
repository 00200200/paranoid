---
name: New benchmark task class
about: Propose a vulnerability class to add to the benchmark
title: "[task] "
labels: benchmark, enhancement
---

**Vulnerability class**
e.g. SSRF, open redirect, command injection, JWT confusion, leaked secrets.

**Neutral task idea**
A one-paragraph, security-hint-free task that a model would implement — and the
function signature the solution should expose.

**The exploit `secure(fn)` should catch**
What input distinguishes an exploitable solution from a safe one?

**Insecure vs secure reference**
Roughly what the deliberately-insecure and the safe implementation look like.
(These become `solutions/selftest_insecure/` and `solutions/selftest_secure/`.)

See [CONTRIBUTING.md](../../CONTRIBUTING.md#adding-a-benchmark-task) for the format.
