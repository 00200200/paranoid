# Security Policy

## This is a defensive tool

`paranoid` and its `/hack-me` workflow are for securing **your own** code and
pentesting **your own** running app, locally and with authorization. They are not
built to target third-party systems, scan hosts you don't own, evade detection,
or produce live malware — and the skill is written to decline when a request
drifts that way. Please use it accordingly.

The example targets ([`examples/ledgerlite`](examples/ledgerlite),
[`examples/vampi`](examples/vampi)) are **intentionally vulnerable** and meant to
run only on `localhost`. Never deploy them anywhere reachable.

The same goes for [`benchmark/solutions/selftest_insecure/`](benchmark/solutions/selftest_insecure):
every file there is a **deliberately exploitable reference** (SQL injection,
pickle deserialization, path traversal, and so on) that exists so CI can prove
the harness still detects a known bug. They are never imported by the skill or
the `/hack-me` command, and they are not a vulnerability in this project — please
don't file reports against them.

## Reporting a vulnerability in this repo

The skills and benchmark here are Markdown and dependency-free Python that your
agent reads and runs locally — there's no server or hosted component. If you
still find a security issue in this repository (for example, a `/hack-me`
instruction that could be misused, or a benchmark harness that executes solution
code unsafely):

- **Preferred:** open a [GitHub Security Advisory](https://github.com/kulchankas/paranoid/security/advisories/new)
  (private disclosure).
- Or open a normal issue if it is not sensitive.

Please include what you did, what happened, and what you expected. We aim to
acknowledge reports quickly and will credit reporters who want it.

## A note on the benchmark harness

`benchmark/harness/run.py` imports and executes the solution files you point it at.
Only run it on solutions you trust or generated yourself — treat it like running
any untrusted script.
