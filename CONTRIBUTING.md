# Contributing to paranoid

Thanks for helping make agent-written code harder to break. `paranoid` is small
on purpose — Markdown skills plus a dependency-free Python benchmark — so
contributing is low-friction.

## Good first contributions

- **A new benchmark task class.** The harness covers 14 classes today (IDOR,
  missing auth, SQLi, mass assignment, path traversal, SSRF, XSS, command
  injection, open redirect, JWT auth, leaked secrets, CSRF, template injection).
  XXE, ReDoS, and insecure deserialization are still open.
- **A `/hack-me` framework guide.** We cover Next.js, FastAPI, Express, Django,
  Rails, Flask, Spring Boot, and Go in
  [`skills/paranoid/references/frameworks.md`](skills/paranoid/references/frameworks.md).
  Laravel and Phoenix are wanted.
- **An independent-app proof.** Run `/hack-me` against a public
  intentionally-vulnerable app on localhost and add a receipts report under
  [`examples/`](examples) (see [`examples/vampi`](examples/vampi) for the format).
- **Fixes to a reference file** — a clearer failure mode, a better fix pattern.

### Help wanted (scoped, ready to pick up)

Each of these is a self-contained PR. Comment on the matching issue (or open one
from the templates) before starting.

1. **Benchmark: XXE task class.** Add `tasks/xxe_xml_parse/` (XML parsed with
   external entities enabled) plus insecure/secure self-test refs. *Done when*
   `run.py --only xxe_xml_parse` reports insecure 100% / secure 0%.
2. **Benchmark: ReDoS task class.** Add a task where a catastrophic-backtracking
   regex runs on user input, with a bounded, deterministic check. *Done when* the
   self-test shows 100% / 0%.
3. **Framework guide: Laravel.** Add a Laravel (PHP) section to
   `references/frameworks.md` matching the existing structure (routes, where auth
   lives, run command, probe first). *Done when* it's linked from the "Covered
   here" line.
4. **Framework guide: Phoenix.** Same shape as #3, for Elixir/Phoenix.
5. **Independent proof: a second app.** A localhost `/hack-me` run against another
   public vulnerable app (e.g. a small DVWA-style target), with a receipts
   `HACKME_REPORT.md` under `examples/`. *Done when* every finding shows a real
   request/response and a re-verified fix.

Recently shipped from this list: CSRF and template-injection task classes, the
Flask and Spring Boot guides, and the harness `--json` flag.

These map to the issue templates in
[`.github/ISSUE_TEMPLATE/`](.github/ISSUE_TEMPLATE); label them `good first issue`
when filed.

## Adding a benchmark task

Each task is a directory under [`benchmark/tasks/`](benchmark/tasks):

```
tasks/<task_id>/
  spec.md      # neutral prompt — NO security hints; states the function signature
  check.py     # defines TASK = {"id","fn","vuln"} and functional(fn) / secure(fn)
```

- `functional(fn)` returns `(ok, note)` — does the solution do the job?
- `secure(fn)` returns `(ok, note)` — is the known exploit blocked? `ok=True`
  means safe.
- Then add a **deliberately-insecure** and a **secure** reference under
  `benchmark/solutions/selftest_insecure/<task_id>.py` and
  `benchmark/solutions/selftest_secure/<task_id>.py`.

Verify the harness detects your task before you push:

```bash
cd benchmark
python3 harness/run.py --only <task_id> solutions/selftest_insecure solutions/selftest_secure
# expect: insecure 100% exploit rate, secure 0%
```

The CI job ([`.github/workflows/benchmark.yml`](.github/workflows/benchmark.yml))
runs the full self-test on every push and PR; it must stay green.

## Honesty rules (non-negotiable)

This project exists because it reported a *negative* result honestly. Keep it that
way:

- **No number in a README until the harness produced it.** Report the model and
  date alongside any benchmark figure.
- **Report losses too.** A skill that doesn't help is a finding, not a failure to
  hide.
- **Proofs are real requests.** In `/hack-me` reports, every claim is backed by an
  actual request/response the reader can reproduce.

## Scope & ethics

`paranoid` secures the user's own code and pentests the user's own running app,
locally and with authorization. Contributions must not turn it into a tool for
attacking third-party systems, evading detection, or building live malware. See
[`SECURITY.md`](SECURITY.md).

## Style

- Python: standard library only in the benchmark; keep it 3.8+ compatible.
- Markdown: concrete over abstract — show the insecure line and the fixed line.
- One logical change per commit; a clear message.
