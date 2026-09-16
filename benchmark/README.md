# Benchmark: does a security *skill* actually reduce vulnerabilities?

This is the honest test that shaped `paranoid`. It answers one question with a
reproducible harness instead of a claim — and the answer is *why* `paranoid` is a
doing-tool (`/hack-me`) rather than a "write secure code" prompt.

## The question

> For the same security-sensitive tasks, does an agent with the skill loaded
> produce fewer exploitable solutions than the same agent without it, holding
> functional correctness equal?

Two numbers per condition:

- **exploit rate among correct solutions** — of the code that actually works, how
  much is still exploitable. Lower is better.
- **correctness** — the skill mustn't win on security by breaking functionality.

## Method

- **Tasks** (`tasks/`): each has a *neutral* spec (no security hints), a
  **functional** check, and an **exploit** check for a specific class (IDOR,
  missing authz, SQLi, mass assignment, path traversal, SSRF, XSS, command
  injection, open redirect, JWT auth verification, leaked secrets, CSRF,
  template/format-string injection).
- **Conditions**: identical base model; `baseline` = no skill, `paranoid` = skill
  in context. The generated solutions live in `solutions/<condition>/`.
- **Score**: `harness/run.py` runs the functional check, then the exploit check,
  for each solution and reports per-condition rates.

## Result

Matched-model runs, skill vs no-skill:

| Model | Task set | exploit rate (baseline) | exploit rate (paranoid) | delta |
|---|---|:--:|:--:|:--:|
| Fable 5.1 | 3 isolated fns, leading specs | 0% | 0% | +0pp |
| Opus | 3 isolated fns, leading specs | 0% | 0% | +0pp |
| Opus | 3 isolated fns, neutral/tempting specs | 0% | 0% | +0pp |

**A capable model already writes the secure version of an isolated function
unprompted.** The skill has no headroom to add value at this granularity.

This is not a broken harness. Against deliberately-insecure vs secure reference
solutions (`solutions/selftest_insecure`, `solutions/selftest_secure`) it reports
**100%** and **0%** exploit rates respectively — it detects the difference when
there is one. This self-test runs in [CI](../.github/workflows/benchmark.yml) on
every push, so a regression that makes the harness miss a known bug fails the
build.

## Task classes

Fourteen classes have a neutral spec + functional + exploit check today:
`idor_invoices`, `idor_session_only`, `missing_auth_admin`, `sqli_login`,
`mass_assignment_update`, `path_traversal_note`, `ssrf_url_preview`,
`xss_comment_render`, `command_injection_ping`, `open_redirect_login`,
`jwt_verify_identity`, `leaked_secrets_client_config`, `csrf_state_change`,
`template_injection_notice`. All fourteen are covered by the insecure/secure
self-test above (100% / 0%). The matched-model numbers reported here predate the
classes added after SQLi/IDOR/mass-assignment; those newer classes are
harness-verified and awaiting a model-condition run (honesty rule: no model number
appears until the harness produced it).

Machine-readable output: add `--json` to any `run.py` invocation to get a single
JSON summary (per-condition rates + delta) instead of the human tables — handy for
CI and for diffing conditions.

## What it means

Isolated functions are the wrong unit. The vulnerabilities that ship in real
apps live in cross-cutting **wiring** — an auth check present on one route and
missing on the next, a request body spread into an update, a search that builds
SQL — context a model can't hold perfectly across a whole codebase. That is what
`/hack-me` targets by attacking the **running app**, and where it demonstrably
finds real bugs (see [`../examples/ledgerlite`](../examples/ledgerlite)).

## This matches the literature

The null result isn't an artifact of a tiny harness — it lines up with recent
work:

- [*Prompt Structure Redistributes, Not Reduces*](https://arxiv.org/html/2608.24857v1)
  — security-aware prompting changes *which* weakness categories appear but does
  not reliably lower the overall vulnerability rate.
- [BaxBench](https://baxbench.com/) — generic security reminders help *reasoning*
  models modestly and barely move instruction-following ones; naming the exact
  vulnerability helps but costs functional correctness.

The consistent takeaway: guidance nudges, it doesn't fix. That's why `paranoid`'s
value is in *doing* (`/hack-me`), not advising.

## Reproduce

```bash
cd benchmark

# sanity-check the harness itself:
python3 harness/run.py --only mass_assignment_update,idor_session_only,path_traversal_note \
    solutions/selftest_insecure solutions/selftest_secure     # expect 100% vs 0%

# score a pair of generated conditions:
python3 harness/run.py solutions/opus_baseline solutions/opus_paranoid
python3 harness/run.py --only mass_assignment_update,idor_session_only,path_traversal_note \
    solutions/hard_opus_baseline solutions/hard_opus_paranoid
```

To add your own condition, drop one `<task_id>.py` per task into
`solutions/<name>/` (each defining the function named in that task's `spec.md`)
and pass that dir to `run.py`. Generate them with any model, with or without the
skill in context.

## Honesty rules for this benchmark

- No number in a README until the harness produced it here. (The +0pp above is
  measured, not assumed.)
- Report the losses too — this whole page *is* a negative result, kept because
  it's true and it's why the project pivoted.
- Report the model and date; a number without them is meaningless as models move.
- A fuller run belongs on realistic, multi-file apps (BaxBench-style), not just
  isolated functions — that's the regime where a security tool has room to help.
