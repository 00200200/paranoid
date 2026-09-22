<p align="center">
  <img src="assets/banner.svg" alt="paranoid — your app is guilty until proven secure" width="100%">
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-1f6feb" alt="MIT license"></a>
  <a href="https://github.com/kulchankas/paranoid/actions/workflows/benchmark.yml"><img src="https://github.com/kulchankas/paranoid/actions/workflows/benchmark.yml/badge.svg" alt="benchmark self-test"></a>
  <img src="https://img.shields.io/badge/runs%20in-Claude%20Code%20·%20Codex%20·%20Cursor-8957e5" alt="Runs in Claude Code, Codex, Cursor">
  <img src="https://img.shields.io/badge/proofs-localhost%20only-3fb950" alt="Localhost-only proofs">
  <a href="https://github.com/kulchankas/paranoid/stargazers"><img src="https://img.shields.io/github/stars/kulchankas/paranoid?style=social" alt="GitHub stars"></a>
</p>

# 🕵️ paranoid

An agent skill that pentests the app you're building. `/hack-me` attacks your own
running app the way an attacker would, then closes what it finds:

```
find  →  prove  →  patch  →  re-verify
```

Nothing is called a bug until a real HTTP request proves it, and no fix is done
until that exact exploit stops working.

<p align="center">
  <img src="assets/hack-me-demo.svg" alt="hack-me finds, proves, patches and re-verifies four real vulnerabilities in a running app" width="760">
</p>

## Quickstart

**Claude Code** — one install, gets you the skill *and* the `/hack-me` command:

```bash
/plugin marketplace add kulchankas/paranoid
/plugin install paranoid@paranoid
```

**Codex, Cursor, or any agent that reads skills:**

```bash
npx skills add kulchankas/paranoid/skills/paranoid
```

then copy [`commands/hack-me.md`](commands/hack-me.md) into your agent's commands
directory (e.g. `.claude/commands/`).

Start your app and point the agent at it:

```bash
python3 my_app.py     # your app, running locally
/hack-me              # → http://localhost:<port>
```

No dependencies, no network calls, no telemetry — it's Markdown your agent reads.

---

## Receipts

### On an app we didn't write

The hard claim is code we don't control. Pointed at [OWASP **VAmPI**](https://github.com/erev0s/VAmPI)
— a well-known third-party vulnerable API — with nothing but its URL, `/hack-me`
found, proved, patched and re-verified **six** real bugs:

<p align="center">
  <img src="assets/vampi-receipts.svg" alt="hack-me finds, proves, patches and re-verifies six real vulnerabilities in OWASP VAmPI" width="760">
</p>

| # | Finding | OWASP API | Status |
|---|---------|:--:|:--:|
| 1 | Unauth `/users/v1/_debug` dumps every password | API3/5 | **401/403** |
| 2 | Read any user's private book secret (BOLA) | API1 | **404** |
| 3 | Register with `admin:true` → privilege escalation | API6 | **admin=false** |
| 4 | Change any user's password (account takeover) | API1 | **victim untouched** |
| 5 | SQLi in user lookup (UNION-dumps passwords) | API8 | **404** |
| 6 | Debugger + stack traces exposed | API7 | **clean errors** |

Notably, VAmPI's own global "secure mode" flag closed only four of the six — the
critical password dump stayed open until patched. `/hack-me` caught it by
replaying every exploit instead of trusting the flag. Full receipts:
[`examples/vampi/HACKME_REPORT.md`](examples/vampi/HACKME_REPORT.md).

### On a demo app, start to finish

Against a small invoicing API ([`examples/ledgerlite`](examples/ledgerlite)), an
agent told **nothing** about the app's bugs found four by probing:

| # | Found by probing the API | Class | After patch |
|---|---|---|:--:|
| 1 | Any user reads any invoice | IDOR / broken object auth | **404** |
| 2 | `/admin/users` open to anyone logged in | broken function auth | **403** |
| 3 | `/search?email=` SQL injection (dumped passwords) | SQLi | **`[]`** |
| 4 | `/profile` accepts `is_admin` | mass assignment → privesc | **400** |

Every legitimate request still returns `200` afterwards. Reproduce it yourself:
`python3 examples/ledgerlite/app.py`, then run `/hack-me`. Walkthrough with exact
requests and diffs: [`examples/ledgerlite/HACKME_REPORT.md`](examples/ledgerlite/HACKME_REPORT.md).

## What `/hack-me` actually does

1. **Maps** your running app and picks the risk classes it's exposed to.
2. **Probes** each — one crafted request that only succeeds if the bug is real.
3. **Proves** every finding with the actual request/response (no theorizing).
4. **Patches** the root cause with a minimal, behavior-preserving fix.
5. **Re-verifies** by replaying the exact exploit — a finding isn't closed until it fails.

It knows where routes and auth live in twelve stacks (Next.js, FastAPI, Express,
Django, Rails, Flask, Spring Boot, Laravel, Phoenix, Go, NestJS, ASP.NET Core) — see
[`references/frameworks.md`](skills/paranoid/references/frameworks.md). Guardrails
apply throughout; see [Scope & ethics](#scope--ethics).

## Why this isn't another "write secure code" skill

It started as the obvious thing — guidance telling the agent to write secure code
— and then got **benchmarked honestly** before anyone believed it. The harness
([`benchmark/`](benchmark)) generates the same tasks with and without the skill
and runs real exploits against whatever the model writes.

The result was a clean negative:

| Model | Tasks | Exploit rate **without** skill | **with** skill | Effect |
|---|---|:--:|:--:|:--:|
| Opus | **all 22 classes, blinded** | **0%** | **0%** | **none** |
| Opus | 3 isolated functions | 0% | 0% | none |
| Fable 5.1 | 3 isolated functions | 0% | 0% | none |

On an isolated function a capable model already writes the secure version
unprompted — ownership in the `WHERE` clause, parameterized queries, field
allow-lists. **Advice adds nothing there.** (The harness isn't rigged: it flags
deliberately-insecure reference code at 100% and secure code at 0%, and CI
asserts that on every push.)

*Blinded* matters here: the task ids name their own vulnerability, so asking a
model for `sqli_login.py` is itself a security hint. The 22-class run was redone
with the specs renamed `task_01…task_22`, generated outside the repo, with no
mention of a benchmark — and the result held. The skill did, however, cost a
functional test the baseline passed. [Full method, caveats and raw
solutions.](benchmark)

Real vulnerabilities don't live in one tidy function. They live in the **wiring**
of a whole running app: auth on one route but not the next, a request body that
quietly sets `is_admin`, a search box that concatenates SQL. So `paranoid` stops
advising and starts attacking the running app.

## Also inside: the paranoid skill

The guidance the benchmark tested still earns its place as a **companion while
you code** and as `hack-me`'s knowledge base:

- [the vibe-coded top 10](skills/paranoid/references/vibe-top-10.md)
- references: [auth & access](skills/paranoid/references/auth-access.md) ·
  [secrets & the client boundary](skills/paranoid/references/secrets-config.md) ·
  [injection & SSRF](skills/paranoid/references/injection.md) ·
  [APIs & webhooks](skills/paranoid/references/apis-webhooks.md) ·
  [framework guides](skills/paranoid/references/frameworks.md)
- a 7-point [pre-commit gate](skills/paranoid/checklists/pre-commit.md)

Load it while building; run `/hack-me` to check whether it held.

## The benchmark

A reproducible harness for *"does a security skill actually reduce
vulnerabilities?"* — 23 vulnerability classes, each with a neutral spec, a
functional check and a real exploit check. All 22 have been scored against a
model in both conditions, blinded; the raw solutions are committed so anyone can
re-score them. CI asserts on every push that the deliberately-insecure references
still score 100% and the secure ones 0%, so the benchmark can't silently rot.
Details, caveats and how to re-run it: [`benchmark/`](benchmark).

## Scope & ethics

`paranoid` secures **your** code and pentests **your** running app, with your
say-so: authorized targets, localhost only, non-destructive proofs. It is not
built to target third-party systems, scan hosts you don't own, evade detection,
or produce live malware, and it will decline to. See [SECURITY.md](SECURITY.md).

## Roadmap

- [x] `/hack-me` loop — find → prove → patch → re-verify, on localhost
- [x] Reproducible skill-efficacy benchmark + the honest result behind the pivot
- [x] Independent-app proof — [OWASP VAmPI](examples/vampi): 6 real bugs found, fixed & re-verified
- [x] 23 benchmark task classes (IDOR, missing auth, SQLi, mass assignment, path traversal, SSRF, XSS, command injection, open redirect, JWT auth, leaked secrets, CSRF, template injection, XXE, unrestricted upload, permissive CORS, weak password storage, ReDoS, unverified webhooks, insecure deserialization, SSRF via DNS-rebinding, route-wiring IDOR)
- [x] `/hack-me` framework guides — 10 stacks
- [x] A second independent-app proof — [DVWA](examples/dvwa): 6 real bugs found, fixed & re-verified on a PHP/MariaDB stack
- [ ] A third proof on a target that publishes no bug list, so the *find* step has to earn it
- [x] SSRF via DNS-rebinding task class

`paranoid` is v0.1 and actively developed — issues and PRs welcome.

## Contributing

New vulnerability classes, framework guides, and independent-app proofs are the
most useful contributions — see [CONTRIBUTING.md](CONTRIBUTING.md) for the format
and the honesty rules, and [SECURITY.md](SECURITY.md) for scope. Good first issues
are labeled in the tracker.

## License

MIT © 2026 kulchankas. See [LICENSE](LICENSE).
