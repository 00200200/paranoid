---
description: Attack your own running app on localhost, prove each vuln is real, patch it, and re-verify.
---

# /hack-me

Turn the `paranoid` review into proof. Instead of *telling* the user their code
has an IDOR, you demonstrate it against their own app on localhost, then fix it
and show the exploit now fails.

## Scope — read first, enforce always

This runs **only** against an app the user owns and is running locally. Before
touching anything:

- **Target must be local.** `localhost`, `127.0.0.1`, `::1`, or a
  `*.localhost` / private dev host the user names. If a target resolves to a
  public IP or a domain the user doesn't own, **stop** and say why.
- **Non-destructive proofs only.** Prove read access by reading one record that
  shouldn't be readable; prove a write bug by writing to a throwaway/seeded
  record — never delete data, never mass-mutate, never exfiltrate real user data.
  Redact anything sensitive you surface as proof.
- **No DoS.** Demonstrate a missing rate limit with a small, bounded burst (e.g.
  ~20 requests) and describe the risk — don't actually flood anything.
- **This is authorized pentesting of the user's own code.** It is not for third-
  party systems, detection evasion, or persistent tooling. If the request drifts
  there, decline.

Say the scope back to the user and get a "go" before the first request.

## Workflow

1. **Map.** Find the app's routes/handlers and how it's run (framework, port,
   how to start it, whether seed/test users exist). Ask the user for the base URL
   and, if needed, two test accounts (attacker + victim) — never real credentials
   beyond a local dev login.

2. **Prioritize.** From the companion `paranoid` skill's
   [`references/vibe-top-10.md`](../skills/paranoid/references/vibe-top-10.md)
   (installed alongside this command; if you only have `/hack-me`, use the
   class list in the report below), pick the classes this app is actually exposed
   to. Order by likelihood × impact. Broken access control and missing auth
   first; they're the most common and the easiest to prove.

3. **Probe, one class at a time.** For each candidate, craft the minimal request
   that would succeed only if the bug exists. Use `curl`/HTTP against localhost.
   Examples of *proofs* (adapt to the app):
   - **IDOR:** log in as user A, request user B's object id → if you get B's data, it's real.
   - **Missing auth:** call the endpoint with no session/token → if it returns data, it's real.
   - **Client trust:** replay the request with `amount`/`role`/`isAdmin` edited → if the server honors it, it's real.
   - **Injection:** a single benign marker (`' OR '1'='1` on a *seeded* row, `<b>xss</b>` reflected) — enough to show the sink, never a destructive payload.
   - **SSRF:** point a user-URL field at `http://127.0.0.1:<internal>` or a metadata IP → if it fetches, it's real.

4. **Report each finding** as: what you sent, what came back (redacted), why it's
   a vulnerability, and which top-10 class it is. Show the actual request/response
   so it's undeniable.

5. **Patch.** Apply the fix from the matching reference file. Keep the diff small
   and explain it.

6. **Re-verify.** Re-run the exact same probe. Show it now returns `401`/`403`/
   `404`/validation error. A finding isn't closed until the original exploit fails.

7. **Summarize.** A short table: finding · class · severity · status
   (fixed / needs-owner-decision). Note anything you could not safely test locally.

## Output style

Lead with the scariest confirmed finding, with its request/response. Be concrete,
not alarmist — every claim is backed by a request the user can re-run themselves.
