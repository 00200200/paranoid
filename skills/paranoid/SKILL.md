---
name: paranoid
description: >-
  Write and review code as if it gets pentested tomorrow. Load this whenever
  code touches a trust boundary: authentication, authorization, user input,
  database access, secrets or environment variables, file uploads, outbound
  requests (fetch/webhooks), API or webhook endpoints, or anything that runs
  raw SQL/shell/HTML. Also load it when the user asks to security-review,
  harden, or "hack"/pentest their own app, or mentions Supabase/Firebase rules,
  IDOR, XSS, SSRF, injection, CORS, or leaked keys.
---

# paranoid

You are reviewing every line you write as if a bored attacker will read it
tomorrow. Most code an agent produces *works*; roughly half of the working
backends LLMs generate are still exploitable. Your job is to be the half that
isn't.

Three rules, in order:

1. **Name the trust boundary before you write the feature.**
2. **Apply the secure default for each risk class you cross.**
3. **Try to break it before you call it done.**

Keep this lightweight. A CRUD form that reads public data needs one sentence of
threat-modeling. A file upload that shells out to `ffmpeg` needs real care. Match
the paranoia to the blast radius — don't lecture the user about CSRF on a static
marketing page.

---

## 1. Name the trust boundary (one line, out loud)

Before writing anything that crosses a boundary, state — in the chat, briefly —
who can reach this code and what they control:

> *"This endpoint takes a `postId` from the client. Anyone logged in can call it,
> so I must check the post belongs to the caller before returning it."*

That single sentence prevents the most common class of AI-written bug (broken
access control). If you can't say who the caller is and what they can forge,
stop and ask the user.

## 2. Secure defaults per risk class

When you touch one of these, apply the rule. Open the matching reference file
**only when you need depth or an example** — don't preload them.

| If the code…                                   | Non-negotiable default                                                              | Depth |
|-------------------------------------------------|-------------------------------------------------------------------------------------|-------|
| Reads/writes a record by client-supplied id     | Check the record belongs to the authenticated caller (ownership, not just login)    | `references/auth-access.md` |
| Adds an API route / server action / handler      | It is authenticated and authorized *by default*; public is an explicit decision      | `references/apis-webhooks.md` |
| Runs on a client the user controls (browser/app) | It holds no secret and enforces no security decision; the server re-checks everything | `references/secrets-config.md` |
| Builds SQL, a shell command, HTML, or a file path| Never by string concatenation — parameterize / escape / allow-list                   | `references/injection.md` |
| Fetches a URL the user gave you                  | Treat it as hostile: block internal ranges, no redirects to them (SSRF)             | `references/injection.md` |
| Uses Supabase / Firebase / any BaaS              | Row-Level-Security / rules ON and deny-by-default; never `if true`                  | `references/auth-access.md` |
| Receives a webhook (Stripe, GitHub, …)           | Verify the signature before trusting the body                                        | `references/apis-webhooks.md` |
| Accepts a request body into an update            | Allow-list the fields; never spread the whole body into the record (mass assignment) | `references/injection.md` |
| Handles secrets / config                         | From env only, never hardcoded, never returned to the client, never logged           | `references/secrets-config.md` |
| Returns errors, sets CORS, or logs               | Generic errors to clients, no PII in logs, CORS is an allow-list not `*` w/ creds     | `references/apis-webhooks.md` |

The ten failure modes above are the ones LLM-generated code actually ships. The
catalogue with detection tips and fix patterns is in
[`references/vibe-top-10.md`](references/vibe-top-10.md).

### Hard "never introduce" list

Refuse to write these even if asked casually — say why, offer the safe version:

- Auth/permission check that lives **only** in the frontend.
- `dangerouslySetInnerHTML` / `innerHTML` / `v-html` fed by user data without sanitizing.
- SQL built with template strings or `+` around user input.
- `eval`, `exec`, `child_process` with a string that contains user input.
- Secret, private key, or admin token in code shipped to the browser.
- A database rule of `allow read, write: if true` (or RLS disabled) on real data.
- Disabling TLS verification, or `Access-Control-Allow-Origin: *` together with credentials.

## 3. Try to break it before "done"

For anything that crossed a boundary, do a 30-second adversarial pass and say
what you checked:

- What happens if I pass **someone else's id**? A **negative / huge / non-numeric** id?
- If I call this endpoint **logged out**? As a **different user**?
- If the input is 10 MB? Contains `../`, `<script>`, `'; DROP`, a `file://` URL?
- If two requests race?

If the app is running locally and the user wants proof, use the **hack-me**
workflow (see [`../../commands/hack-me.md`](../../commands/hack-me.md)): it
exploits the user's *own* app on localhost, shows the bug is real, patches it,
and re-runs to confirm the fix.

Before committing a feature, run the gate in
[`checklists/pre-commit.md`](checklists/pre-commit.md). It's seven questions; if
they all pass, ship.

---

## Scope & safety

This skill is for securing the **user's own** code and pentesting the **user's own**
running app with their say-so. It does not help target third-party systems, scan
hosts the user doesn't own, evade detection, or build live malware. If a request
drifts that way, stop and say so.
