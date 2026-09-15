# 🕵️ paranoid

**Make your coding agent write like it's getting pentested tomorrow.**

`paranoid` is an [Agent Skill](https://docs.claude.com/en/docs/claude-code/skills)
for Claude Code, Codex, and Cursor. When your agent touches a trust boundary —
auth, user input, a database, secrets, an outbound request, an API route — it
loads a short security playbook and applies the secure default *before* it writes
the code. Then it can attack your own app to prove the holes are real.

Roughly **half of the functionally-correct backends that LLMs generate are still
exploitable** ([BaxBench](https://baxbench.com/)). Your tests pass, the feature
works, and any logged-in user can read anyone else's data. `paranoid` is aimed at
exactly that gap.

```
why review later when review now
```

---

## What it does

- **Threat-models in one line** before writing a feature, so it can't forget who
  the caller is or what they control.
- **Applies secure defaults** for the ten vulnerability classes AI-generated apps
  actually ship — broken access control / IDOR, missing auth, client-trust,
  injection (SQL/shell/XSS/path), open BaaS rules (Supabase RLS, Firebase),
  SSRF, leaked secrets, mass assignment, unverified webhooks, and leaky
  errors/CORS. See [`the vibe-coded top 10`](skills/paranoid/references/vibe-top-10.md).
- **Runs a 7-question pre-commit gate** so a risky diff doesn't ship unreviewed.
- **`/hack-me`** — attacks your *own* app on localhost, shows the exploit
  working, patches it, and re-runs to prove the fix. Localhost-only,
  non-destructive, your code only.

## Install

```bash
npx skills add kulchankas/paranoid/skills/paranoid
```

Or drop [`skills/paranoid/`](skills/paranoid) into your project's skills
directory (`.claude/skills/`, `.codex/skills/`, or `.cursor/skills/`). The
`/hack-me` command lives in [`commands/`](commands) — copy it to
`.claude/commands/` to use it as a slash command.

No dependencies, no network calls, no telemetry. It's Markdown your agent reads.

## See it work

> **You:** add an endpoint to fetch an invoice by id
>
> **Agent (paranoid loaded):** This reads a record by a client-supplied `id`, so
> I'll scope the query to the authenticated user or anyone could read anyone's
> invoice:
> ```ts
> const inv = await db.invoice.findFirst({ where: { id, userId: req.user.id } });
> if (!inv) return res.sendStatus(404);
> ```
> paranoid gate: access-control ✓ · auth ✓ · validation ✓

Then, if it's running locally:

> **You:** /hack-me
>
> **Agent:** Target `http://localhost:3000`, your app, non-destructive. Logged in
> as `alice`, requested `bob`'s invoice `inv_812`… got back Bob's data (IDOR,
> broken access control). Patched with an ownership check. Re-ran the same
> request → `404`. Finding closed.

## Does it actually help? (benchmark)

Claims about security tooling are cheap, so this ships with a reproducible
harness instead of a vibe. It runs a slice of security-focused code-generation
tasks with and without the skill and diffs the exploit rate.

- **How to reproduce:** [`benchmark/README.md`](benchmark/README.md)
- **Results:** _running — the number goes here when the harness has produced it,
  not before._ (Building trust is the whole point of a security tool; we're not
  going to headline a figure we haven't measured.)

## Scope & ethics

`paranoid` secures **your** code and pentests **your** running app, with your
say-so. It is not built to target third-party systems, scan hosts you don't own,
evade detection, or produce live malware, and it will decline to. Authorized,
defensive, local.

## License

MIT © 2026 kulchankas. See [LICENSE](LICENSE).
