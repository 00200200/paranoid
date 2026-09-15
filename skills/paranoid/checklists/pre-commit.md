# Pre-commit security gate

Run this before committing a feature that crossed any trust boundary. Seven
questions. If code changed touches auth, data access, input, secrets, outbound
requests, or endpoints and you can't answer "yes" (or "n/a"), fix it first.

Report the result compactly, e.g.:

> paranoid gate: 1 ✓ · 2 ✓ · 3 ✓ · 4 ⚠ fixed (added ownership check) · 5 ✓ · 6 n/a · 7 ✓

1. **Access control** — Does every lookup/mutation on a client-supplied id scope
   to the authenticated caller (ownership/membership, not just "logged in")?

2. **Auth coverage** — Is every new route/handler/action authenticated and
   authorized by default, with any public one a deliberate, marked exception?

3. **Client trust** — Are all prices, roles, permissions, and gates enforced on
   the server? No secret or security decision shipped to the browser?

4. **Injection** — Is all SQL/shell/HTML/path/URL construction parameterized,
   escaped, or allow-listed — no string-built queries, `innerHTML`, or `shell=True`
   on user input?

5. **Validation** — Does every request body/query pass through a schema with
   field allow-listing and size/length/range bounds (no `data: req.body`)?

6. **Untrusted I/O** — Are webhooks signature-verified, sensitive routes
   rate-limited, and server-side fetches of user URLs SSRF-guarded?

7. **Leakage** — Errors generic to clients, no secrets/PII in logs or responses,
   CORS an allow-list, security headers set, responses free of extra DB fields?

If the app is running locally and the user wants proof rather than a checklist,
escalate to the **hack-me** workflow (`commands/hack-me.md`).
