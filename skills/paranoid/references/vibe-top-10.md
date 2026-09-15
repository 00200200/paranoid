# The vibe-coded top 10

The vulnerability classes that AI-generated and "vibe-coded" apps actually ship,
ranked by how often they show up. Each entry: **what the agent does wrong**, how
to **spot** it, and the **fix pattern**. This is the map — the four topic files
(`auth-access`, `secrets-config`, `injection`, `apis-webhooks`) hold the detail.

---

### 1. Broken access control / IDOR

The single most common one. The endpoint authenticates the user ("are you logged
in?") but never authorizes the *object* ("is this row yours?").

```js
// ✗ any logged-in user can read any invoice
app.get('/api/invoices/:id', auth, async (req, res) => {
  const inv = await db.invoice.findUnique({ where: { id: req.params.id } });
  res.json(inv);
});
// ✓ scope every lookup to the caller
const inv = await db.invoice.findFirst({
  where: { id: req.params.id, userId: req.user.id },
});
if (!inv) return res.sendStatus(404);
```

**Spot:** any query keyed on a client-supplied id without the caller's id in the
`where`. **Fix:** ownership in the query itself, `404` (not `403`) on miss.
→ `auth-access.md`

### 2. Missing authentication on endpoints

New route ships with no auth because "the frontend never calls it that way."
Attackers call it directly.

**Spot:** route/handler/server-action with no auth middleware or session check;
admin or internal routes guessable by name. **Fix:** deny by default — a shared
`requireAuth` wrapper, and public routes are the annotated exception.
→ `apis-webhooks.md`

### 3. Trusting the client

Permission checks, prices, roles, or feature gates enforced only in the browser;
the server accepts whatever arrives.

```js
// ✗ client sends the price
await charge(req.body.amountCents);
// ✓ server derives it
const price = await priceFor(req.body.sku);
```

**Spot:** `if (user.isAdmin)` in frontend code with no server twin; amounts,
roles, or `isAdmin` read from the request body. **Fix:** the server re-derives
and re-checks everything that matters. → `secrets-config.md`

### 4. Injection (SQL / command / XSS / path)

String-built queries and commands, unescaped HTML, user input in file paths.

```js
db.query(`SELECT * FROM users WHERE email = '${email}'`); // ✗ SQLi
db.query('SELECT * FROM users WHERE email = $1', [email]); // ✓
element.innerHTML = comment;                               // ✗ XSS
element.textContent = comment;                             // ✓
fs.readFile(`/data/${req.query.name}`);                    // ✗ ../../etc/passwd
```

**Spot:** template strings / `+` around SQL, shell, HTML, or paths; `innerHTML`,
`dangerouslySetInnerHTML`, `v-html`; `exec`/`eval` with dynamic input. **Fix:**
parameterize, use `textContent`, pass argv arrays not shell strings, allow-list
and `path.basename` file names. → `injection.md`

### 5. Insecure database / BaaS rules

Supabase table with RLS off; Firebase rules `allow read, write: if true`. The
API key is public by design, so the rules *are* the security — and they're open.

**Spot:** RLS disabled on a table with real data; any rule that resolves to
`true`; a service-role key used from the client. **Fix:** RLS on, deny by
default, policies scoped to `auth.uid()`. → `auth-access.md`

### 6. SSRF (server fetches a user-supplied URL)

Webhook testers, link previews, image proxies, "import from URL." The server
fetches attacker-controlled URLs and can be pointed at `169.254.169.254`
(cloud metadata) or internal services.

**Spot:** `fetch`/`axios`/`requests` where the URL comes from the user. **Fix:**
allow-list schemes and hosts, resolve DNS and block private/link-local ranges,
disable redirects to them. → `injection.md`

### 7. Leaked secrets

API keys hardcoded in source, `.env` committed, keys inlined into the client
bundle (`NEXT_PUBLIC_…`, `VITE_…`), or secrets echoed in error responses/logs.

**Spot:** high-entropy strings in source; `.env` tracked by git; secrets under a
client-exposed env prefix; keys in log lines. **Fix:** env only, server only,
rotate anything that was committed, `.gitignore` the env file.
→ `secrets-config.md`

### 8. Mass assignment / missing validation

The whole request body is trusted and spread into a DB update, letting a user
set fields they shouldn't (`role`, `isAdmin`, `credits`, `userId`).

```js
await db.user.update({ where: { id }, data: req.body }); // ✗ sets role too
```

**Spot:** `...req.body`, `Object.assign(record, req.body)`, `data: req.body`.
**Fix:** parse the body through a schema (zod/pydantic) and pass only the
allow-listed fields. → `injection.md`

### 9. Unverified webhooks & no rate limiting

Payment/CI webhooks whose signature is never checked (anyone can POST a fake
"payment succeeded"); auth and reset endpoints with no throttle (credential
stuffing, enumeration).

**Spot:** a webhook handler reading `req.body` with no signature verification;
login/OTP/reset routes with no rate limit. **Fix:** verify the provider
signature against the raw body; rate-limit sensitive routes.
→ `apis-webhooks.md`

### 10. Verbose errors, PII logs, permissive CORS

Stack traces and SQL errors returned to the client; emails/tokens written to
logs; `Access-Control-Allow-Origin: *` alongside credentials; missing security
headers.

**Spot:** `res.send(err)` / `err.stack` to client; PII in `console.log`; CORS
reflecting any origin with `credentials: true`. **Fix:** generic client errors +
server-side detail, redact logs, CORS allow-list, set the standard headers.
→ `apis-webhooks.md`

---

**Why these ten:** they line up with OWASP's top categories (broken access
control and injection lead there too), and with what security benchmarks find
LLMs produce — functionally correct backends that are still exploitable about
half the time. They are deliberately concrete: an agent can check for every one
of them mechanically.
