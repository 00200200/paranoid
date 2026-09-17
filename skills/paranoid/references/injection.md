# Injection, SSRF & untrusted input

The unifying rule: **never mix untrusted data into a command language by
concatenation.** SQL, shell, HTML, file paths, and URLs are all languages an
attacker can escape out of if you build strings. Use the structured API instead.

## SQL injection

```js
// ✗
db.query(`SELECT * FROM users WHERE email = '${email}'`);
db.query("... WHERE id = " + id);
// ✓ parameterized
db.query('SELECT * FROM users WHERE email = $1', [email]);        // pg
db.execute('SELECT * FROM users WHERE email = ?', [email]);        // mysql2
```

```python
cur.execute("SELECT * FROM users WHERE email = %s", (email,))      # ✓
cur.execute(f"SELECT * FROM users WHERE email = '{email}'")        # ✗
```

- ORMs (Prisma, Drizzle, SQLAlchemy, ActiveRecord) parameterize for you —
  **until** you drop to `$queryRawUnsafe`, `.raw()`, `text()` with an f-string,
  or `find_by_sql`. Those re-open the door; parameterize there too.
- Column/table names can't be parameterized — allow-list them against a fixed set,
  never interpolate user input into identifiers.

## Command injection

```js
// ✗ user input in a shell string
exec(`convert ${req.file.path} out.png`);
// ✓ no shell, argv array
execFile('convert', [req.file.path, 'out.png']);
```

```python
subprocess.run(["convert", path, "out.png"])        # ✓ list, no shell
subprocess.run(f"convert {path} out.png", shell=True) # ✗
```

- Avoid `shell=True` / the string form of `exec`. Pass an argv array so the OS
  never re-parses metacharacters (`; | & $() ` `` ` ``).
- `eval`, `Function()`, `exec()`, `pickle.loads`, `yaml.load` (use `safe_load`),
  and unbounded template engines are all code-execution sinks — never on user input.

## XSS

```jsx
// ✗
<div dangerouslySetInnerHTML={{ __html: comment }} />
element.innerHTML = comment;   // vanilla
<div v-html="comment" />       // vue
// ✓
<div>{comment}</div>           // React auto-escapes
element.textContent = comment;
```

- Default to text rendering; frameworks escape `{expr}` for you — the danger is
  the explicit "raw HTML" escape hatch.
- If you genuinely must render user HTML (rich text), sanitize with **DOMPurify**
  (client) or a server sanitizer — allow-list tags/attributes, never a blocklist.
- Also escape in non-HTML sinks: attribute values, `href`/`src` (block
  `javascript:`), inline `<script>` JSON (use `JSON.stringify` + escape `<`).
- Defense in depth: a `Content-Security-Policy` that forbids inline script turns
  many XSS bugs into non-events.

## Path traversal

```js
// ✗ ../../../etc/passwd
fs.readFile(path.join(UPLOAD_DIR, req.query.name));
// ✓ strip directory components, then confirm containment
const name = path.basename(req.query.name);
const full = path.resolve(UPLOAD_DIR, name);
if (!full.startsWith(path.resolve(UPLOAD_DIR) + path.sep)) throw new Error('bad path');
```

- `path.basename` drops `../`; the `startsWith(resolvedDir)` check catches the
  rest (symlinks, absolute paths). Never serve files by a raw client path.
- For uploads: allow-list extensions/MIME, generate your own filename, store
  outside the web root, and cap the size.

## Mass assignment

```js
// ✗ user can set role, credits, userId…
await db.user.update({ where: { id }, data: req.body });
// ✓ parse + allow-list
const { name, bio } = updateSchema.parse(req.body);
await db.user.update({ where: { id }, data: { name, bio } });
```

Validate every request body through a schema (zod, pydantic, valibot) at the
edge. It gives you allow-listing, type coercion, and length/format bounds in one
move — and rejects the 10 MB blob and the negative id for free.

## SSRF (server-side request forgery)

When the server fetches a URL the user supplied (link previews, webhooks
"test", image import, PDF render):

```js
const url = new URL(input);
if (!['http:', 'https:'].includes(url.protocol)) throw new Error('scheme');
// resolve DNS and reject private / link-local / loopback targets
const { address } = await dns.lookup(url.hostname);
if (isPrivate(address)) throw new Error('blocked host'); // 10/8,172.16/12,192.168/16,127/8,169.254/16,100.64/10,::1,fc00::/7
const res = await fetch(url, { redirect: 'manual' });    // don't auto-follow to an internal 302
```

- The prize is usually cloud metadata (`169.254.169.254`) or internal admin
  services. Block by resolved IP, not by hostname string (DNS rebinding).
- Allow-list hosts if you can (you rarely need to fetch *arbitrary* URLs).
- Disable auto-redirects, or re-validate the target on each hop.

## Deserialization & other sinks

Untrusted input into `pickle`, Java/Ruby native deserialization, `yaml.load`,
XML parsers with external entities (XXE), or regexes built from user input
(ReDoS) are all injection cousins. Same rule: parse with a safe, structured
loader; never let input choose what code runs.
