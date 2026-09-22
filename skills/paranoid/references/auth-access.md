# Auth & access control

Broken access control is #1 for a reason: the code looks correct, the tests pass,
the happy path works — and any user can read any other user's data. Authentication
("who are you") is not authorization ("may you touch *this*"). You need both.

## Ownership on every object lookup

Every read/write keyed on a client-supplied id must be scoped to the caller.

```ts
// ✗ authenticated but not authorized
const doc = await db.document.findUnique({ where: { id } });

// ✓ ownership is part of the query
const doc = await db.document.findFirst({ where: { id, ownerId: req.user.id } });
if (!doc) return res.sendStatus(404); // 404, not 403 — don't confirm it exists
```

For shared resources, check membership rather than a single owner:

```ts
const member = await db.membership.findFirst({
  where: { projectId, userId: req.user.id },
});
if (!member) return res.sendStatus(404);
if (action === 'delete' && member.role !== 'owner') return res.sendStatus(403);
```

Rules of thumb:
- Put the caller's id **in the `where` clause**, not in an `if` after the fetch
  you might forget.
- Prefer `404` over `403` on ownership misses so you don't leak existence.
- Do the check server-side, every time — never rely on the client hiding a button.
- IDs that are enumerable (`1, 2, 3…`) make IDOR trivial; UUIDs help but are
  **not** an access control — still check ownership.
- Multi-route APIs: don't scope `GET /resource/:id` and forget mutations.
  `PATCH`, `PUT`, and `DELETE` must include the owner check in the mutation
  query (`where: { id, ownerId }`), not just rely on router-level authentication.

## Function-level authorization

Don't gate only by "is logged in." Gate by role/permission for the specific
action, on the server:

```ts
export const requireRole = (role) => (req, res, next) =>
  req.user?.roles?.includes(role) ? next() : res.sendStatus(403);

app.delete('/api/users/:id', auth, requireRole('admin'), handler);
```

Never trust a role sent by the client (`req.body.role`, a JWT claim the client
can set, a header). Roles come from your datastore, keyed on the authenticated
identity.

## Supabase (Row-Level Security)

The anon key is public **by design** — RLS policies are your access control. If
RLS is off, the table is world-readable/writable to anyone with the key (which
is in your client bundle).

```sql
alter table documents enable row level security;

-- deny by default, then grant precisely
create policy "owner reads" on documents
  for select using (auth.uid() = owner_id);
create policy "owner writes" on documents
  for insert with check (auth.uid() = owner_id);
create policy "owner updates" on documents
  for update using (auth.uid() = owner_id) with check (auth.uid() = owner_id);
```

- Enable RLS on **every** table holding real data; a table with RLS off and a
  policy defined is still open — the policy does nothing until RLS is enabled.
- The `service_role` key bypasses RLS. It is server-only. Never ship it to the
  browser, never put it behind a `NEXT_PUBLIC_`/`VITE_` prefix.
- `with check` guards writes; `using` guards reads/matches. You usually need both.

## Firebase rules

```
// ✗ the default that ends up in production
match /{document=**} { allow read, write: if true; }

// ✓ authenticated + ownership + validation
match /notes/{id} {
  allow read: if request.auth != null && resource.data.uid == request.auth.uid;
  allow create: if request.auth != null && request.resource.data.uid == request.auth.uid;
  allow update, delete: if request.auth != null && resource.data.uid == request.auth.uid;
}
```

Test rules in the emulator; a rule that fails closed is a bug you can see, a rule
that fails open is a breach you can't.

## Sessions & tokens (quick hits)

- Session cookies: `HttpOnly`, `Secure`, `SameSite=Lax` (or `Strict`).
- JWTs: verify signature **and** `exp`; pin the algorithm (reject `alg: none` /
  `None` / `NONE` and algorithm-confusion — match case-insensitively or allow-list
  the one alg you use). Don't store them in `localStorage` if a cookie will do.
- On logout / privilege change, invalidate server-side; a stateless JWT you can't
  revoke is a liability for sensitive apps.
- Password hashes: slow + salted (`bcrypt` / `argon2id` / `scrypt` / PBKDF2 with
  a per-row salt). Unsalted `md5`/`sha1`/`sha256` of the password is still weak —
  rainbow-tableable — even though it is not plaintext.
