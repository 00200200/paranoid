# /hack-me framework guides

Where routes and auth live in the common stacks, how to run the app locally, and
what to probe first. Use this in the **Map** and **Prioritize** steps of
[`/hack-me`](../../../commands/hack-me.md). The proof recipes are the same across
frameworks — these guides just tell you where to look and how to talk to the app.

For every stack the priority order is the same: **broken access control / IDOR →
missing auth → injection → mass assignment → SSRF → info leaks.** Below is where
each tends to hide per framework.

---

## Next.js (App Router / Pages Router)

**Where routes live**
- App Router: `app/**/route.ts` (Route Handlers) and `app/**/actions.ts` /
  `"use server"` functions (Server Actions). Each is *independently reachable* —
  a Server Action is a POST endpoint even if no button calls it.
- Pages Router: `pages/api/**/*.ts`.
- Middleware: `middleware.ts` runs at the edge; auth there does **not** cover
  Server Actions or the data layer automatically.

**Where auth should be**
- In the handler/action itself (or a wrapper it calls), re-checking the session
  server-side. `getServerSession` / `auth()` from NextAuth, Clerk's `auth()`,
  or a manual cookie/JWT check. Treat any check that only happens in a Client
  Component or in `middleware.ts` as *absent* for data endpoints.

**Run it**
- `npm run dev` (default `http://localhost:3000`). Note the actual port from the
  console; `next dev -p <port>` changes it.

**Probe first**
- Call `route.ts` handlers directly with `curl` (no cookies) — many assume "the
  UI is the only caller." → missing auth.
- Server Actions: replay the POST the form makes, tampering ids and role/price
  fields in the body → IDOR / mass assignment.
- `NEXT_PUBLIC_*` env vars in the client bundle → leaked secrets (grep the
  built JS / `.env`).
- Any "fetch a URL" API route (og-image, link preview, proxy) → SSRF.

---

## FastAPI (Python)

**Where routes live**
- `@app.get(...)` / `@app.post(...)` / `APIRouter` decorators, usually under
  `app/`, `routers/`, or `api/`. `app.include_router(...)` wires them up.
- Interactive route map for free: open `http://localhost:8000/docs` (Swagger) or
  `/openapi.json` — it enumerates every path and its params.

**Where auth should be**
- FastAPI dependencies: `Depends(get_current_user)` on the route or router.
  A route with **no** `Depends` guarding identity is public. Check that the
  dependency actually *authorizes* (ownership/role), not just authenticates.
- Ownership must be in the query (`WHERE owner_id == current_user.id`), not an
  `if` you can forget.

**Run it**
- `uvicorn app.main:app --reload` (default `http://127.0.0.1:8000`), or
  `fastapi dev`. Confirm the port from the console.

**Probe first**
- Pull `/openapi.json`, then hit each path with no `Authorization` header →
  missing auth.
- Endpoints taking a path/query id (`/items/{id}`) as another user → IDOR.
- Pydantic models that accept extra fields, or `Model(**body)` /
  `.dict()`-into-update patterns → mass assignment (watch for `model_config`
  without `extra="forbid"`).
- Raw SQL via `text("... %s" % x)` or f-strings in SQLAlchemy → SQLi.

---

## Express (Node.js)

**Where routes live**
- `app.get/post(...)`, `router.<verb>(...)` across `routes/`, `controllers/`,
  or a single `server.js`/`index.js`. Middleware chains matter: the order of
  `app.use(...)` decides whether auth runs before a handler.

**Where auth should be**
- An auth middleware (`requireAuth`, `passport.authenticate`, a JWT verifier)
  applied to the route or router. A handler registered *before* the auth
  `app.use`, or on a router that never mounts it, is public.
- After auth, look for the authorization gap: `req.user` exists but the DB query
  doesn't scope to `req.user.id`.

**Run it**
- `npm start` / `npm run dev` / `node server.js`. Port is usually
  `process.env.PORT || 3000` — read it from the console.

**Probe first**
- Hit each route with no cookie/token → missing auth; then as the wrong user
  with someone else's id → IDOR.
- `data: req.body`, `Object.assign(row, req.body)`, `...req.body` into an
  update → mass assignment (try smuggling `role`/`isAdmin`).
- `db.query(\`... ${x}\`)`, `.raw()`, or `child_process.exec(\`... ${x}\`)` →
  SQL / command injection.
- `res.send(err)` / stack traces to the client, and `cors({ origin: true,
  credentials: true })` → info leak / permissive CORS.

---

## Any stack — the constants

- **Base URL + two accounts.** Get the real port from the run console; ask for an
  attacker and a victim test account (local dev login only).
- **Enumerate before probing.** A route list (source grep, `/docs`,
  `/openapi.json`, the router file) turns guessing into checking.
- **One class at a time**, minimal request, real request/response as proof, then
  patch the root cause and replay the exact request to confirm it now fails.
