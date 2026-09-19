# APIs, webhooks & responses

The edge of your app: routes, the webhooks you receive, and what you send back.

## Deny by default

Every route is authenticated and authorized unless you consciously make it
public. Structure this so "public" is the annotated exception, not the silent
default you forgot to change.

```ts
// ✓ one wrapper, applied everywhere; public routes are explicit
const requireAuth = (h) => async (req, res) => {
  const s = await getSession(req);
  if (!s) return res.sendStatus(401);
  req.user = s.user;
  return h(req, res);
};

app.get('/api/health', publicRoute(handler));      // explicitly public
app.get('/api/orders', requireAuth(listOrders));    // default
```

- Don't rely on a route being "internal" or unguessable. If it's reachable, it's
  reached. Admin endpoints especially.
- Middleware order matters: auth must run **before** the handler, and a catch-all
  shouldn't accidentally bypass it. In Next.js, remember route handlers and
  server actions are each independently reachable — protect the data layer, not
  just the page.
- Return `401` for "not logged in", `403` for "logged in but not allowed",
  `404` to hide existence on ownership misses.

## Input validation at the edge

Parse every body/query/param through a schema before use (see mass assignment in
`injection.md`). Enforce bounds: max length on strings, ranges on numbers,
max size on the request body, max items on arrays. Unbounded input is how you get
both injection and denial-of-service.

## Rate limiting sensitive routes

Login, signup, password reset, OTP, and anything expensive needs a throttle —
otherwise: credential stuffing, user enumeration, and cost/DoS.

```ts
import rateLimit from 'express-rate-limit';
app.use('/api/auth', rateLimit({ windowMs: 60_000, max: 10 }));
```

- Key by IP **and** account where you can; lock/back off after repeated failures.
- Make auth responses uniform and constant-ish time so they don't reveal whether
  an account exists ("invalid email or password", never "no such user").

## Webhooks: verify before you trust

An unverified webhook is an unauthenticated POST that mutates your data. Anyone
can send `{"type":"payment_succeeded"}`. Verify the provider's signature against
the **raw** body (not the parsed/re-serialized JSON — re-serializing breaks the
signature):

```ts
// Stripe — needs the raw body
app.post('/webhooks/stripe',
  express.raw({ type: 'application/json' }),
  (req, res) => {
    let event;
    try {
      event = stripe.webhooks.constructEvent(
        req.body, req.headers['stripe-signature'], process.env.STRIPE_WEBHOOK_SECRET);
    } catch {
      return res.sendStatus(400); // bad/forged signature
    }
    // event is trustworthy from here
  });
```

- GitHub: HMAC-SHA256 over the raw body with your secret, compared to
  `X-Hub-Signature-256` using a **constant-time** compare (`crypto.timingSafeEqual`).
- The usual skip: `JSON.parse(req.body)` and credit the customer with no HMAC
  check. A forged `payment.succeeded` then lands as an unauthenticated POST.
  Verify first (constant-time, against the raw bytes), parse after.
- Guard against replay: honor timestamps/tolerances and treat delivery ids as
  idempotency keys so a re-sent event isn't processed twice.

## Responses, errors, logs, CORS, headers

- **Errors:** generic message + a correlation id to the client; the stack trace
  and SQL error go to your server logs only. Never `res.send(err)` /
  `err.stack` / raw DB errors to the client.
- **Logs:** no passwords, tokens, full card numbers, or PII. Redact before
  logging; assume logs are less protected than your database.
- **CORS:** an allow-list of known origins. Never reflect an arbitrary `Origin`
  with `Access-Control-Allow-Credentials: true` — that's an open door with the
  user's cookies. `*` is only acceptable for truly public, credential-less APIs.
- **Headers:** set the standard set (via `helmet` or equivalent):
  `Content-Security-Policy`, `Strict-Transport-Security`,
  `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` (or CSP
  `frame-ancestors`), `Referrer-Policy`. HTTPS everywhere; cookies `Secure`.
- **Data shape:** return only the fields the client needs. Serializing a whole
  DB row leaks `passwordHash`, internal flags, other users' data — select
  explicitly or use a response DTO.
