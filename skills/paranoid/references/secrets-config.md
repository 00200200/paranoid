# Secrets, config & the client boundary

Two failure modes here: secrets that reach the browser, and security decisions
made on a device the user controls. Both come from forgetting that **everything
shipped to the client is public** — bundles are readable, requests are editable,
`localStorage` is inspectable.

## Secrets live server-side, in env, never in code

```ts
// ✗
const stripe = new Stripe('sk_live_51J...');
// ✓
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);
```

- Never hardcode keys, tokens, or connection strings. Read from `process.env` /
  `os.environ` and fail loudly at boot if a required one is missing.
- `.env` is **git-ignored**; commit a `.env.example` with empty values instead.
- If a secret was ever committed, it is compromised — rotate it. Removing it in a
  later commit does not help; it's in history. Say this to the user plainly.
- Never put a secret in an error message, an API response, or a log line.

### The client-env-prefix trap

Bundlers inline any variable with a public prefix into the browser bundle:

- Next.js: `NEXT_PUBLIC_*`
- Vite: `VITE_*`
- Create React App: `REACT_APP_*`
- Expo: `EXPO_PUBLIC_*`

A `NEXT_PUBLIC_STRIPE_SECRET_KEY` is a public secret — a contradiction that ships
constantly. Only publishable/anon keys belong under these prefixes. When you add
one, ask: "is it fine for this to be in HTML anyone can view?" If not, it's a
server variable and the code that uses it must run on the server.

### The other direction: don't strip the keys that are meant to ship

This is the failure mode of being *too* careful, and it is measured, not
hypothetical: in this project's own benchmark, the one functional test the
paranoid condition failed (and the baseline passed) was a client-config task
where it dropped `STRIPE_PUBLISHABLE_KEY` along with the real secrets. The
guidance above, followed without this counterweight, filters until the feature
breaks. A security fix that breaks payments is not a fix.

Some credentials are **designed** to be public and are load-bearing in the
browser. Removing them doesn't harden anything — it just breaks checkout, auth,
maps, or analytics:

| Meant to ship | Never ships |
|---|---|
| Stripe **publishable** key (`pk_live_…`, `pk_test_…`) | Stripe secret key (`sk_live_…`) |
| Supabase **anon** key | Supabase `service_role` key |
| Firebase web config, including `apiKey` | Firebase Admin SDK service-account JSON |
| Sentry/PostHog **public DSN** or project key | Sentry auth token |
| Google Maps **browser** key (restrict by referrer) | Google service-account key |
| Algolia **search-only** key | Algolia admin key |

The rule: **decide by what the credential is, not by what its name looks like.**
`SECRET`, `KEY` and `TOKEN` in a variable name are a prompt to check, not a
verdict — `STRIPE_PUBLISHABLE_KEY` and `SESSION_SECRET` both contain one of
those words and belong on opposite sides of the boundary. If you can't tell what
a credential is, say so and ask, rather than silently dropping it.

Firebase's `apiKey` is the classic confusion: it is an identifier, not an
authenticator, and Firebase documents it as public. Access is controlled by
security rules, so removing the key breaks the app without securing anything.

## The client enforces nothing

Anything the client sends can be forged with curl. So:

- **Prices, totals, discounts:** the server derives them from ids, never accepts
  amounts from the body.
- **Roles / permissions / `isAdmin`:** read from your datastore by authenticated
  identity, never from the request.
- **Quotas, limits, feature gates:** re-checked server-side even if the UI hides
  the control.
- **Validation:** client-side validation is UX; the server validates again
  because the client can be bypassed entirely.

```ts
// ✗ trusting the client's claim
if (req.body.isPremium) unlock(feature);
// ✓ server is the source of truth
const user = await db.user.findUnique({ where: { id: req.user.id } });
if (user.plan === 'premium') unlock(feature);
```

A useful mental test: **"If the attacker writes the client, does this still
hold?"** If not, move the check to the server.

## Config hygiene

- Separate keys per environment (dev/staging/prod); a leaked dev key shouldn't
  touch prod data.
- Least privilege on the key itself — a read-only key for a read-only job beats a
  god key everywhere.
- Scan before you push: `git secrets`, `gitleaks`, or `trufflehog` in a
  pre-commit hook catches the accident before it's permanent.
- Debug/verbose flags off in production — they turn into #10 (verbose errors).
