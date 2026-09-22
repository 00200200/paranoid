# DVWA — independent-app proof (second app)

A localhost `/hack-me` run against [DVWA](https://github.com/digininja/DVWA)
("Damn Vulnerable Web Application"), a well-known third-party
intentionally-vulnerable PHP/MariaDB app — the project's **second**
independent-app proof, alongside [`vampi`](../vampi) (an API target). This one
is a classic server-rendered web app stack, so it exercises `/hack-me` against
form posts, cookies, and `Location` headers rather than a JSON API.

## Files

- **`HACKME_REPORT.md`** — the report: every finding with the exact exploit
  request, the response proving it, the fix, and the re-verification of the
  same request.
- **`patches/`** — the six patched source files as applied (Low security level),
  named after their path in the DVWA repo, so the fix can be diffed against the
  upstream file without cloning DVWA.

## Reproduce

```bash
git clone https://github.com/digininja/DVWA && cd DVWA
cp config/config.inc.php.dist config/config.inc.php
# uncomment the "volumes: - ./:/var/www/html" lines in compose.yml to serve
# local source (needed so the /hack-me patch step can edit real files)
docker compose up -d                       # http://127.0.0.1:4280
# visit /setup.php once to create the DB, log in admin / password,
# then Settings → DVWA Security → Low
```

Point `/hack-me` (see [`../../commands/hack-me.md`](../../commands/hack-me.md))
at `http://127.0.0.1:4280` with the seeded `admin` / `password` account. Six
vulnerabilities found, proven, patched, and re-verified — see the report.

Same guardrails as always: your own / authorized target, localhost only,
non-destructive proofs.
