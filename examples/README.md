# Examples — `/hack-me`, proven

Three worked runs of the `/hack-me` loop (find → prove → patch → re-verify), from
easiest-to-trust to hardest:

| Example | Target | Why it's here | Findings |
|---------|--------|---------------|:--:|
| [`ledgerlite`](ledgerlite) | our own tiny invoicing API | proves the **loop** works end-to-end, with before/after source | 4 fixed |
| [`vampi`](vampi) | [OWASP VAmPI](https://github.com/erev0s/VAmPI) — a third-party vulnerable API | proves it works on an app **we didn't write**, with live receipts | 6 fixed |
| [`dvwa`](dvwa) | [DVWA](https://github.com/digininja/DVWA) — a third-party vulnerable **web app** (PHP/MariaDB) | second independent-app proof; a different stack and request shape (forms, cookies, redirects) than the API targets | 6 fixed |

Each folder has a `HACKME_REPORT.md` with the exact exploit request, the response
that proves it, the fix, and the re-verification of the same request.

Same guardrails throughout: your own / authorized target, localhost only,
non-destructive proofs. Point `/hack-me` (see [`../commands/hack-me.md`](../commands/hack-me.md))
at *your* app for your own results.
