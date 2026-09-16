# /hack-me framework guides

Where routes and auth live in the common stacks, how to run the app locally, and
what to probe first. Use this in the **Map** and **Prioritize** steps of
[`/hack-me`](../../../commands/hack-me.md). The proof recipes are the same across
frameworks — these guides just tell you where to look and how to talk to the app.

Covered here: **Next.js, FastAPI, Express, Django, Ruby on Rails, Flask, Spring
Boot, Go.**

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

## Django (Python)

**Where routes live**
- `urls.py` (`urlpatterns`) maps paths to views in `views.py` or DRF
  `ViewSet`s/`APIView`s under an app dir. `django-admin` mounts `/admin/`.

**Where auth should be**
- `@login_required` / `LoginRequiredMixin` for authentication; **object**
  permissions are the gap — a `get_object_or_404(Model, pk=...)` with no owner
  filter is IDOR. Scope querysets: `Model.objects.filter(owner=request.user)`.
- DRF: `permission_classes` on the view, plus `get_queryset()` scoped to
  `self.request.user`. `AllowAny` is an explicit decision, not a default.

**Run it**
- `python manage.py runserver` (default `http://127.0.0.1:8000`).

**Probe first**
- Detail/edit/delete views taking a `pk`/`slug`, requested as another user → IDOR.
- `ModelForm`/serializer with `fields = '__all__'` → mass assignment (can set
  `is_staff`/`is_superuser`/FK owner). Serializers should list fields explicitly
  and mark server-owned ones `read_only`.
- `.raw()` / `.extra()` / `cursor.execute(f"...")` → SQLi.
- `mark_safe(...)` / `|safe` / `format_html` with user data → XSS.
- `DEBUG = True` reachable → stack traces + settings leak.

## Ruby on Rails

**Where routes live**
- `config/routes.rb` (`resources :things`) → `app/controllers/*_controller.rb`
  actions. `rails routes` prints the full map.

**Where auth should be**
- A `before_action :authenticate_user!` (Devise) for authn; authorization is the
  classic Rails gap — scope through the association:
  `current_user.things.find(params[:id])`, not `Thing.find(params[:id])`.
- Strong parameters are the mass-assignment guard:
  `params.require(:thing).permit(:title, :body)` — never `permit!`.

**Run it**
- `bin/rails server` (default `http://localhost:3000`).

**Probe first**
- `Model.find(params[:id])` without `current_user` scope → IDOR.
- `permit!` or a permit list that includes `role`/`admin`/`user_id` → mass
  assignment / privilege escalation.
- `where("name = '#{params[:q]}'")` / string-interpolated SQL → SQLi.
- `html_safe` / `raw()` on user input → XSS.
- Missing `authenticate_user!` on an admin/namespaced controller → missing auth.

## Flask (Python)

**Where routes live**
- `@app.route(...)` / `@bp.route(...)` decorators across `app.py`, a `views.py`,
  or blueprints registered with `app.register_blueprint(...)`.

**Where auth should be**
- A decorator (`@login_required` from Flask-Login, or a hand-rolled
  `before_request`) — Flask ships with **nothing** on by default, so a route
  with no decorator is fully public. Ownership is manual: scope every query to
  `current_user`, don't just check `current_user.is_authenticated`.

**Run it**
- `flask run` or `python app.py` (default `http://127.0.0.1:5000`; watch for
  `debug=True`, which serves the interactive Werkzeug console — see VAmPI in
  [`../../../examples/vampi`](../../../examples/vampi)).

**Probe first**
- Routes taking an id from the URL/args with no owner check → IDOR; unauthenticated
  → missing auth.
- `db.session.execute(text(f"... {x}"))` / string-built SQL → SQLi.
- `render_template_string(user_input)` or `Template(user_input)` → SSTI; user data
  in `{{ ... | safe }}` → XSS.
- `subprocess.run(cmd, shell=True)` with user input → command injection.
- A debug/admin route that dumps data with no `is_admin` check → broken function
  auth (this is exactly VAmPI Finding 1).

## Spring Boot (Java / Kotlin)

**Where routes live**
- `@RestController` / `@Controller` classes with `@GetMapping` / `@PostMapping`
  (etc.) methods, usually under a `controller`/`web` package.

**Where auth should be**
- Spring Security: an `HttpSecurity` config (`SecurityFilterChain`) plus
  method-level `@PreAuthorize("hasRole('ADMIN')")` / `@PreAuthorize("#id == principal.id")`.
  A `permitAll()` that's too broad, or a controller with no method security, is the
  gap. Object ownership belongs in the query or a `@PreAuthorize` SpEL check.

**Run it**
- `./mvnw spring-boot:run` or `./gradlew bootRun` (default `http://localhost:8080`).

**Probe first**
- Endpoints with a path variable id and no `@PreAuthorize`/owner check → IDOR;
  actuator or admin paths reachable → missing/again function auth.
- `entityManager.createQuery("... " + x)` / string-concatenated JPQL/SQL → SQLi
  (use bound parameters / criteria API).
- Binding the request body straight onto a JPA entity (`@ModelAttribute` /
  `@RequestBody Entity`) → mass assignment; use a DTO with explicit fields.
- Thymeleaf `[(${...})]` / `th:utext` with user data → XSS.
- Exposed Spring Boot Actuator (`/actuator/env`, `/actuator/heapdump`) → secrets
  leak.

## Go (net/http, chi, gin, echo)

**Where routes live**
- `http.HandleFunc` / `mux.HandleFunc`, or a router (`chi`, `gin`, `echo`)
  registering handlers, usually in `main.go` or a `handlers/` package.

**Where auth should be**
- Middleware wrapping the mux/router that populates a user into the request
  `context.Context`; handlers read `r.Context()`. A handler registered outside
  the authed middleware chain is public.
- Ownership: put the user id in the query
  (`WHERE id = $1 AND owner_id = $2`), not an `if` after the row loads.

**Run it**
- `go run .` / `go run ./cmd/server`. Port is usually a flag or
  `os.Getenv("PORT")` — read the startup log.

**Probe first**
- Handlers reading `chi.URLParam(r,"id")` / `r.PathValue("id")` with no owner
  check → IDOR; call them unauthenticated → missing auth.
- `db.Query(fmt.Sprintf("... %s", x))` → SQLi (use `db.Query("... $1", x)` /
  placeholders).
- `exec.Command("sh","-c", userStr)` → command injection (pass args, not a shell
  string).
- `text/template` (instead of `html/template`) rendering to HTML → XSS.
- `json.Unmarshal` into a struct with server-owned fields that the client can set
  → mass assignment.

## Any stack — the constants

- **Base URL + two accounts.** Get the real port from the run console; ask for an
  attacker and a victim test account (local dev login only).
- **Enumerate before probing.** A route list (source grep, `/docs`,
  `/openapi.json`, the router file) turns guessing into checking.
- **One class at a time**, minimal request, real request/response as proof, then
  patch the root cause and replay the exact request to confirm it now fails.
