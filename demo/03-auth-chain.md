# 03 — Full auth chain: Authentik (authn) → OPA (authz) → backends

Demonstrates the north-south zero-trust chain. Runs in the **browser on
your host** (the OIDC login dance can't be scripted meaningfully); the
unauthenticated part is scriptable with curl.

Request path per hit on `http://localhost:8080`:

```
browser → Caddy (vm1:8080)
        → Authentik forward-auth (vm1:9000)   who are you?   fail → 302 to login
        → authz-shim → OPA (vm2:8288→8181)    allowed?       fail → 403
        → reverse_proxy mTLS → vm5:8090 / vm6:8091 / vm4:3000
```

## Prereqs

Authentik manual setup from the README done: proxy provider `grafana-proxy`,
application `Grafana` assigned to the embedded outpost, groups `viewers`,
users `viewer1` (in `viewers`) and `stranger1` (no groups), passwords =
username. The bootstrap admin `admin@testzero.local` / `admin` is in
`authentik Admins`.

## Part A — unauthenticated (scriptable, run on host)

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8080/           # → 200  (public landing, vm5)
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8080/dashboard  # → 302  (authn redirect)
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8080/api/status # → 302
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8080/grafana/   # → 302
```

Expected: landing 200 (anonymous zone never touches OPA), everything else 302. **No authz decision lines appear** for these — they die at the
Authentik hop. (6+ rapid hits trip CrowdSec http-probing — demo 07.)

## Part B — authenticated matrix (browser)

Log in at `http://localhost:9000` as each user, then visit the paths
through `http://localhost:8080`. Log out (or incognito) between users.

| Path                         | stranger1 (no groups) | viewer1              | admin            |
| ---------------------------- | --------------------- | -------------------- | ---------------- |
| `/`                          | 200 (anonymous)       | 200                  | 200              |
| `/dashboard`                 | **403** (authz deny)  | 200 + vm6 status box | 200              |
| `/api/status`                | 403                   | 200 JSON             | 200 JSON         |
| POST `/api/echo` (form/curl) | 403                   | 200 JSON echo        | 200 JSON echo    |
| POST `/anything-else`        | 403                   | **403** (path rule)  | 200/404 from app |
| `/grafana/`                  | 403                   | 200 (Viewer role)    | 200 (Admin)      |

Expected behaviour per role:

- **stranger1** authenticates fine (Authentik accepts, password works)
  but OPA denies every protected path → Caddy 403. This is
  _authenticated ≠ authorized_: fail at layer 2, not layer 1.
- **viewer1** browses everything (GET rule) and may POST only under
  `/api`, `/dashboard`, `/grafana` (demo 02 showed the same decisions at
  the OPA REST level).
- **admin** hits the `authentik Admins` catch-all rule.

The `/dashboard` page on vm5 shows the **identity headers** Caddy
injected (user/groups/email) plus the result of vm5's **east-west**
server-side call `web → vm6:8091/status` with its own mTLS client cert —
a second, independent identity layer (demo 04 covers it).

## What to watch (while clicking through)

```bash
# vm2 — one JSON line per decision, the audit trail shipped to Loki:
tailscale ssh user@vm2 -- journalctl -u authz-shim -f
# → {"event":"authz","user":"stranger1","groups":[],"method":"GET","path":"/dashboard","decision":"deny"}

# vm6 — east-west callers arriving from vm5/Caddy with workload CNs:
tailscale ssh user@vm6 -- journalctl -u testzero-api -f
# → workload=svc:vm5-web ... / workload=svc:caddy ...

# vm5 — the dashboard's server-side API call:
tailscale ssh user@vm5 -- journalctl -u testzero-web -f
```

Grafana `:8080/grafana/` → "Authz Decisions (OPA)" dashboard plots
allow/deny over time from those same lines (Loki `job="authz"`).

## Optional — fill the deny graph without logging in/out

From **vm1** (the shim trusts only `tag:identity` sources), imitate
Caddy's subrequests:

```fish
# NOTE: no spaces inside header values — tailscale ssh re-joins args
# with spaces through a remote shell; quoted words would be split.
for i in (seq 5)
    tailscale ssh user@vm1 -- curl -s -o /dev/null vm2:8288/ \
        -H X-Authentik-Username:viewer1 -H X-Authentik-Groups:viewers \
        -H X-Forwarded-Method:GET -H X-Forwarded-Uri:/dashboard
    tailscale ssh user@vm1 -- curl -s -o /dev/null vm2:8288/ \
        -H X-Authentik-Username:stranger1 -H X-Authentik-Groups:[] \
        -H X-Forwarded-Method:GET -H X-Forwarded-Uri:/dashboard
end
# dashboard should show 5 allows (200) + 5 denies (403)
```

Verified live: `stranger1 → 403` with shim log
`{"decision":"deny",…,"user":"stranger1","path":"/dashboard"}` and
`viewer1 → 200` with `{"decision":"allow",…}`.

## Optional — fail-closed proof

```bash
echo pass | tailscale ssh user@vm2 -- sudo -S systemctl stop opa
# browse /dashboard as viewer1 → 403 (shim can't reach OPA → deny-all)
echo pass | tailscale ssh user@vm2 -- sudo -S systemctl start opa
# recovers. vm6 behaves the same for workload authz (demo 04).
```
