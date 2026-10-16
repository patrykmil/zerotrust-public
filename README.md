# TestZero

```
vm1  ── Authentik + Caddy + PostgreSQL + Redis + CrowdSec
vm2  ── OPA + authz-shim + step-ca + VictoriaMetrics
vm3  ── Zeek + Suricata + Grafana Alloy
vm4  ── Grafana + Loki
vm5  ── Web app + Tetragon + Alloy
vm6  ── Internal REST API (mTLS) + Tetragon + Alloy
```

## Quickstart

1. Generate a Tailscale auth key at https://login.tailscale.com/admin/settings/keys (reusable, NOT ephemeral) and put it into `variables/template.credentials.nix` and mv to `variables/credentials.nix`:

```nix
{
  tailscale = {
    authKey = "tskey-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
  };
}
```

2. Build and boot all six VMs (RAM budget: 4×4 GB + 2×2 GB):

```bash
# required nix+tailscale
nix run .#vm1
nix run .#vm2
nix run .#vm3
nix run .#vm4
nix run .#vm5
nix run .#vm6
# or
fish run.sh # required nix+tailscale+fish+wezterm
```

3. In the Tailscale admin console (https://login.tailscale.com):
   3a. Enable MagicDNS (DNS → Enable MagicDNS)
   3b. Paste tailscale/policy.hujson → Save
   3c. Machines → approve the SIX advertised tags if prompted
   (tag:identity, tag:policy, tag:sensor, tag:observe, tag:workload, tag:internal)
4. Open http://localhost:8080 in a browser → redirected to Authentik login at http://localhost:9000. Log in as admin@testzero.local / admin.
5. Follow the Authentik setup checklist below ("Manual Setup Steps").

## Manual Setup Steps

### Authentik (web UI at http://localhost:9000, admin@testzero.local / admin)

- [ ] **Create Proxy Provider** — Applications → Providers → Create
      (type: Proxy, mode: Forward auth (single application),
      Name: `grafana-proxy`, External host: `http://localhost:8080`)
- [ ] **Create Application** — Applications → Applications → Create
      (Name: `Grafana`, Slug: `grafana`, Provider: `grafana-proxy`)
- [ ] **Assign to Embedded Outpost** — Applications → Outposts → edit
      `authentik Embedded Outpost` → add `Grafana` → Update
- [ ] **Point the outpost at Authentik** — without this, login redirects go
      to bare `http://localhost/…` (dead port 80). One-shot via API
      (token from `variables/credentials.nix` → `authentik.bootstrapToken`):
      `bash
TOK="testzero-bootstrap-token"
UUID=$(curl -s -H "Authorization: Bearer $TOK" \
  http://localhost:9000/api/v3/outposts/instances/ \
  | jq -r '.results[] | select(.name=="authentik Embedded Outpost") | .pk')
CFG=$(curl -s -H "Authorization: Bearer $TOK" \
  http://localhost:9000/api/v3/outposts/instances/$UUID/ \
  | jq -c '.config | .authentik_host="http://localhost:9000"')
curl -s -X PATCH -H "Authorization: Bearer $TOK" \
  -H "Content-Type: application/json" \
  http://localhost:9000/api/v3/outposts/instances/$UUID/ \
  -d "{\"config\":$CFG}" | jq -r '.config.authentik_host'
`
      Verify: `curl -s -D - -o /dev/null http://localhost:8080/grafana/`
      must 302 to `http://localhost:9000/application/o/authorize/…`.
- [ ] **Create test viewer** — Directory → Groups → Create `viewers`;
      Directory → Users → Create `viewer1` → join to `viewers`
- [ ] **Create ungrouped user** — Directory → Users → Create `stranger1`
      (no groups)
- [ ] **Set passwords** — each user: edit → Set password = username
- [ ] **Test the zones** — browse with the three users:

      | Path                            | stranger1 (no groups) | viewer1         | akadmin     |
      | ------------------------------- | --------------------- | --------------- | ----------- |
      | `:8080/` (landing)              | 200 anonymous         | 200 anonymous   | 200 anon.   |
      | `:8080/dashboard`               | 403                   | 200             | 200         |
      | `:8080/api/status`              | 403                   | 200             | 200         |
      | POST `:8080/api/echo`           | 403                   | 200             | 200         |
      | POST `:8080/anything-else`      | 403                   | 403 (path rule) | 200         |
      | `:8080/grafana/`                | 403                   | 200 (Viewer)    | 200         |

## Tests

Tests in `demo/`

## Architecture

### Technology Stack

| Component           | What it does                                                                                                                          |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| **Tailscale**       | WireGuard-based mesh VPN; tag-scoped ACLs enforce mesh segmentation                                                                   |
| **Authentik**       | Identity provider — OIDC/OAuth2 SSO for all services                                                                                  |
| **Caddy**           | Access proxy — enforces authentication before proxying to upstream services                                                           |
| **Anubis**          | Bot detection (vm1)                                                                                                                   |
| **OPA**             | Policy engine — answers "is this request allowed?" for users AND workloads via Rego policies; API requires a bearer token (vm2)       |
| **authz-shim**      | Tiny Python bridge translating Caddy forward_auth to OPA queries (vm2)                                                                |
| **step-ca**         | workload-identity CA — issues 24h mTLS certs for svc:caddy, svc:vm5-web, svc:api-vm6; rotated every 6h (vm2)                          |
| **VictoriaMetrics** | Drop-in Prometheus-compatible metrics store, scrapes all services (vm2)                                                               |
| **vmalert**         | Evaluates alert rules against VictoriaMetrics, publishes ALERTS series (vm2)                                                          |
| **node-exporter**   | Prometheus agent exposing per-VM CPU/RAM/disk/systemd metrics (all VMs)                                                               |
| **PostgreSQL**      | Database backend for Authentik (vm1)                                                                                                  |
| **Redis**           | Cache and session backend for Authentik (vm1)                                                                                         |
| **Zeek**            | Network security monitor capturing traffic on the Tailscale interface (vm3)                                                           |
| **Suricata**        | Signature-based IDS on the same interface; alert-only EVE JSON; ET/Open + OISF TrafficID rules fetched by `suricata-update` (vm3)     |
| **Tetragon**        | eBPF runtime detection on the workload VMs — traces shell spawn and sensitive-file opens (vm5, vm6)                                   |
| **CrowdSec**        | Security engine on the gateway — detects SSH brute force + HTTP probing, enforces 30-min IP bans via firewall bouncer (vm1)           |
| **Vulnix**          | CVE scanner — daily scan of the system closure against the NVD feed; findings shipped to Loki, dashboard + alert on Grafana (all VMs) |
| **sbomnix**         | SBOM generator — weekly CycloneDX + SPDX bill of materials of the system closure in `/var/lib/sbom/` (all VMs)                        |
| **Grafana Alloy**   | Log shipper — tails Zeek + Suricata logs and forwards them to Loki (vm3)                                                              |
| **Loki**            | Log aggregation — stores and indexes all Zeek + Suricata logs (vm4)                                                                   |
| **Grafana**         | Visualization — dashboards for Zeek logs and metrics (vm4)                                                                            |

## Ports

### Host → VM Port Forwards

| Host Port | Target   | Service                                                 |
| --------- | -------- | ------------------------------------------------------- |
| 2201      | vm1:22   | SSH                                                     |
| 2202      | vm2:22   | SSH                                                     |
| 2203      | vm3:22   | SSH                                                     |
| 2204      | vm4:22   | SSH                                                     |
| 2205      | vm5:22   | SSH                                                     |
| 2206      | vm6:22   | SSH                                                     |
| 8080      | vm1:8080 | Caddy (protected — Authentik + OPA required)            |
| 8181      | vm2:8181 | OPA REST API (policy evaluation; bearer token required) |
| 8428      | vm2:8428 | VictoriaMetrics (PromQL API + UI)                       |
| 8880      | vm2:8880 | vmalert (alert state API + UI)                          |
| 9000      | vm1:9000 | Authentik web UI                                        |

### VM Internal Ports

Services listen on `0.0.0.0` where noted; the VM firewall (`networking.firewall`)
restricts reachability as shown below. `tailnet-only` = the port is opened only
on the `tailscale0` interface.

| VM  | Ports                                                                                                                                                                                                                                                         |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| vm1 | 22 (SSH), 5432 (PostgreSQL, loopback), 6379 (Redis, loopback), 9000 (Authentik), 8080 (Caddy), **8081** (CrowdSec LAPI, loopback) — **9300** (Authentik metrics, tailnet-only), **6060** (CrowdSec metrics, tailnet-only), 9100 (node-exporter, tailnet-only) |
| vm2 | 22 (SSH), 8181 (OPA, token-auth), 8428 (VictoriaMetrics), 8880 (vmalert) — **8288** (authz-shim, tailnet-only), **8443** (step-ca, tailnet-only), 9100 (node-exporter, tailnet-only)                                                                          |
| vm3 | 22 (SSH), 12345 (Alloy management, loopback), 9100 (node-exporter, tailnet-only)                                                                                                                                                                              |
| vm4 | 22 (SSH), **3000** (Grafana, tailnet-only), **3100** (Loki, tailnet-only), 9100 (node-exporter, tailnet-only)                                                                                                                                                 |
| vm5 | 22 (SSH), **8090** (web app, tailnet-only, mTLS), 12345 (Alloy management, loopback), 9100 (node-exporter, tailnet-only)                                                                                                                                      |
| vm6 | 22 (SSH), **8091** (internal API, tailnet-only, mTLS), 12345 (Alloy management, loopback), 9100 (node-exporter, tailnet-only)                                                                                                                                 |

## Credentials

In `variables/credentials.nix`

## Cheat Sheet

Conventions used below:

```bash
# [host]  = your tailnet-connected desktop. MagicDNS resolves vm1..vm6;
#           QEMU forwards expose localhost:{8080,8181,8428,8880,9000}.
# [vmN]   = inside VM N. One-shot form:
tailscale ssh user@vmN -- <command>
# root on any VM non-interactively (password `pass` goes to sudo's stdin):
echo pass | tailscale ssh user@vmN -- sudo -S <command>
```

> Gotcha: `tailscale ssh` re-joins arguments through the remote login
> shell — never put spaces inside `curl -H 'Header: value'` values across
> it. Write `-H X-Authentik-Groups:viewers` instead (legal HTTP).

### Service health

```bash
# [any VM] the three Authentik services (migrate is oneshot, may be inactive)
systemctl status authentik authentik-migrate
journalctl -u authentik -n 20 --no-pager

# [vm2] policy + CA + metrics
systemctl status opa authz-shim victoriametrics vmalert-testzero step-ca

# [vm3] sensors
systemctl status zeek suricata alloy
journalctl -fu suricata-update        # first boot: ET/Open + TrafficID fetch

# [vm4] observability
systemctl status grafana loki

# [vm5]/[vm6] workloads
systemctl status testzero-web         # vm5
systemctl status testzero-api         # vm6
journalctl -u testzero-api -f         # watch east-west callers arrive
```

### Gateway auth chain

```bash
# [host] anonymous requests:
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8080/            # → 200  public landing (vm5)
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8080/dashboard   # → 302  Authentik login redirect
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8080/grafana/    # → 302
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:9000             # → 200  Authentik UI
# direct backends have NO host forwards:
curl -m 3 -so /dev/null -w '%{http_code}\n' http://127.0.0.1:3000          # → 000
curl -m 3 -so /dev/null -w '%{http_code}\n' http://127.0.0.1:8090          # → 000
curl -m 3 -so /dev/null -w '%{http_code}\n' http://127.0.0.1:8091          # → 000
```

Authenticated matrix (browser): see demo/03-auth-chain.md — stranger1 gets
403 at authz, viewer1 passes allowed paths, admin passes everything.

Watch decisions live:

```bash
# [host] one JSON line per gateway authz decision:
tailscale ssh user@vm2 -- journalctl -f -u authz-shim
# → {"event":"authz","user":"viewer1",...,"path":"/dashboard","decision":"allow"}
# NOTE: only authenticated requests reach the shim — anonymous probes die
# at the Authentik hop (302) and produce no decision lines.
```

Fill the deny graph without logging in/out — open a shell ON vm1 first
(`tailscale ssh user@vm1`), then quoting works normally:

```bash
for i in $(seq 5); do
  curl -s -o /dev/null vm2:8288/ \
    -H "X-Authentik-Username: viewer1" -H "X-Authentik-Groups: viewers" \
    -H "X-Forwarded-Method: GET" -H "X-Forwarded-Uri: /dashboard"    # → 200
  curl -s -o /dev/null vm2:8288/ \
    -H "X-Authentik-Username: stranger1" -H "X-Authentik-Groups: []" \
    -H "X-Forwarded-Method: GET" -H "X-Forwarded-Uri: /dashboard"    # → 403
done
```

### OPA policy evaluation

All queries need the bearer token; without/wrong token → 401.

```bash
# [host]
TOK="Authorization: Bearer testzero-opa-bearer-token"

# Allowed — admin group catch-all:
curl -s -X POST localhost:8181/v1/data/testzero/authz -H "$TOK" \
  -d '{"input":{"user":"akadmin","groups":["authentik Admins"],"method":"GET","path":"/"}}'
# → {"result":{"allow":true,"reason":"allowed: admin group membership"},...}

# Allowed — viewer write confined to application paths:
curl -s -X POST localhost:8181/v1/data/testzero/authz -H "$TOK" \
  -d '{"input":{"user":"viewer1","groups":["viewers"],"method":"POST","path":"/api/echo"}}'
# → {"result":{"allow":true,"reason":"allowed: viewer write on application path"},...}

# Denied — viewer write outside application paths:
curl -s -X POST localhost:8181/v1/data/testzero/authz -H "$TOK" \
  -d '{"input":{"user":"viewer1","groups":["viewers"],"method":"POST","path":"/etc/passwd"}}'
# → {"result":{"allow":false,"reason":"denied: no rule matched (...)"},...}

# Denied — authenticated user without groups:
curl -s -X POST localhost:8181/v1/data/testzero/authz -H "$TOK" \
  -d '{"input":{"user":"stranger1","groups":[],"method":"GET","path":"/dashboard"}}'
# → {"result":{"allow":false,...}}

# Workload policy (queried by vm6 per API request):
curl -s -X POST localhost:8181/v1/data/testzero/workload -H "$TOK" \
  -d '{"input":{"workload":"svc:vm5-web","method":"GET","path":"/status"}}'
# → {"result":{"allow":true,"reason":"allowed: web tier status read"},...}
curl -s -X POST localhost:8181/v1/data/testzero/workload -H "$TOK" \
  -d '{"input":{"workload":"svc:vm5-web","method":"POST","path":"/echo"}}'
# → {"result":{"allow":false,...}}   (echo belongs to svc:caddy only)

# No token at all:
curl -s -o /dev/null -w '%{http_code}\n' -X POST localhost:8181/v1/data/testzero/authz -d '{}'
# → 401
```

### Segmentation

```bash
# [host] ALLOWED — gateway UIs, wireguard path, identity SSH:
curl -I http://vm1:8080                  # → 200 anonymous landing
curl -I http://vm1:9000                  # → 302 Authentik redirect
tailscale ping -c 3 vm4                  # → pong (ICMP not governed by ACLs)
tailscale ssh user@vm3 hostname          # → vm3 (no password prompted)

# [host] BLOCKED — service ports invisible to members (000 = timeout):
curl -m 3 http://vm2:8428                # VictoriaMetrics
curl -m 3 http://vm2:8181                # OPA (mesh side; only the host forward works)
curl -m 3 http://vm4:3000                # Grafana direct
curl -m 3 http://vm4:3100                # Loki
curl -m 3 http://vm5:8090                # web app (only gateway reaches it)
curl -m 3 http://vm6:8091                # internal API (invisible end-to-end)
```

### Workload identity / mTLS (step-ca)

```bash
# [host] CA health + issued certs + rotation timer:
tailscale ssh user@vm2 -- curl -ks https://vm2:8443/health        # → {"status":"ok"}
echo pass | tailscale ssh user@vm5 -- sudo -S ls -l /var/lib/mtls # web.crt web.key root_ca.crt, 0640
tailscale ssh user@vm5 -- systemctl is-enabled mtls-certs.timer   # → enabled (6h rotation)

# [host] ACCEPTED — vm5 web tier reads vm6 status with its client cert;
# the response echoes the caller's workload CN:
echo pass | tailscale ssh user@vm5 -- sudo -S curl -s --cacert /var/lib/mtls/root_ca.crt \
  --cert /var/lib/mtls/web.crt --key /var/lib/mtls/web.key https://vm6:8091/status
# → {... "workload": "svc:vm5-web" ...}

# [host] REJECTED — no client cert: TLS handshake dies before any HTTP
# (curl exit != 0, empty body):
echo pass | tailscale ssh user@vm1 -- sudo -S curl -sm 5 --cacert /var/lib/mtls/root_ca.crt \
  https://vm5:8090/

# [host] REJECTED — valid cert, action not in the workload policy:
echo pass | tailscale ssh user@vm5 -- sudo -S curl -s --cacert /var/lib/mtls/root_ca.crt \
  --cert /var/lib/mtls/web.crt --key /var/lib/mtls/web.key -X POST -d x https://vm6:8091/echo
# → 403 {"error": "denied by workload policy", "workload": "svc:vm5-web"}
# journalctl -u testzero-api shows "api policy: denied: no rule matched (...)"

# [host] REJECTED — wrong direction: only tag:identity may even SYN vm5:8090
# (ACL drop, timeout):
echo pass | tailscale ssh user@vm6 -- sudo -S curl -m 4 -s -o /dev/null -w '%{http_code}' \
  https://vm5:8090/                                                # → 000

# Fail-closed proof — stop OPA, any vm6 call 403s; start again, recovers:
echo pass | tailscale ssh user@vm2 -- sudo -S systemctl stop opa
echo pass | tailscale ssh user@vm2 -- sudo -S systemctl start opa

# Rotation watch (fresh 24h keypair every 6h, consumers reloaded after):
tailscale ssh user@vm5 -- journalctl -u mtls-certs -f
```

### Runtime detection (Tetragon)

```bash
# [host] trip the two tripwires on vm5:
tailscale ssh user@vm5 -- bash -c true                       # fires shell-spawn
echo pass | tailscale ssh user@vm5 -- sudo -S cat /etc/shadow >/dev/null   # fires sensitive-file-open

# [host] events land in the export file:
echo pass | tailscale ssh user@vm5 -- sudo -S tail -n 20 /var/log/tetragon/events.json

# [vm5/vm6] sensor status:
systemctl status tetragon --no-pager
tetra status
```

Same hooks run on vm6. Grafana (:8080/grafana/) → "Runtime Security
(Tetragon)" dashboard; TetragonEventFired appears in the Alerting UI.

### IDS signatures (Suricata)

pcap on tailscale0 sees kernel-path traffic only. Tailscale SSH terminates
inside tailscaled's userspace netstack — packets to/from port 22 never
reach the capture, so there is intentionally no SSH tripwire anymore.

```bash
# sid 8000001 self-fires ~every 15s (vm2 scrapes vm3's node-exporter).

# [host] fire sid 8000003: known payload in a request body to vm3:9100,
# sent FROM vm2 (member devices are ACL-blocked from tag:sensor):
printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$TESTZERO-TRIPWIRE' \
  | tailscale ssh user@vm2 -- tee /tmp/tz-tripwire >/dev/null
tailscale ssh user@vm2 -- curl -s -o /dev/null --data-binary @/tmp/tz-tripwire \
  http://vm3:9100/metrics
tailscale ssh user@vm2 -- rm -f /tmp/tz-tripwire

# [host] alerts land in eve.json within seconds (canary rules flood the
# log, so count signature ids rather than tail; the . dots stand in for
# JSON quotes — they would be stripped by the remote shell):
echo pass | tailscale ssh user@vm3 -- sudo -S \
  grep -oaE '.signature_id..[0-9]+' /var/log/suricata/eve.json | sort | uniq -c | sort -rn
# → 8000001 (scrape), 8000003 (payload), 8000010/8000011 (diagnostic canaries)
```

Grafana (:8080/grafana/) → "Suricata Alerts" dashboard; the provisioned
SuricataSignatureFired rule fires within ~1 minute.

### Active response (CrowdSec)

What trips what (verified on the live deployment):

| Trigger                                                              | Source IP vm1 sees | Ban kills for 30 min                                                                            |
| -------------------------------------------------------------------- | ------------------ | ----------------------------------------------------------------------------------------------- |
| SSH brute force vs `localhost:2201` (hub `crowdsecurity/sshd-bf`)    | `10.0.2.2`         | only the QEMU host forwards to vm1 — tailnet unaffected ✔                                       |
| HTTP probing = 6+ **4xx** in <1 min (custom `testzero/http-probing`) | that client's IP   | its share of vm1                                                                                |
| Unauthenticated curls to :8080                                       | —                  | **nothing**: every path 302s (Authentik redirect); the scenario counts only 400/401/403/404/405 |
| SSH brute force over the tailnet                                     | —                  | nothing: Tailscale SSH never reaches sshd                                                       |

```bash
# [vm1] health:
systemctl status crowdsec crowdsec-firewall-bouncer --no-pager
ss -ltn | grep 8081                # LAPI loopback listener (:8080 is Caddy's!)
sudo cscli metrics                 # lines parsed, buckets, LAPI hits
sudo cscli bouncers list           # 'Last API pull' ticking = enforcement alive

# [host] trigger — fail 7+ passwords against the forwarded SSH port
# (no sshpass needed; OpenSSH >= 8.4):
printf '#!/bin/sh\necho notthepass\n' > /tmp/ask.sh && chmod +x /tmp/ask.sh
for i in $(seq 8); do
  env SSH_ASKPASS=/tmp/ask.sh SSH_ASKPASS_REQUIRE=force \
    ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password \
        -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1 \
        -p 2201 user@localhost true
done

# [vm1] ~20s later — detection + active decision:
sudo cscli alerts list
# | Ip:10.0.2.2 | crowdsecurity/ssh-slow-bf | ban:1 |
sudo cscli decisions list
# | crowdsec | Ip:10.0.2.2 | crowdsecurity/ssh-slow-bf | ban | 29m.. |
sudo iptables -S CROWDSEC_CHAIN    # DROP jump via ipset crowdsec-blacklists-0
sudo ipset list crowdsec-blacklists-0

# [host] effective — forward dead, tailnet fine:
curl -m 5 http://localhost:8080/   # → curl: (28) timeout
tailscale ssh user@vm1 hostname    # → vm1

# [vm1] release early (~15s bouncer lag; bans also expire by themselves):
sudo cscli decisions delete -i 10.0.2.2

# Alternative 4xx source: log into the browser as stranger1 (no groups) and
# click six protected pages — every page 403s at the shim and bans YOUR IP
# (via http://vm1:8080 that includes your tailnet IP; rescue: ssh -p 2201
# user@localhost arrives as 10.0.2.2 and can delete the decision).
```

Ops reference: caddy JSON (`/var/log/caddy/access-:8080.log`) + sshd
journal → parsers (`testzero/caddy-json`, hub `crowdsecurity/linux`) →
scenarios (`testzero/http-probing`, hub `ssh-*-bf`) → profile
`testzero-ban-30m` → decisions → bouncer stream → iptables. Engine metrics
on vm1:6060 are scraped by vm2 (job `crowdsec`).

More `cscli`:

```bash
sudo cscli alerts inspect <id>                 # full event detail
sudo cscli explain --file <logline.txt> --type caddy   # debug parser/scenario match
sudo journalctl -u crowdsec -u crowdsec-firewall-bouncer -b
```

### Vulnerability scanning & SBOMs (vulnix + sbomnix, all VMs)

```bash
# [any VM] timers + last runs:
systemctl list-timers --no-pager | grep -E "vulnix|sbom"
systemctl status vulnix-scan sbom-generate --no-pager

# [any VM] artifacts:
cat /var/log/sbom/vulnix.json | jq '.[].name'   # affected derivations
head /var/log/sbom/findings.log                 # shipped to Loki (job=vulnix)
ls -la /var/lib/sbom/                           # <vm>.{cdx,spdx}.json (weekly)

# [host] run a scan now instead of waiting for the daily timer:
echo pass | tailscale ssh user@vm1 -- sudo -S systemctl start vulnix-scan

# [host] retrieve an SBOM:
echo pass | tailscale ssh user@vm1 -- sudo -S cat /var/lib/sbom/vm1.cdx.json > vm1.cdx.json

# Suppress false positives / accepted risks:
#   edit variables/vulnix-whitelist.toml (TOML, see comments there), rebuild.
```

Fleet view: Grafana → "Vulnerability Management" dashboard; the
VulnixHighSeverityFound rule fires on high/critical findings within 24h.

Pipeline: `vulnix -S` (system closure vs NVD feed, cached in
`/var/cache/vulnix`) → `/var/log/sbom/findings.log` (one JSON line per CVE,
severity from CVSSv3) → Alloy → Loki (`job="vulnix"`, `host=<vm>`) →
dashboard + alert. `sbomnix /run/current-system` writes CycloneDX/SPDX to
`/var/lib/sbom/<vm>.{cdx,spdx}.json` weekly.

### Metrics & alerts

```bash
# [host] all scrape targets:
curl -s 'localhost:8428/api/v1/query?query=up' | jq -r '.data.result[].metric.job'

# down targets (expect an empty result array):
curl -s 'localhost:8428/api/v1/query?query=up==0'

# firing alerts — vmalert publishes ALERTS series back into VictoriaMetrics:
curl -s 'localhost:8428/api/v1/query?query=ALERTS'
curl -s localhost:8880/api/v1/alerts        # vmalert's own state API
curl -s localhost:8880/api/v1/rules         # loaded rule groups

# node memory by VM:
curl -s 'localhost:8428/api/v1/query?query=(1-node_memory_MemAvailable_bytes/node_memory_MemTotal_bytes)*100'
```

Alert rules: ScrapeTargetDown (critical), NodeHighMemoryUsage,
NodeHighCpuUsage (warning). No Alertmanager — firing state surfaces via the
ALERTS series, the :8880 API and the fleet dashboard.
