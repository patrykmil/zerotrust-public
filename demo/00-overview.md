# TestZero demo suite

One file per zero-trust aspect. Every demo shows **both** the accepted
path and the rejected path of the same control.

## Prerequisites

- All six VMs booted (`nix run .#vmN`), tailnet joined, tags approved,
  `tailscale/policy.hujson` applied in the admin console.
- Authentik manual setup done (README "Manual Setup Steps") — required
  only for `03-auth-chain.md`.
- You run everything from **your host**, which must be on the tailnet
  with MagicDNS (names `vm1`–`vm6` resolve) and the QEMU host port
  forwards up (`localhost:8080`, `:8181`, `:8428`, `:8880`, `:9000`).
- Host tools: `fish`, `curl`, `tailscale`. `nc` optional (one step of 05).

## Run order

| #   | File                    | Aspect                                         | Accepted case shown                                | Rejected case shown                                       |
| --- | ----------------------- | ---------------------------------------------- | -------------------------------------------------- | --------------------------------------------------------- |
| 1   | `01-segmentation.fish`  | Tailscale tag ACLs                             | member → vm1 gateway/Authentik                     | member → vm2/vm4/vm5/vm6 service ports: timeout           |
| 2   | `02-opa-policy.fish`    | Central policy engine (OPA REST)               | admin/viewer allows, workload allows               | wrong path/method/user deny, no token → 401               |
| 3   | `03-auth-chain.md`      | Full user chain: Authentik → OPA → vm5/vm6/vm4 | viewer1 reaches dashboard/API/Grafana              | stranger1 → 403, anonymous → 302                          |
| 4   | `04-mtls-workload.fish` | step-ca workload identity, east-west mTLS      | `svc:vm5-web` → vm6 `/status` 200                  | no client cert → TLS failure; wrong workload/action → 403 |
| 5   | `05-suricata.fish`      | Signature IDS on vm3                           | scripted tripwires produce eve.json alerts         | (detection demo)                                          |
| 6   | `06-tetragon.fish`      | eBPF runtime detection on vm5                  | shell-spawn + /etc/shadow open land in events.json | (detection demo)                                          |
| 7   | `07-crowdsec.fish`      | Active response (ban) on vm1                   | probing → 30-min iptables DROP of source IP        | ban = the rejection; early release documented             |
| 8   | `08-monitoring.fish`    | Metrics, alerts, vulnix/SBOM presence          | all scrape targets up, timers armed, artifacts     | shows where a down target / firing alert appears          |
| 9   | `09-anubis.fish`        | Bot gate (Anubis PoW) on /spotlight            | curl → 200 real page                           | agent (WebFetch UA) sees only the challenge page          |

Run scripts with `fish demo/0X-*.fish` (they `cd`-independent, use only
tailnet names + host forwards). Each script prints `PASS`/`FAIL` per
check and exits non-zero on any failure — the check expectations _are_
the expected behaviour.

## What to watch on which VM

Every VM command goes through `tailscale ssh user@vmN` (identity-based,
no password). `sudo` on a VM needs the user password `pass`; the scripts
pipe it in non-interactively (`echo pass | ... sudo -S`).

| VM  | Command                                                                                | Shows                                                  |
| --- | -------------------------------------------------------------------------------------- | ------------------------------------------------------ |
| vm2 | `tailscale ssh user@vm2 -- journalctl -u authz-shim -f`                                | one JSON line per gateway authz decision (demos 01–03) |
| vm2 | `tailscale ssh user@vm2 -- journalctl -u opa -f`                                       | OPA decision logs (02, 04)                             |
| vm6 | `tailscale ssh user@vm6 -- journalctl -u testzero-api -f`                              | east-west callers + workload authz verdicts (03, 04)   |
| vm5 | `tailscale ssh user@vm5 -- journalctl -u testzero-web -f`                              | web tier + its server-side vm6 calls (03)              |
| vm3 | `echo pass \| tailscale ssh user@vm3 -- sudo -S tail -f /var/log/suricata/eve.json`    | IDS alerts (05)                                        |
| vm5 | `echo pass \| tailscale ssh user@vm5 -- sudo -S tail -f /var/log/tetragon/events.json` | runtime events (06)                                    |
| vm1 | `echo pass \| tailscale ssh user@vm1 -- sudo -S cscli decisions list`                  | active bans (07)                                       |
| vm1 | `echo pass \| tailscale ssh user@vm1 -- sudo -S journalctl -u anubis-gateway -f`        | PoW challenges issued (09)                             |
| vm2 | `journalctl -u mtls-certs -f` on vm1/vm5/vm6                                           | cert rotation every 6h (04 background)                 |
