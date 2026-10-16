#!/usr/bin/env fish
# 08 — Monitoring: VictoriaMetrics + vmalert + vulnix/SBOM presence.
#
# Purpose: prove the fleet is calm and observed — all scrape targets up,
#   no firing alerts, scan/SBOM timers armed on every VM.
# Contents: PromQL checks (up, up==0, ALERTS, target count), vmalert rules
#   presence, Grafana path sanity, per-VM timer checks, artifact listing
#   (informational — fresh VMs may not have run yet).
# VMs: all (metrics via host forwards, timers via tailscale ssh).

set -g pass_count 0
set -g fail_count 0
function check -a desc expected actual
    if test "$expected" = "$actual"
        echo "  PASS  $desc"
        set -g pass_count (math $pass_count + 1)
    else
        echo "  FAIL  $desc (expected [$expected], got [$actual])"
        set -g fail_count (math $fail_count + 1)
    end
end

function vmq -a q
    curl -sm 5 "localhost:8428/api/v1/query?query=$q" | string collect
end

echo "== VictoriaMetrics (vm2) =="
string match -q '*"status":"success"*' (vmq up)
check "PromQL API answering" 0 $status

set down (vmq "up==0" | string match -r '"result":\[\]' )
check "zero scrape targets down (up==0 result empty)" '"result":[]' "$down"

set res (vmq up | string match -ar '"value":\[' | count)
if test "$res" -ge 8
    check "scrape jobs reporting ($res targets up)" ok ok
else
    check "scrape jobs reporting ($res targets up)" ok "$res"
end

echo "== vmalert (vm2) =="
# firing alerts on a calm fleet = empty ALERTS series in VictoriaMetrics
# (vmalert publishes firing alerts as metrics; ponytail: glob can't
# escape [] reliably in fish — query the series instead)
set res (vmq ALERTS | string match -r '"result":\[\]' )
check "no alerts currently firing (ALERTS series empty)" '"result":[]' "$res"
# prove alert *rules* exist and are evaluated:
string match -q '*ScrapeTargetDown*' (curl -sm 5 localhost:8880/api/v1/rules)
check "alert rules loaded (ScrapeTargetDown present)" 0 $status

echo "== Grafana path sanity =="
set c (curl -sm 5 -o /dev/null -w '%{http_code}' http://localhost:8080/grafana/)
check "grafana via Caddy chain (302 to login when anonymous — demo 03)" 302 $c
set c (curl -m 3 -s -o /dev/null -w '%{http_code}' http://127.0.0.1:3000 2>/dev/null)
check "grafana direct :3000 (000 — hardened, tailnet-only)" 000 $c

echo "== vulnix + sbom timers (all 6 VMs) =="
for vm in vm1 vm2 vm3 vm4 vm5 vm6
    set out (tailscale ssh user@$vm -- systemctl list-timers vulnix-scan.timer sbom-generate.timer --no-pager 2>/dev/null | string collect)
    if string match -q '*vulnix*' -- $out; and string match -q '*sbom*' -- $out
        check "$vm: vulnix-scan + sbom-generate timers armed" ok ok
    else
        check "$vm: vulnix-scan + sbom-generate timers armed" ok missing
    end
end

echo "== artifacts (informational — fresh VMs may not have run yet) =="
echo pass | tailscale ssh user@vm1 -- sudo -S sh -c "'test -s /var/log/sbom/findings.log && echo findings || echo none'" 2>/dev/null
echo pass | tailscale ssh user@vm1 -- sudo -S ls /var/lib/sbom/ 2>/dev/null
echo "  (run now instead of waiting for the timers:
    echo pass | tailscale ssh user@vm1 -- sudo -S systemctl start vulnix-scan sbom-generate )"

echo
echo "passed: $pass_count  failed: $fail_count"
test $fail_count -eq 0
