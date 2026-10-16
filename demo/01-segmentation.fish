#!/usr/bin/env fish
# 01 — Network segmentation (Tailscale tag ACLs).
#
# Purpose: prove members reach only the gateway UIs + SSH while service
#   ports stay invisible (ACL drops are silent at the source).
# Contents: curl code checks for accepted (vm1:8080/:9000) vs rejected
#   (vm2/vm4/vm5/vm6 ports) paths, plus the localhost:8181 host forward.
# VMs: all (probed from the host over the tailnet; no VM login needed).

set -g pass_count 0
set -g fail_count 0
function check -a desc expected actual
    if test "$expected" = "$actual"
        echo "  PASS  $desc"
        set -g pass_count (math $pass_count + 1)
    else
        echo "  FAIL  $desc (expected $expected, got [$actual])"
        set -g fail_count (math $fail_count + 1)
    end
end

function codeof -a url
    curl -m 3 -s -o /dev/null -w '%{http_code}' $url 2>/dev/null
    # curl prints 000 + nonzero exit when the ACL blackholes the TCP SYN
end

echo "== ACCEPTED: what a member device may reach =="
check "http://vm1:8080/ landing (200)"           200 (codeof http://vm1:8080/)
check "http://vm1:9000/ Authentik UI (302 to /if/)" 302 (codeof http://vm1:9000/)


echo "== REJECTED: service ports invisible to members (000 = timeout) =="
check "http://vm2:8428  VictoriaMetrics"  000 (codeof http://vm2:8428)
check "http://vm2:8181  OPA (mesh side)"  000 (codeof http://vm2:8181)
check "http://vm4:3000  Grafana direct"   000 (codeof http://vm4:3000)
check "http://vm4:3100  Loki"             000 (codeof http://vm4:3100)
check "http://vm5:8090  web app"          000 (codeof http://vm5:8090)
check "http://vm6:8091  internal API"     000 (codeof http://vm6:8091)
# OPA is still reachable via the QEMU host forward on localhost:8181 —
# that forward is host-side plumbing, not a mesh grant. Demo 02 uses it.
check "http://localhost:8181 OPA (host forward)" \
    401 (curl -m 3 -s -o /dev/null -w '%{http_code}' http://localhost:8181)

echo
echo "passed: $pass_count  failed: $fail_count"
test $fail_count -eq 0
