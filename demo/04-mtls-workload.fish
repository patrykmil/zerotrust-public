#!/usr/bin/env fish
# 04 — Workload identity: step-ca mTLS + central workload authz.
#
# Purpose: prove east-west calls need all three layers — mesh ACL, client
#   cert, OPA workload verdict — and fail closed without any of them.
# Contents: CA/certs/rotation checks, accepted calls, rejection layer by
#   layer (no cert, wrong action, ACL drop).
# VMs: vm1 (caddy cert), vm2 (step-ca), vm5 + vm6 (probes run on-VM via
#   tailscale ssh — members have no mesh route to the backends).

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

# Run <cmd...> as root ON <vm>; remote stderr (sudo prompt) dropped.
function rroot -a vm
    echo pass | tailscale ssh user@$vm -- sudo -S $argv[2..] 2>/dev/null
end

echo "== CA + issued certs =="
set out (tailscale ssh user@vm2 -- curl -ks https://vm2:8443/health 2>/dev/null)
string match -q '*ok*' -- $out
check "step-ca /health on vm2" 0 $status

set out (rroot vm5 ls /var/lib/mtls)
string match -q '*web.crt*' -- $out
check "vm5 holds issued workload cert (web.crt)" 0 $status
set out (tailscale ssh user@vm5 -- systemctl is-enabled mtls-certs.timer 2>/dev/null)
check "mtls-certs rotation timer armed (6h)" enabled "$out"

echo "== ACCEPTED: cert + allowed workload action =="
set out (rroot vm5 curl -s --cacert /var/lib/mtls/root_ca.crt \
    --cert /var/lib/mtls/web.crt --key /var/lib/mtls/web.key \
    https://vm6:8091/status)
string match -q '*svc:vm5-web*' -- $out
check "vm5 web → vm6 GET /status (200, API sees our CN)" 0 $status

set c (rroot vm1 curl -sm 5 -o /dev/null -w '%{http_code}' --cacert /var/lib/mtls/root_ca.crt \
    --cert /var/lib/mtls/caddy.crt --key /var/lib/mtls/caddy.key https://vm5:8090/)
check "vm1 caddy cert → vm5:8090 (200, gateway identity accepted)" 200 $c

echo "== REJECTED: layer by layer =="
# Layer 2 — no client cert at all: TLS handshake dies before any HTTP.
rroot vm5 curl -sm 5 --cacert /var/lib/mtls/root_ca.crt https://vm6:8091/status >/dev/null
if test $status -ne 0
    check "vm5 → vm6 WITHOUT client cert (TLS handshake refused)" denied denied
else
    check "vm5 → vm6 WITHOUT client cert (TLS handshake refused)" denied allowed
end

# Layer 3 — valid cert, action not in the workload policy:
# svc:vm5-web may GET /status only; POST /echo belongs to svc:caddy.
set out (rroot vm5 curl -s --cacert /var/lib/mtls/root_ca.crt \
    --cert /var/lib/mtls/web.crt --key /var/lib/mtls/web.key \
    -X POST -d x https://vm6:8091/echo)
string match -q '*denied by workload policy*' -- $out
check "svc:vm5-web POST /echo → 403 (OPA workload deny)" 0 $status

# The other direction is cut two ways: only tag:identity may even SYN
# vm5:8090 (ACL), and the server additionally requires a client cert.
set c (rroot vm6 curl -m 4 -s -o /dev/null -w '%{http_code}' https://vm5:8090/)
check "vm6 → vm5:8090 (000 = ACL drop, tag:internal→tag:workload ungranted)" 000 $c
rroot vm1 curl -sm 5 --cacert /var/lib/mtls/root_ca.crt https://vm5:8090/ >/dev/null
if test $status -ne 0
    check "vm1 → vm5 WITHOUT client cert (TLS handshake refused)" denied denied
else
    check "vm1 → vm5 WITHOUT client cert (TLS handshake refused)" denied allowed
end

# Layer 1 — ACL: a member device can't even SYN vm6:8091 (also in demo 01).
set c (curl -m 3 -s -o /dev/null -w '%{http_code}' http://vm6:8091 2>/dev/null)
check "host → vm6:8091 (000 = ACL drop)" 000 $c

echo
echo "Optional fail-closed proof (manual, see demo/03-auth-chain.md end):"
echo "  stop OPA on vm2 → every vm6 call 403s; start OPA → recovers."
echo
echo "passed: $pass_count  failed: $fail_count"
test $fail_count -eq 0
