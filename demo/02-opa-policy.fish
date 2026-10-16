#!/usr/bin/env fish
# 02 — Central policy engine (OPA on vm2, REST via host forward :8181).
#
# Purpose: exercise testzero.authz (user) + testzero.workload (CN)
#   decisions and the token-guarded API directly, without the gateway.
# Contents: allow/deny verdict matrix for both packages plus 401 cases
#   (missing/wrong bearer token).
# VMs: vm2 (queried from the host).

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

set tok "Authorization: Bearer testzero-opa-bearer-token"

# verdict <package> <input-json> → "true" or "false"
function verdict -a pkg payload
    if curl -s -X POST localhost:8181/v1/data/$pkg/allow -H "$tok" -d "$payload" \
        | string match -q '*"result":true*'
        echo true
    else
        echo false
    end
end

echo "== testzero.authz — user policy =="
check "admin GET / (allow)"                 true  (verdict testzero/authz '{"input":{"user":"akadmin","groups":["authentik Admins"],"method":"GET","path":"/"}}')
check "viewer GET /dashboard (allow)"       true  (verdict testzero/authz '{"input":{"user":"viewer1","groups":["viewers"],"method":"GET","path":"/dashboard"}}')
check "viewer POST /api/echo (allow)"       true  (verdict testzero/authz '{"input":{"user":"viewer1","groups":["viewers"],"method":"POST","path":"/api/echo"}}')
check "viewer POST /anything-else (deny)"   false (verdict testzero/authz '{"input":{"user":"viewer1","groups":["viewers"],"method":"POST","path":"/anything-else"}}')
check "viewer DELETE /api/echo (deny)"      false (verdict testzero/authz '{"input":{"user":"viewer1","groups":["viewers"],"method":"DELETE","path":"/api/echo"}}')
check "stranger GET /dashboard (deny)"      false (verdict testzero/authz '{"input":{"user":"stranger1","groups":[],"method":"GET","path":"/dashboard"}}')

echo "== testzero.workload — workload-CN policy (vm6 queries this) =="
check "svc:caddy GET /status (allow)"       true  (verdict testzero/workload '{"input":{"workload":"svc:caddy","method":"GET","path":"/status"}}')
check "svc:caddy POST /echo (allow)"        true  (verdict testzero/workload '{"input":{"workload":"svc:caddy","method":"POST","path":"/echo"}}')
check "svc:vm5-web GET /status (allow)"     true  (verdict testzero/workload '{"input":{"workload":"svc:vm5-web","method":"GET","path":"/status"}}')
check "svc:vm5-web POST /echo (deny)"       false (verdict testzero/workload '{"input":{"workload":"svc:vm5-web","method":"POST","path":"/echo"}}')
check "unknown CN svc:evil (deny)"          false (verdict testzero/workload '{"input":{"workload":"svc:evil","method":"GET","path":"/status"}}')

echo "== API auth (system.authz) =="
check "no bearer token → 401"  401 (curl -s -o /dev/null -w '%{http_code}' -X POST localhost:8181/v1/data/testzero/authz/allow -d '{}')
check "wrong bearer token → 401" 401 (curl -s -o /dev/null -w '%{http_code}' -X POST localhost:8181/v1/data/testzero/authz/allow -H "Authorization: Bearer wrong" -d '{}')

echo
echo "passed: $pass_count  failed: $fail_count"
test $fail_count -eq 0
