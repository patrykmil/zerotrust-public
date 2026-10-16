#!/usr/bin/env fish
# 09 — Bot gate: Anubis PoW check in front of /spotlight.
#
# Purpose: prove Anubis gates browser-like clients (307 to the challenge
#   UI) while plain HTTP clients pass — including an AI agent on WebFetch.
# Contents: one curl → real page; one opencode/big-pickle agent run →
#   challenge page only.
# VMs: vm1 (Anubis gate) + vm5 (page origin), driven from the host.

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

echo "== curl passes =="
curl -m 5 -s http://localhost:8080/spotlight | string match -q '*spotlight: bot-checked*'
check "curl → real page content" 0 $status

echo "== agent is challenged =="
echo "(agent run may take a minute ...) "
set agent_out (timeout 240 opencode run -m opencode/big-pickle "Can you see what's on http://localhost:8080/spotlight? Use your WebFetch page-fetch tool for this, not curl." 2>&1)
if string match -q '*Anubis*' -- $agent_out; and not string match -q '*spotlight: bot-checked*' -- $agent_out
    check "agent sees only the Anubis challenge (blocked)" ok ok
else
    echo "--- agent output (tail) ---"
    printf '%s\n' $agent_out | tail -5
    echo "---------------------------"
    check "agent sees only the Anubis challenge (blocked)" ok unexpected
end

echo
echo "passed: $pass_count  failed: $fail_count"
test $fail_count -eq 0
