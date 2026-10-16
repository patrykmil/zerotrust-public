#!/usr/bin/env fish
# 06 — Runtime detection: Tetragon eBPF hooks on the workload VMs.
#
# Purpose: prove shell execs and /etc/shadow reads land in events.json on
#   the way to Loki/Grafana (the sensor records even our own lookups).
# Contents: tripwires (bash exec, shadow read) + negative case (no events
#   from undefined policies) with wait-and-poll loops.
# VMs: vm5 (vm6 carries the same hooks).

set -g pass_count 0
set -g fail_count 0
function check -a desc expected actual
    if test "$expected" = "$actual"
        echo "  PASS  $desc"
        set -g pass_count (math $pass_count + 1)
    else
        echo "  FAIL  $desc (expected $expected, got $actual)"
        set -g fail_count (math $fail_count + 1)
    end
end

function rroot -a vm
    echo pass | tailscale ssh user@$vm -- sudo -S $argv[2..] 2>/dev/null
end

echo "sensor status on vm5:"
tailscale ssh user@vm5 -- systemctl is-active tetragon; or begin
    echo "  FAIL  tetragon not active"; exit 1
end

echo "firing tripwires on vm5 ..."
tailscale ssh user@vm5 -- bash -c true >/dev/null 2>&1        # shell-spawn
rroot vm5 cat /etc/shadow >/dev/null                          # sensitive-file-open

function seen -a needle
    rroot vm5 tail -n 200 /var/log/tetragon/events.json | string match -q "*$needle*"
end

echo "waiting for events ..."
for i in (seq 15)
    seen shell-spawn;           and set sh_found 1
    seen sensitive-file-open;   and set sf_found 1
    set -q sh_found; and set -q sf_found; and break
    sleep 2
end

set -q sh_found
check "shell-spawn event recorded (bash exec)"            0 $status
set -q sf_found
check "sensitive-file-open recorded (/etc/shadow read)"   0 $status

# negative case: a policy that doesn't exist can't have events
if rroot vm5 tail -n 200 /var/log/tetragon/events.json | string match -q '*no-such-policy*'
    check "no events from undefined policies" clean dirty
else
    check "no events from undefined policies" clean clean
end

echo
echo "Same hooks live on vm6 — repeat with user@vm6 if desired."
echo "Fleet view: http://localhost:8080/grafana/ → \"Runtime Security (Tetragon)\""
echo "passed: $pass_count  failed: $fail_count"
test $fail_count -eq 0
