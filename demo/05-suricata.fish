#!/usr/bin/env fish
# 05 — Signature IDS: Suricata on the sensor (sniffing tailscale0).
#
# Purpose: prove mesh traffic fires signature alerts into eve.json on the
#   way to Loki/Grafana; documents the Tailscale-SSH blind spot (sid
#   8000002 can't fire — userspace interception, kept as rejected case).
# Contents: tripwire fires (8000001 scrape, 8000003 payload) + quiet case
#   (8000002) with wait-and-poll loops.
# VMs: vm2 (fires the triggers), vm3 (eve.json).

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

# eve.json is flooded by the canary rules (8000010/11) every second —
# search a generous tail window.
function sid_seen -a sid
    rroot vm3 tail -n 2000 /var/log/suricata/eve.json | string match -q "*\"signature_id\":$sid*"
end

echo "firing tripwires: vm2 → vm3:9100 (scrape GET + payload POST) ..."
# payload as a remote file via stdin: keeps the special chars out of
# every shell layer between here and vm2
printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$TESTZERO-TRIPWIRE' \
    | tailscale ssh user@vm2 -- tee /tmp/tz-tripwire >/dev/null
tailscale ssh user@vm2 -- curl -sm 5 -o /dev/null http://vm3:9100/metrics
tailscale ssh user@vm2 -- curl -sm 5 -o /dev/null --data-binary @/tmp/tz-tripwire http://vm3:9100/metrics
tailscale ssh user@vm2 -- rm -f /tmp/tz-tripwire

# sid 8000002 trigger attempt: STANDARD ssh (not tailscale ssh) to vm3.
# BatchMode: no password prompts; the SYN alone would be enough if the
# kernel path ever saw it.
echo "attempting standard ssh to vm3 (sid 8000002 trigger) ..."
for i in (seq 3)
    ssh -o BatchMode=yes -o ConnectTimeout=4 -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null user@vm3 true 2>/dev/null
end

echo "waiting for alerts to flush to eve.json ..."
for i in (seq 15)
    sid_seen 8000001; and set s1 1
    sid_seen 8000003; and set s3 1
    set -q s1; and set -q s3; and break
    sleep 2
end

set -q s1
check "sid 8000001 metrics-scrape signature fired"   0 $status
set -q s3
check "sid 8000003 tripwire-payload signature fired" 0 $status

# Rejected case: standard ssh to vm3 was attempted 3 times above, yet the
# sid must stay quiet — tailscaled intercepted those connections in
# userspace before pcap could see them (see NOTE below).
if sid_seen 8000002
    check "sid 8000002 SSH-to-sensor (standard ssh invisible to IDS)" quiet fired
else
    check "sid 8000002 SSH-to-sensor (standard ssh invisible to IDS)" quiet quiet
end

echo
echo "NOTE: sid 8000002 cannot fire in this deployment — Tailscale SSH"
echo "terminates ALL port-22 connections (incl. standard OpenSSH clients)"
echo "inside vm3's tailscaled userspace, invisible to pcap on tailscale0."
echo "To make SSH detection work, drop --ssh on vm3 (modules/tailscale.nix)"
echo "or capture eth1 instead. modules/suricata.nix also carries the"
echo "diagnostic canary rules (8000010/8000011) flooding eve.json."
echo
echo "Fleet view: http://localhost:8080/grafana/ → \"Suricata Alerts\" dashboard"
echo "passed: $pass_count  failed: $fail_count"
test $fail_count -eq 0
