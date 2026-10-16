#!/usr/bin/env fish
# 07 — Active response: CrowdSec bans on the gateway.
#
# Purpose: prove detection → 30-min firewall DROP → early release, once per
#   trigger, with the tailnet path unaffected throughout.
# Contents: phase 1 SSH brute force (crowdsecurity/ssh-*-bf) and phase 2
#   HTTP 4xx storm (testzero/http-probing); each shows decisions list,
#   dead forward (000), live tailnet SSH, release → 200 again.
# VMs: vm1 (bans 10.0.2.2 — host forwards only; never aim at a tailnet IP).

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

function rroot -a vm
    echo pass | tailscale ssh user@$vm -- sudo -S $argv[2..] 2>/dev/null
end

function codeof -a url
    curl -m 5 -s -o /dev/null -w '%{http_code}' $url 2>/dev/null
    # curl prints 000 + nonzero exit when the DROP blackholes the SYN
end

echo "== Health: engine + bouncer on vm1 =="
set out (tailscale ssh user@vm1 -- systemctl is-active crowdsec crowdsec-firewall-bouncer 2>/dev/null)
string match -q '*active*' -- $out[1]
check "crowdsec active" 0 $status
string match -q '*active*' -- $out[2]
check "crowdsec-firewall-bouncer active" 0 $status
rroot vm1 cscli bouncers list | string match -q '*firewall*'
check "bouncer registered (cscli bouncers list)" 0 $status

# Repeatable runs: drop a stale ban from a previous run first.
rroot vm1 cscli decisions delete -i 10.0.2.2 >/dev/null 2>&1

echo "== Phase 1 trigger: SSH brute force via the host forward =="
printf '#!/bin/sh\necho notthepass\n' > /tmp/tz-ask.sh; chmod +x /tmp/tz-ask.sh
for i in (seq 8)
    env SSH_ASKPASS=/tmp/tz-ask.sh SSH_ASKPASS_REQUIRE=force \
        ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
            -o PreferredAuthentications=password -o PubkeyAuthentication=no \
            -o NumberOfPasswordPrompts=1 -o ConnectTimeout=5 \
            -p 2201 user@localhost true 2>/dev/null
end
rm -f /tmp/tz-ask.sh

echo "waiting for detection → decision (~20s) ..."
for i in (seq 12)
    rroot vm1 cscli decisions list | string match -q '*10.0.2.2*'; and set banned1 1; and break
    sleep 5
end

echo "--- cscli decisions list (SSH ban) ---"
set dl1 (rroot vm1 cscli decisions list 2>/dev/null)
printf '%s\n' $dl1
echo "--------------------------------------"

set -q banned1
check "phase 1: ban decision for 10.0.2.2 present" 0 $status
string match -q '*ssh*' -- $dl1
check "phase 1: reason is crowdsecurity/ssh-*-bf" 0 $status

echo "waiting for enforcement (bouncer → iptables, ~15s) ..."
for i in (seq 6)
    test (codeof http://localhost:8080/) = 000; and set dropped1 1; and break
    sleep 5
end
set -q dropped1
check "phase 1: forward dead while banned (localhost:8080 → 000)" 0 $status

tailscale ssh user@vm1 -- hostname >/dev/null 2>&1
check "phase 1: tailnet path unaffected (tailscale ssh user@vm1)" 0 $status

echo "== Phase 1 release (bans also self-expire after 30 min) =="
rroot vm1 cscli decisions delete -i 10.0.2.2 >/dev/null 2>&1
echo "waiting for bouncer to pick up the deletion (~15s) ..."
for i in (seq 12)
    test (codeof http://localhost:8080/) = 200; and set back1 1; and break
    sleep 5
end
set -q back1
check "phase 1: forward answers again (localhost:8080 → 200)" 0 $status

echo "== Phase 2 trigger: HTTP probing (rapid 404s, no login needed) =="
set probes 0
for i in (seq 10)
    test (codeof http://localhost:8080/outpost.goauthentik.io/tz-probe-$i) = 404; and set probes (math $probes + 1)
end
if test $probes -ge 6
    check "phase 2: 4xx storm sent ($probes/10 probes 404)" ok ok
else
    check "phase 2: 4xx storm sent ($probes/10 probes 404)" ok storm-short
end

echo "waiting for detection → decision (~20s) ..."
for i in (seq 12)
    rroot vm1 cscli decisions list | string match -q '*10.0.2.2*'; and set banned2 1; and break
    sleep 5
end

echo "--- cscli decisions list (HTTP ban) ---"
set dl2 (rroot vm1 cscli decisions list 2>/dev/null)
printf '%s\n' $dl2
echo "---------------------------------------"

set -q banned2
check "phase 2: ban decision for 10.0.2.2 present" 0 $status
string match -q '*http-probing*' -- $dl2
check "phase 2: reason is testzero/http-probing" 0 $status

echo "waiting for enforcement (bouncer → iptables, ~15s) ..."
for i in (seq 6)
    test (codeof http://localhost:8080/) = 000; and set dropped2 1; and break
    sleep 5
end
set -q dropped2
check "phase 2: forward dead while banned (localhost:8080 → 000)" 0 $status

tailscale ssh user@vm1 -- hostname >/dev/null 2>&1
check "phase 2: tailnet path unaffected (tailscale ssh user@vm1)" 0 $status

echo "== Phase 2 release =="
rroot vm1 cscli decisions delete -i 10.0.2.2 >/dev/null 2>&1
echo "waiting for bouncer to pick up the deletion (~15s) ..."
for i in (seq 12)
    test (codeof http://localhost:8080/) = 200; and set back2 1; and break
    sleep 5
end
set -q back2
check "phase 2: forward answers again (localhost:8080 → 200)" 0 $status

echo "--- cscli decisions list (released) ---"
set dl (rroot vm1 cscli decisions list 2>/dev/null)
printf '%s\n' $dl
if string match -q '*10.0.2.2*' -- $dl
    check "ban gone from decisions list" gone present
else
    check "ban gone from decisions list" gone gone
end
echo "---------------------------------------"

echo
echo "passed: $pass_count  failed: $fail_count"
test $fail_count -eq 0
