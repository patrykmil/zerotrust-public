#!/usr/bin/env fish

if test (count $argv) -eq 0
    set vms vm6 vm5 vm4 vm3 vm2 vm1
else
    set vms
    for n in $argv
        if string match -qr '^[1-6]$' -- $n
            set -a vms vm$n
        else
            echo "skip invalid vm: $n (valid: 1-6)" >&2
        end
    end
end

for v in $vms; \
    wezterm cli spawn --new-window --cwd . -- nix run .#$v; \
end