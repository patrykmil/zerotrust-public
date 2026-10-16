# modules/vulnscan.nix: supply-chain scanning — vulnix + SBOM on all VMs.
#
# Purpose: watch what the fleet IS MADE OF (closure vs NVD feed) while
#   behavioral sensors watch what it does; findings feed Loki + alerts.
# Contents: daily vulnix-scan (findings.log → Loki), weekly sbom-generate
#   (CycloneDX/SPDX in /var/lib/sbom), Alloy shipper, committed
#   false-positive whitelist.
# VMs: all (vm1–vm6).
{
  config,
  pkgs,
  lib,
  role,
  ...
}:

let
  whitelist = ../variables/vulnix-whitelist.toml;

  lokiUrl = if role == "vm4" then "http://127.0.0.1:3100" else "http://vm4:3100";

  toFindings = pkgs.writeText "vulnix-to-findings.jq" ''
    [ .[]
      | .name as $name
      | (.affected_by // [])[] as $cve
      | {
          host: $host,
          package: $name,
          cve: $cve,
          score: ((.cvssv3_basescore[$cve] // "0") | tonumber),
          kev: (((.known_exploited // []) | index($cve)) != null)
        }
      | .severity = (
          if .score >= 9 then "critical"
          elif .score >= 7 then "high"
          elif .score >= 4 then "medium"
          else "low"
          end)
    ]
    | sort_by(-.score)[]
    | tostring
  '';

  scanScript = pkgs.writeShellScript "vulnix-scan" ''
    set -eu
    umask 022
    mkdir -p /var/log/sbom /var/cache/vulnix
    export NIX_CONFIG="experimental-features = nix-command flakes"
    SYSTEM=$(readlink -f /run/current-system)

    rc=0
    ${pkgs.vulnix}/bin/vulnix -j -C \
      -w ${whitelist} \
      -c /var/cache/vulnix \
      "$SYSTEM" \
      > /var/log/sbom/vulnix.json.tmp \
      2> /var/log/sbom/vulnix.err || rc=$?
    if [ "$rc" -ne 0 ] && [ "$rc" -ne 2 ]; then
      echo "vulnix failed with exit code $rc:" >&2
      cat /var/log/sbom/vulnix.err >&2
      exit "$rc"
    fi

    if [ ! -s /var/log/sbom/vulnix.json.tmp ]; then
      echo "[]" > /var/log/sbom/vulnix.json.tmp
    fi
    mv /var/log/sbom/vulnix.json.tmp /var/log/sbom/vulnix.json
    chmod 0644 /var/log/sbom/vulnix.json
    if [ "$(cat /var/log/sbom/vulnix.json)" = "[]" ]; then
      : > /var/log/sbom/findings.log.new
    else
      ${pkgs.jq}/bin/jq -cer --arg host "${role}" -f ${toFindings} \
        < /var/log/sbom/vulnix.json > /var/log/sbom/findings.log.new
    fi
    mv /var/log/sbom/findings.log.new /var/log/sbom/findings.log
    chmod 0644 /var/log/sbom/findings.log

    count=$(wc -l < /var/log/sbom/findings.log)
    echo "vulnix: $count CVE finding(s) on ${role} (rc=$rc)"
  '';

  sbomScript = pkgs.writeShellScript "sbom-generate" ''
    set -eu
    export HOME=/root
    mkdir -p /var/lib/sbom /var/log/sbom
    cd /var/lib/sbom
    rm -f sbom.cdx.json sbom.spdx.json sbom.csv

    SYSTEM=$(readlink -f /run/current-system)
    set +e
    ${pkgs.sbomnix}/bin/sbomnix "$SYSTEM" \
      > /var/log/sbom/sbom.log 2>&1
    rc=$?
    set -e
    cat /var/log/sbom/sbom.log
    if [ $rc -ne 0 ]; then
      if grep -q "No deriver found" /var/log/sbom/sbom.log; then
        echo "sbomnix: no deriver for $SYSTEM (keep-derivations was off), falling back to closure enumeration" | tee -a /var/log/sbom/sbom.log
        CLOSURE=$(${pkgs.nix}/bin/nix-store -qR "$SYSTEM")
        UUID=$(cat /proc/sys/kernel/random/uuid)
        TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
        # Build components via jq: each store path -> {name, version, bom-ref, purl}
        printf "%s\n" "$CLOSURE" | ${pkgs.jq}/bin/jq -R -s --arg uuid "$UUID" --arg ts "$TS" --arg system "$SYSTEM" '
          split("\n") | map(select(length>0)) as $paths
          | {
              bomFormat: "CycloneDX",
              specVersion: "1.4",
              version: 1,
              serialNumber: ("urn:uuid:" + $uuid),
              metadata: {
                timestamp: $ts,
                properties: [{name:"sbom_type", value:"runtime_only"}, {name:"sbom_fallback", value:"closure"}],
                tools: [{vendor:"TII", name:"sbomnix", version:"1.7.6"}],
                component: {
                  type: "application",
                  "bom-ref": $system,
                  name: "nixos-system-${role}",
                  version: "0",
                  purl: "pkg:nix/nixos-system-${role}@0"
                }
              },
              components: ($paths | map(
                . as $p
                | capture("/nix/store/[^-]+-(?<base>.+)")
                | .base as $b
                | ($b | capture("(?<name>.+)-(?<ver>[0-9].*)") // {name:$b, ver:""}) as $nv
                | {
                    type: "library",
                    "bom-ref": $p,
                    name: $nv.name,
                    version: $nv.ver,
                    purl: ("pkg:nix/" + $nv.name + (if $nv.ver != "" then ("@" + $nv.ver) else "" end)),
                    properties: [{name:"nix:output_path", value: $p}]
                  }
              ) | unique_by(."bom-ref")),
              dependencies: []
            }
        ' > sbom.cdx.json
        printf "%s\n" "$CLOSURE" | ${pkgs.jq}/bin/jq -R -s --arg uuid "$UUID" --arg ts "$TS" '
          split("\n") | map(select(length>0)) as $paths
          | {
              spdxVersion: "SPDX-2.3",
              dataLicense: "CC0-1.0",
              SPDXID: "SPDXRef-DOCUMENT",
              name: ("SPDXRef-nixos-system-${role}"),
              documentNamespace: ("sbomnix://" + $uuid),
              creationInfo: {created: $ts, creators: ["Tool: sbomnix-1.7.6-fallback"]},
              comment: "included dependencies: runtime_only (fallback closure)",
              packages: ($paths | map(
                . as $p
                | capture("/nix/store/[^-]+-(?<base>.+)")
                | .base as $b
                | ($b | capture("(?<name>.+)-(?<ver>[0-9].*)") // {name:$b, ver:""}) as $nv
                | {
                    name: $nv.name,
                    SPDXID: ("SPDXRef-" + ($p | gsub("[^a-zA-Z0-9.-]"; "-"))),
                    versionInfo: $nv.ver,
                    downloadLocation: "NOASSERTION",
                    licenseConcluded: "NOASSERTION",
                    licenseDeclared: "NOASSERTION",
                    copyrightText: "NOASSERTION",
                    externalRefs: [{referenceCategory:"PACKAGE-MANAGER", referenceType:"purl", referenceLocator: ("pkg:nix/" + $nv.name + (if $nv.ver != "" then ("@" + $nv.ver) else "" end))}]
                  }
              ) | unique_by(.SPDXID)),
              relationships: []
            }
        ' > sbom.spdx.json
        rc=0
      else
        echo "sbomnix failed (rc=$rc), see /var/log/sbom/sbom.log" >&2
        exit $rc
      fi
    fi
    if [ ! -f sbom.cdx.json ] || [ ! -f sbom.spdx.json ]; then
      echo "sbomnix did not produce expected files" >&2
      ls -l >> /var/log/sbom/sbom.log 2>&1 || true
      exit 1
    fi

    mv sbom.cdx.json  ${role}.cdx.json
    mv sbom.spdx.json ${role}.spdx.json
    rm -f sbom.csv
    chmod 0644 ${role}.cdx.json ${role}.spdx.json
    chmod 0644 /var/log/sbom/sbom.log
    echo "SBOM written: /var/lib/sbom/${role}.{cdx,spdx}.json"
  '';
in
{
  config = {

    nix.settings.experimental-features = [ "nix-command" "flakes" ];
    nix.settings.keep-derivations = true;
    nix.settings.keep-outputs = true;

    # ── Daily vulnerability scan ──────────────────────────────────
    systemd.services.vulnix-scan = {
      description = "Vulnix CVE scan of the current system closure";
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      serviceConfig = {
        Type = "oneshot";
        User = "root";
        Group = "root";
        Environment = [
          "LANG=C.UTF-8"
          "LC_ALL=C.UTF-8"
          "LOCALE_ARCHIVE=${pkgs.glibcLocales}/lib/locale/locale-archive"
          "NIX_CONFIG=experimental-features = nix-command flakes"
        ];
        ExecStart = scanScript;
        TimeoutStartSec = 1800;
      };
    };
    systemd.timers.vulnix-scan = {
      description = "Daily vulnix scan";
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnCalendar = "daily";
        RandomizedDelaySec = "30m";
        Persistent = true;
      };
    };

    # ── Weekly SBOM generation ────────────────────────────────────
    systemd.services.sbom-generate = {
      description = "Generate CycloneDX + SPDX SBOM of the system closure";
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      serviceConfig = {
        Type = "oneshot";
        User = "root";
        Group = "root";
        Environment = "HOME=/root";
        ExecStart = sbomScript;
        TimeoutStartSec = 900;
      };
    };
    systemd.timers.sbom-generate = {
      description = "Weekly SBOM refresh";
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnCalendar = "Mon *-*-* 04:30:00";
        RandomizedDelaySec = "15m";
        Persistent = true;
      };
    };

    systemd.tmpfiles.settings."25-sbom-dirs" = {
      "/var/log/sbom"."d" = {
        user = "root";
        group = "root";
        mode = "0755";
      };
      "/var/cache/vulnix"."d" = {
        user = "root";
        group = "root";
        mode = "0700";
      };
      "/var/lib/sbom"."d" = {
        user = "root";
        group = "root";
        mode = "0755";
      };
    };

    services.alloy.enable = true;

    environment.etc."alloy/vulnix.alloy".text = ''
      // Vulnerability findings (vulnix) → Loki on vm4.
      loki.write "vulnix" {
          endpoint {
              url = "${lokiUrl}/loki/api/v1/push"
          }
      }

      local.file_match "vulnix_findings" {
          path_targets = [{__path__ = "/var/log/sbom/findings.log"}]
      }
      loki.source.file "vulnix_findings" {
          targets       = local.file_match.vulnix_findings.targets
          forward_to    = [loki.process.vulnix.receiver]
          tail_from_end = true
      }
      loki.process "vulnix" {
          stage.static_labels {
              values = { job = "vulnix", host = "${role}" }
          }
          forward_to = [loki.write.vulnix.receiver]
      }
    '';
  };
}
