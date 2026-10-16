# modules/tetragon.nix: eBPF runtime detection on the workload VMs.
#
# Purpose: syscall-level tripwires below the network layer — shell execs
#   and sensitive file opens on machines that should do neither.
# Contents: shell-spawn (bash/dash exec) + sensitive-file-open
#   (/etc/shadow, /etc/gshadow) TracingPolicies, events.json export,
#   Alloy → Loki on vm4.
# VMs: vm5 + vm6.
{
  config,
  pkgs,
  lib,
  role,
  ...
}:

let
  isWorkload = role == "vm5" || role == "vm6";

  shellSpawnPolicy = pkgs.writeText "shell-spawn.yaml" ''
    apiVersion: cilium.io/v1alpha1
    kind: TracingPolicy
    metadata:
      name: "shell-spawn"
    spec:
      lsmhooks:
      - hook: "bprm_check_security"
        args:
          - index: 0
            type: "linux_binprm"
        selectors:
        - matchBinaries:
          - operator: "Postfix"
            values:
            - "bash"
            - "dash"
  '';

  shadowPolicy = pkgs.writeText "sensitive-file-open.yaml" ''
    apiVersion: cilium.io/v1alpha1
    kind: TracingPolicy
    metadata:
      name: "sensitive-file-open"
    spec:
      lsmhooks:
      - hook: "file_open"
        args:
          - index: 0
            type: "file"
        selectors:
        - matchArgs:
          - index: 0
            operator: "Equal"
            values:
            - "/etc/shadow"
            - "/etc/gshadow"
  '';
in
{
  config = lib.mkIf isWorkload {

    environment.etc."tetragon/policies/shell-spawn.yaml".source = shellSpawnPolicy;
    environment.etc."tetragon/policies/sensitive-file-open.yaml".source = shadowPolicy;

    systemd.tmpfiles.rules = [ "d /var/log/tetragon 0750 root root - -" ];

    systemd.services.tetragon = {
      description = "Tetragon eBPF runtime security observability";
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      serviceConfig = {
        Type = "simple";
        ExecStart = ''
          ${pkgs.tetragon}/bin/tetragon \
            --tracing-policy-dir /etc/tetragon/policies \
            --export-filename /var/log/tetragon/events.json \
            --export-file-perm 0640 \
            --metrics-server 127.0.0.1:2112 \
            --health-server-address 127.0.0.1:6789
        '';
        Restart = "on-failure";
        RestartSec = "5s";
      };
    };

    # ── Grafana Alloy (Tetragon events → Loki on vm4) ────────────
    services.alloy = {
      enable = true;
      extraFlags = [ "--server.http.listen-addr=127.0.0.1:12345" ];
    };

    environment.etc."alloy/config.alloy".text = ''
      loki.write "loki" {
          endpoint {
              url = "http://vm4:3100/loki/api/v1/push"
          }
      }

      local.file_match "tetragon" {
          path_targets = [{__path__ = "/var/log/tetragon/events.json"}]
      }
      loki.source.file "tetragon" {
          targets    = local.file_match.tetragon.targets
          forward_to = [loki.process.tetragon.receiver]
          tail_from_end = true
      }
      loki.process "tetragon" {
          stage.static_labels {
              values = { job = "tetragon", host = "${role}" }
          }
          forward_to = [loki.write.loki.receiver]
      }
    '';

    systemd.services.alloy.serviceConfig = {
      User = lib.mkForce "root";
      Group = lib.mkForce "root";
      DynamicUser = lib.mkForce false;
    };
  };
}
