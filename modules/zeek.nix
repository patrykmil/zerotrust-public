# modules/zeek.nix: Zeek network monitor + log shipper on the sensor.
#
# Purpose: metadata/behavioral visibility (conn/dns/http/ssl/notice)
#   complementing Suricata's signatures; logs flow to Loki for Grafana.
# Contents: zeek on tailscale0 (vm3's own flows only), Alloy tails
#   conn/dns/http/ssl/notice.log plus Suricata eve.json → Loki on vm4.
# VMs: vm3 only.
{
  config,
  pkgs,
  lib,
  role,
  ...
}:

let
  isZeekSensor = role == "vm3";
  iface = "tailscale0";
in
{
  config = lib.mkIf isZeekSensor {
    environment.systemPackages = with pkgs; [ zeek ];

    environment.etc."zeek/local.zeek".text = ''
      @load base/protocols/conn
      @load base/protocols/dns
      @load base/protocols/http
      @load base/protocols/ssl
    '';

    systemd.tmpfiles.settings."10-zeek" = {
      "/var/log/zeek".d = {
        mode = "0755";
        user = "root";
        group = "root";
      };
    };

    # ── Zeek network monitor ──────────────────────────────────────
    systemd.services.zeek = {
      description = "Zeek Network Security Monitor";
      after = [
        "network.target"
        "tailscaled.service"
      ];
      wants = [ "tailscaled.service" ];
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        Type = "simple";
        ExecStart = "${pkgs.zeek}/bin/zeek -i ${iface} /etc/zeek/local.zeek";
        ExecReload = "${pkgs.coreutils}/bin/kill -HUP \$MAINPID";
        Restart = "on-failure";
        RestartSec = "5";
        WorkingDirectory = "/var/log/zeek";
        StandardOutput = "journal";
        StandardError = "journal";
      };
    };

    # ── Grafana Alloy (Zeek log → Loki shipper) ──────────────────
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


      local.file_match "zeek_conn" {
          path_targets = [{__path__ = "/var/log/zeek/conn.log"}]
      }
      loki.source.file "zeek_conn" {
          targets    = local.file_match.zeek_conn.targets
          forward_to = [loki.process.conn.receiver]
          tail_from_end = true
      }
      loki.process "conn" {
          stage.drop { expression = "^#.*" }
          stage.static_labels { values = { job = "zeek", type = "conn" } }
          forward_to = [loki.write.loki.receiver]
      }

      local.file_match "zeek_dns" {
          path_targets = [{__path__ = "/var/log/zeek/dns.log"}]
      }
      loki.source.file "zeek_dns" {
          targets    = local.file_match.zeek_dns.targets
          forward_to = [loki.process.dns.receiver]
          tail_from_end = true
      }
      loki.process "dns" {
          stage.drop { expression = "^#.*" }
          stage.static_labels { values = { job = "zeek", type = "dns" } }
          forward_to = [loki.write.loki.receiver]
      }

      local.file_match "zeek_http" {
          path_targets = [{__path__ = "/var/log/zeek/http.log"}]
      }
      loki.source.file "zeek_http" {
          targets    = local.file_match.zeek_http.targets
          forward_to = [loki.process.http.receiver]
          tail_from_end = true
      }
      loki.process "http" {
          stage.drop { expression = "^#.*" }
          stage.static_labels { values = { job = "zeek", type = "http" } }
          forward_to = [loki.write.loki.receiver]
      }

      local.file_match "zeek_ssl" {
          path_targets = [{__path__ = "/var/log/zeek/ssl.log"}]
      }
      loki.source.file "zeek_ssl" {
          targets    = local.file_match.zeek_ssl.targets
          forward_to = [loki.process.ssl.receiver]
          tail_from_end = true
      }
      loki.process "ssl" {
          stage.drop { expression = "^#.*" }
          stage.static_labels { values = { job = "zeek", type = "ssl" } }
          forward_to = [loki.write.loki.receiver]
      }

      local.file_match "zeek_notice" {
          path_targets = [{__path__ = "/var/log/zeek/notice.log"}]
      }
      loki.source.file "zeek_notice" {
          targets    = local.file_match.zeek_notice.targets
          forward_to = [loki.process.notice.receiver]
          tail_from_end = true
      }
      loki.process "notice" {
          stage.drop { expression = "^#.*" }
          stage.static_labels { values = { job = "zeek", type = "notice" } }
          forward_to = [loki.write.loki.receiver]
      }

      local.file_match "suricata_eve" {
          path_targets = [{__path__ = "/var/log/suricata/eve.json"}]
      }
      loki.source.file "suricata_eve" {
          targets    = local.file_match.suricata_eve.targets
          forward_to = [loki.process.suricata.receiver]
          tail_from_end = true
      }
      loki.process "suricata" {
          stage.static_labels { values = { job = "suricata" } }
          stage.json {
              expressions = { event_type = "event_type", signature = "alert.signature" }
          }
          stage.labels { values = { event_type = "", signature = "" } }
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
