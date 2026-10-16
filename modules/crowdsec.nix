# modules/crowdsec.nix: active response — detect, decide, firewall-ban.
#
# Purpose: turn SSH brute force and HTTP 4xx storms into 30-minute
#   iptables DROPs of the offending source IP at the gateway.
# Contents: engine + firewall bouncer, testzero/caddy-json parser over the
#   Caddy access log, testzero/http-probing scenario + hub
#   crowdsecurity/linux (sshd), testzero-ban-30m profile, :6060 metrics.
# VMs: vm1 only (scraped by vm2).
{
  config,
  pkgs,
  lib,
  role,
  ...
}:

let
  isGateway = role == "vm1";

  configFile =
    (pkgs.formats.yaml { }).generate "crowdsec.yaml"
      config.services.crowdsec.settings.general;

  caddyParser = {
    name = "testzero/caddy-json";
    description = "parse Caddy JSON access logs";
    filter = "evt.Line.Labels.type == 'caddy' && evt.Line.Raw startsWith '{'";
    onsuccess = "next_stage";
    statics = [
      {
        meta = "log_type";
        value = "http-caddy";
      }
      {
        meta = "source_ip";
        expression = ''JsonExtract(evt.Line.Raw, "request.remote_ip")'';
      }
      {
        meta = "http_path";
        expression = ''JsonExtract(evt.Line.Raw, "request.uri")'';
      }
      {
        meta = "http_method";
        expression = ''JsonExtract(evt.Line.Raw, "request.method")'';
      }
      {
        meta = "http_status";
        expression = ''JsonExtract(evt.Line.Raw, "status")'';
      }
    ];
  };

  httpProbingScenario = {
    type = "leaky";
    name = "testzero/http-probing";
    description = "HTTP 4xx storm from one source IP (scan / auth brute force)";
    filter = "evt.Meta.log_type == 'http-caddy' && evt.Meta.http_status in ['400', '401', '403', '404', '405']";
    groupby = "evt.Meta.source_ip";
    leakspeed = "1m";
    capacity = 5;
    cache_size = 20;
    labels = {
      remediation = true;
    };
  };
in
{
  config = lib.mkIf isGateway {

    services.crowdsec = {
      enable = true;
      name = "testzero-gateway";
      autoUpdateService = true;

      hub.collections = [ "crowdsecurity/linux" ];

      settings = {
        lapi.credentialsFile = "/var/lib/crowdsec/lapi.yaml";
        capi.credentialsFile = "/var/lib/crowdsec/capi.yaml";
        general = {
          api.server = {
            enable = true;
            listen_uri = "127.0.0.1:8081";
            online_client = {
              sharing = false;
              pull.community = false;
              pull.blocklists = false;
            };
          };
          prometheus.listen_addr = "0.0.0.0";
        };
      };

      localConfig = {
        acquisitions = [
          {
            filename = "/var/log/caddy/access-:8080.log";
            labels.type = "caddy";
            mode = "tail";
          }
          {
            journalctl_filter = [ "_SYSTEMD_UNIT=sshd.service" ];
            labels.type = "syslog";
            mode = "tail";
          }
        ];

        parsers.s01Parse = [ caddyParser ];
        scenarios = [ httpProbingScenario ];

        profiles = [
          {
            name = "testzero-ban-30m";
            filters = [ ''Alert.Remediation == true && Alert.GetScope() == "Ip"'' ];
            decisions = [
              {
                type = "ban";
                duration = "30m";
              }
            ];
            notifications = [ ];
            on_success = "break";
          }
        ];
      };
    };

    systemd.services.crowdsec.path = lib.mkForce [ pkgs.systemd ];

    systemd.services.crowdsec.serviceConfig.DynamicUser = lib.mkForce false;
    systemd.services.crowdsec-update-hub.serviceConfig.DynamicUser = lib.mkForce false;

    systemd.services.crowdsec-update-hub.serviceConfig.ExecStartPost =
      lib.mkForce "+systemctl try-reload-or-restart crowdsec.service";

    systemd.services.crowdsec.serviceConfig.TimeoutStartSec = lib.mkForce 600;

    systemd.services.crowdsec-firewall-bouncer.serviceConfig = {
      Restart = lib.mkForce "on-failure";
      RestartSec = lib.mkForce "10s";
    };
    systemd.services.crowdsec-firewall-bouncer-register.serviceConfig.Restart =
      lib.mkForce "on-failure";

    services.crowdsec-firewall-bouncer = {
      enable = true;
      registerBouncer.enable = true;
    };

    systemd.services.crowdsec-machine-init = {
      description = "Ensure the CrowdSec LAPI machine exists and has credentials";
      wantedBy = [ "multi-user.target" ];
      before = [ "crowdsec.service" ];
      path = [ config.system.path ];
      serviceConfig = {
        Type = "oneshot";
        User = "crowdsec";
        Group = "crowdsec";
        UMask = "0077";
        Environment = "USER=crowdsec";
        ExecStart = pkgs.writeShellScript "crowdsec-machine-init" ''
          set -eu
          cscli machines add testzero-gateway --auto --force
        '';
      };
    };

    systemd.services.crowdsec-firewall-bouncer-register.serviceConfig = {
      DynamicUser = lib.mkForce false;
      StateDirectory = lib.mkForce "crowdsec-firewall-bouncer-register";
    };

    networking.firewall.interfaces.tailscale0.allowedTCPPorts = [ 6060 ];

    systemd.tmpfiles.settings."10-crowdsec-root" = {
      "/var/lib/crowdsec" = {
        d = {
          user = "crowdsec";
          group = "crowdsec";
          mode = "0750";
        };
      };
    };

    users.users.crowdsec.extraGroups = [ "caddy" ];

    systemd.tmpfiles.settings."10-crowdsec-config" = {
      "/etc/crowdsec/config.yaml" = {
        link = {
          type = "L+";
          argument = "${configFile}";
        };
      };
    };
  };
}
