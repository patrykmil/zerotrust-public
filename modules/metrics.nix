# modules/metrics.nix: metrics collection and fleet alerting.
#
# Purpose: scrape every exporter into one TSDB, evaluate alert rules, and
#   feed the Grafana fleet dashboard.
# Contents: node-exporter on all VMs :9100 (tailnet-only); vm1 opens
#   authentik :9300; vm2 runs VictoriaMetrics :8428 (jobs: node, authentik,
#   grafana, loki, opa, crowdsec) + vmalert :8880 (ScrapeTargetDown,
#   NodeHighMemoryUsage, NodeHighCpuUsage); vm4 provisions the
#   VictoriaMetrics datasource + VM Fleet dashboard.
# VMs: all for node-exporter; VictoriaMetrics/vmalert on vm2, datasource
#   wiring on vm4, authentik target on vm1.
{
  config,
  pkgs,
  lib,
  role,
  credentials,
  ...
}:

let
  isMetrics = role == "vm2";
  isGateway = role == "vm1";
  isDashboard = role == "vm4";
  vmPort = 8428;
  nodePort = 9100;

  fleetDashboard = pkgs.writeText "fleet-dashboard.json" (
    builtins.toJSON {
      title = "VM Fleet";
      uid = "vm-fleet";
      tags = [
        "metrics"
        "vminfrastructure"
      ];
      schemaVersion = 39;
      version = 1;
      refresh = "30s";
      timezone = "browser";
      panels = [
        {
          title = "CPU Usage %";
          type = "timeseries";
          gridPos = {
            h = 8;
            w = 12;
            x = 0;
            y = 0;
          };
          datasource = {
            type = "prometheus";
            uid = "vmetrics";
          };
          targets = [
            {
              expr = "100 - (avg by (instance) (rate(node_cpu_seconds_total{mode=\"idle\"}[$__rate_interval])) * 100)";
              legendFormat = "{{instance}}";
              refId = "A";
            }
          ];
          fieldConfig = {
            defaults = {
              unit = "percent";
              min = 0;
              max = 100;
            };
            overrides = [ ];
          };
        }
        {
          title = "Memory Usage %";
          type = "timeseries";
          gridPos = {
            h = 8;
            w = 12;
            x = 12;
            y = 0;
          };
          datasource = {
            type = "prometheus";
            uid = "vmetrics";
          };
          targets = [
            {
              expr = "(1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100";
              legendFormat = "{{instance}}";
              refId = "A";
            }
          ];
          fieldConfig = {
            defaults = {
              unit = "percent";
              min = 0;
              max = 100;
            };
            overrides = [ ];
          };
        }
        {
          title = "Scrape Targets Up";
          type = "timeseries";
          gridPos = {
            h = 8;
            w = 24;
            x = 0;
            y = 8;
          };
          datasource = {
            type = "prometheus";
            uid = "vmetrics";
          };
          targets = [
            {
              expr = "up";
              legendFormat = "{{job}} ({{instance}})";
              refId = "A";
            }
          ];
          fieldConfig = {
            defaults = {
              unit = "none";
              min = 0;
              max = 1;
            };
            overrides = [ ];
          };
        }
        {
          title = "Firing Alerts";
          type = "table";
          gridPos = {
            h = 8;
            w = 24;
            x = 0;
            y = 16;
          };
          datasource = {
            type = "prometheus";
            uid = "vmetrics";
          };
          targets = [
            {
              expr = "ALERTS{alertstate=\"firing\"}";
              instant = true;
              format = "table";
              refId = "A";
            }
          ];
        }
      ];
    }
  );
in
{
  config = lib.mkMerge [

    # ── All VMs: expose system metrics (tailnet-only) ──────────────
    {
      services.prometheus.exporters.node = {
        enable = true;
        listenAddress = "0.0.0.0";
        port = nodePort;
        enabledCollectors = [ "systemd" ];
      };
      networking.firewall.interfaces.tailscale0.allowedTCPPorts = [ nodePort ];
    }

    # ── vm1: let the collector reach authentik metrics ────────────
    (lib.mkIf isGateway {
      networking.firewall.interfaces.tailscale0.allowedTCPPorts = [ 9300 ];
    })

    # ── vm2: VictoriaMetrics + vmalert ─────────────────────────────
    (lib.mkIf isMetrics {
      services.victoriametrics = {
        enable = true;
        listenAddress = "0.0.0.0:${builtins.toString vmPort}";
        retentionPeriod = "15d";
        prometheusConfig = {
          global.scrape_interval = "15s";
          scrape_configs = [
            {
              job_name = "node";
              static_configs = [
                {
                  targets = [
                    "vm1:${builtins.toString nodePort}"
                    "vm2:${builtins.toString nodePort}"
                    "vm3:${builtins.toString nodePort}"
                    "vm4:${builtins.toString nodePort}"
                  ];
                }
              ];
            }
            {
              job_name = "authentik";
              metrics_path = "/metrics";
              static_configs = [ { targets = [ "vm1:9300" ]; } ];
            }
            {
              job_name = "grafana";
              metrics_path = "/grafana/metrics";
              basic_auth = {
                username = credentials.grafana.adminUser;
                password = credentials.grafana.adminPassword;
              };
              static_configs = [ { targets = [ "vm4:3000" ]; } ];
            }
            {
              job_name = "loki";
              metrics_path = "/metrics";
              static_configs = [ { targets = [ "vm4:3100" ]; } ];
            }
            {
              job_name = "opa";
              metrics_path = "/metrics";
              authorization = {
                credentials = credentials.opa.token;
              };
              static_configs = [ { targets = [ "vm2:8181" ]; } ];
            }
            {
              job_name = "crowdsec";
              metrics_path = "/metrics";
              static_configs = [ { targets = [ "vm1:6060" ]; } ];
            }
          ];
        };
      };

      networking.firewall.allowedTCPPorts = [
        vmPort
        8880
      ];

      virtualisation.forwardPorts = [
        {
          from = "host";
          host.port = vmPort;
          guest.port = vmPort;
        }
        {
          from = "host";
          host.port = 8880;
          guest.port = 8880;
        }
      ];

      services.vmalert.instances.testzero = {
        enable = true;
        settings = {
          "notifier.blackhole" = "true";
          "datasource.url" = "http://127.0.0.1:${builtins.toString vmPort}";
          "remoteWrite.url" = "http://127.0.0.1:${builtins.toString vmPort}";
          "httpListenAddr" = "0.0.0.0:8880";
        };
        rules.groups = [
          {
            name = "testzero-infrastructure";
            interval = "30s";
            rules = [
              {
                alert = "ScrapeTargetDown";
                expr = "up == 0";
                for = "2m";
                labels.severity = "critical";
                annotations.summary = "Scrape target {{ $labels.job }} on {{ $labels.instance }} is down for 2m";
              }
              {
                alert = "NodeHighMemoryUsage";
                expr = "(1 - node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes) * 100 > 90";
                for = "5m";
                labels.severity = "warning";
                annotations.summary = "Memory usage > 90% for 5m on {{ $labels.instance }}";
              }
              {
                alert = "NodeHighCpuUsage";
                expr = "100 - avg by (instance) (rate(node_cpu_seconds_total{mode=\"idle\"}[2m])) * 100 > 85";
                for = "5m";
                labels.severity = "warning";
                annotations.summary = "CPU usage > 85% for 5m on {{ $labels.instance }}";
              }
            ];
          }
        ];
      };
    })

    # ── vm4: Grafana gets the VictoriaMetrics datasource + fleet dashboard ──
    (lib.mkIf isDashboard {
      services.grafana.provision.datasources.settings.datasources = [
        {
          name = "VictoriaMetrics";
          uid = "vmetrics";
          type = "prometheus";
          access = "proxy";
          url = "http://vm2:${builtins.toString vmPort}";
          isDefault = false;
        }
      ];

      services.grafana.provision.dashboards.settings.providers = [
        {
          name = "Metrics";
          options.path = "/etc/grafana/dashboards/metrics";
          orgId = 1;
          type = "file";
          updateIntervalSeconds = 30;
        }
      ];

      environment.etc."grafana/dashboards/metrics/fleet.json".source = fleetDashboard;
    })
  ];
}
