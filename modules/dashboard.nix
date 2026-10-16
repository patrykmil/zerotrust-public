# modules/dashboard.nix: observability frontend — Loki + Grafana.
#
# Purpose: single pane for every sensor feed: Zeek, Suricata, Tetragon,
#   authz decisions and vulnix findings, plus infra alert rules.
# Contents: Loki :3100 (filesystem store), Grafana :3000 under /grafana/
#   (auth-proxy via gateway headers), provisioned dashboards (Zeek,
#   Tetragon, Authz, Suricata, Vulnix) and alert rules
#   (SuricataSignatureFired, AuthzDeniedFired, TetragonEventFired,
#   VulnixHighSeverityFound).
# VMs: vm4 only.
{
  config,
  pkgs,
  lib,
  role,
  credentials,
  ...
}:

let
  isDashboard = role == "vm4";

  zeekDashboard = pkgs.writeText "zeek-dashboard.json" (
    builtins.toJSON {
      title = "Zeek Overview";
      uid = "zeek-overview";
      tags = [
        "zeek"
        "security"
      ];
      schemaVersion = 39;
      version = 1;
      refresh = "30s";
      timezone = "browser";
      panels = [
        {
          title = "Connections";
          type = "timeseries";
          gridPos = {
            h = 8;
            w = 12;
            x = 0;
            y = 0;
          };
          targets = [
            {
              expr = "count_over_time({job=\"zeek\", type=\"conn\"}[$__interval])";
              legendFormat = "connections";
              refId = "A";
            }
          ];
          fieldConfig = {
            defaults = {
              unit = "short";
            };
            overrides = [ ];
          };
        }
        {
          title = "DNS Queries";
          type = "timeseries";
          gridPos = {
            h = 8;
            w = 12;
            x = 12;
            y = 0;
          };
          targets = [
            {
              expr = "count_over_time({job=\"zeek\", type=\"dns\"}[$__interval])";
              legendFormat = "queries";
              refId = "A";
            }
          ];
          fieldConfig = {
            defaults = {
              unit = "short";
            };
            overrides = [ ];
          };
        }
        {
          title = "HTTP Requests";
          type = "timeseries";
          gridPos = {
            h = 8;
            w = 12;
            x = 0;
            y = 8;
          };
          targets = [
            {
              expr = "count_over_time({job=\"zeek\", type=\"http\"}[$__interval])";
              legendFormat = "requests";
              refId = "A";
            }
          ];
          fieldConfig = {
            defaults = {
              unit = "short";
            };
            overrides = [ ];
          };
        }
        {
          title = "SSL/TLS Connections";
          type = "timeseries";
          gridPos = {
            h = 8;
            w = 12;
            x = 12;
            y = 8;
          };
          targets = [
            {
              expr = "count_over_time({job=\"zeek\", type=\"ssl\"}[$__interval])";
              legendFormat = "connections";
              refId = "A";
            }
          ];
          fieldConfig = {
            defaults = {
              unit = "short";
            };
            overrides = [ ];
          };
        }
      ];
    }
  );

  tetragonDashboard = pkgs.writeText "tetragon-dashboard.json" (
    builtins.toJSON {
      title = "Runtime Security (Tetragon)";
      uid = "tetragon-runtime";
      tags = [
        "tetragon"
        "security"
      ];
      schemaVersion = 39;
      version = 1;
      refresh = "10s";
      timezone = "browser";
      panels = [
        {
          title = "Detection events over time";
          type = "timeseries";
          gridPos = {
            h = 9;
            w = 24;
            x = 0;
            y = 0;
          };
          datasource = {
            type = "loki";
            uid = "loki";
          };
          targets = [
            {
              expr = "sum(count_over_time({job=\"tetragon\"} |= \"shell-spawn\" [$__interval]))";
              legendFormat = "shell-spawn";
              refId = "A";
            }
            {
              expr = "sum(count_over_time({job=\"tetragon\"} |= \"sensitive-file-open\" [$__interval]))";
              legendFormat = "sensitive-file-open";
              refId = "B";
            }
          ];
          fieldConfig = {
            defaults = {
              unit = "short";
            };
            overrides = [ ];
          };
        }
        {
          title = "Recent runtime security events";
          type = "logs";
          gridPos = {
            h = 10;
            w = 24;
            x = 0;
            y = 9;
          };
          datasource = {
            type = "loki";
            uid = "loki";
          };
          targets = [
            {
              expr = "{job=\"tetragon\"}";
              refId = "A";
            }
          ];
          options = {
            showTime = true;
            wrapLogMessage = true;
            enableLogDetails = true;
          };
        }
      ];
    }
  );

  authzDashboard = pkgs.writeText "authz-dashboard.json" (
    builtins.toJSON {
      title = "Authz Decisions (OPA)";
      uid = "authz-decisions";
      tags = [
        "opa"
        "security"
      ];
      schemaVersion = 39;
      version = 1;
      refresh = "10s";
      timezone = "browser";
      panels = [
        {
          title = "Decisions over time";
          type = "timeseries";
          gridPos = {
            h = 9;
            w = 24;
            x = 0;
            y = 0;
          };
          datasource = {
            type = "loki";
            uid = "loki";
          };
          targets = [
            {
              expr = "sum(count_over_time({job=\"authz\"} | json | decision=\"allow\" [$__interval]))";
              legendFormat = "allow";
              refId = "A";
            }
            {
              expr = "sum(count_over_time({job=\"authz\"} | json | decision=\"deny\" [$__interval]))";
              legendFormat = "deny";
              refId = "B";
            }
          ];
          fieldConfig = {
            defaults = {
              unit = "short";
            };
            overrides = [ ];
          };
        }
        {
          title = "Recent decisions";
          type = "logs";
          gridPos = {
            h = 10;
            w = 24;
            x = 0;
            y = 9;
          };
          datasource = {
            type = "loki";
            uid = "loki";
          };
          targets = [
            {
              expr = "{job=\"authz\"} | json";
              refId = "A";
            }
          ];
          options = {
            showTime = true;
            wrapLogMessage = true;
            enableLogDetails = true;
          };
        }
      ];
    }
  );

  suricataDashboard = pkgs.writeText "suricata-dashboard.json" (
    builtins.toJSON {
      title = "Suricata Alerts";
      uid = "suricata-alerts";
      tags = [
        "suricata"
        "security"
      ];
      schemaVersion = 39;
      version = 1;
      refresh = "30s";
      timezone = "browser";
      panels = [
        {
          title = "Alerts over time";
          type = "timeseries";
          gridPos = {
            h = 9;
            w = 24;
            x = 0;
            y = 0;
          };
          datasource = {
            type = "loki";
            uid = "loki";
          };
          targets = [
            {
              expr = "sum by (signature) (count_over_time({job=\"suricata\"} | json | event_type=\"alert\" [$__interval]))";
              legendFormat = "{{signature}}";
              refId = "A";
            }
          ];
          fieldConfig = {
            defaults = {
              unit = "short";
            };
            overrides = [ ];
          };
        }
        {
          title = "Recent alerts";
          type = "logs";
          gridPos = {
            h = 9;
            w = 24;
            x = 0;
            y = 9;
          };
          datasource = {
            type = "loki";
            uid = "loki";
          };
          targets = [
            {
              expr = "{job=\"suricata\"} | json | event_type=\"alert\"";
              refId = "A";
            }
          ];
          options = {
            showTime = true;
            wrapLogMessage = true;
            enableLogDetails = true;
          };
        }
        {
          title = "Top signatures (range)";
          type = "bargauge";
          gridPos = {
            h = 6;
            w = 24;
            x = 0;
            y = 18;
          };
          datasource = {
            type = "loki";
            uid = "loki";
          };
          targets = [
            {
              expr = "topk(10, sum by (signature) (count_over_time({job=\"suricata\"} | json | event_type=\"alert\" [$__range])))";
              instant = true;
              legendFormat = "{{signature}}";
              refId = "A";
            }
          ];
          options = {
            reduceOptions = {
              values = false;
              calcs = [ "lastNotNull" ];
            };
            orientation = "horizontal";
          };
        }
      ];
    }
  );

  vulnixDashboard = pkgs.writeText "vulnix-dashboard.json" (
    builtins.toJSON {
      title = "Vulnerability Management";
      uid = "vulnix-mgmt";
      tags = [
        "vulnix"
        "sbom"
        "security"
      ];
      schemaVersion = 39;
      version = 1;
      refresh = "5m";
      timezone = "browser";
      panels = [
        {
          title = "Findings over time by severity";
          type = "timeseries";
          gridPos = {
            h = 9;
            w = 24;
            x = 0;
            y = 0;
          };
          datasource = {
            type = "loki";
            uid = "loki";
          };
          targets = [
            {
              expr = "sum(count_over_time({job=\"vulnix\"} | json | severity=\"critical\" [$__interval]))";
              legendFormat = "critical";
              refId = "A";
            }
            {
              expr = "sum(count_over_time({job=\"vulnix\"} | json | severity=\"high\" [$__interval]))";
              legendFormat = "high";
              refId = "B";
            }
            {
              expr = "sum(count_over_time({job=\"vulnix\"} | json | severity=\"medium\" [$__interval]))";
              legendFormat = "medium";
              refId = "C";
            }
            {
              expr = "sum(count_over_time({job=\"vulnix\"} | json | severity=\"low\" [$__interval]))";
              legendFormat = "low";
              refId = "D";
            }
          ];
          fieldConfig = {
            defaults = {
              unit = "short";
            };
            overrides = [ ];
          };
        }
        {
          title = "Open findings by severity (24h)";
          type = "bargauge";
          gridPos = {
            h = 8;
            w = 12;
            x = 0;
            y = 9;
          };
          datasource = {
            type = "loki";
            uid = "loki";
          };
          targets = [
            {
              expr = "sum by (severity) (count_over_time({job=\"vulnix\"} | json [24h]))";
              instant = true;
              legendFormat = "{{severity}}";
              refId = "A";
            }
          ];
          options = {
            reduceOptions = {
              values = false;
              calcs = [ "lastNotNull" ];
            };
            orientation = "horizontal";
          };
        }
        {
          title = "Most affected packages (24h)";
          type = "bargauge";
          gridPos = {
            h = 8;
            w = 12;
            x = 12;
            y = 9;
          };
          datasource = {
            type = "loki";
            uid = "loki";
          };
          targets = [
            {
              expr = "topk(10, sum by (package) (count_over_time({job=\"vulnix\"} | json [24h])))";
              instant = true;
              legendFormat = "{{package}}";
              refId = "A";
            }
          ];
          options = {
            reduceOptions = {
              values = false;
              calcs = [ "lastNotNull" ];
            };
            orientation = "horizontal";
          };
        }
        {
          title = "Recent findings";
          type = "logs";
          gridPos = {
            h = 10;
            w = 24;
            x = 0;
            y = 17;
          };
          datasource = {
            type = "loki";
            uid = "loki";
          };
          targets = [
            {
              expr = "{job=\"vulnix\"} | json";
              refId = "A";
            }
          ];
          options = {
            showTime = true;
            wrapLogMessage = true;
            enableLogDetails = true;
          };
        }
      ];
    }
  );
in
{
  config = lib.mkIf isDashboard {

    # ── Loki (log store) ──────────────────────────────────────────
    services.loki = {
      enable = true;
      configuration = {
        auth_enabled = false;
        server = {
          http_listen_port = 3100;
          http_listen_address = "0.0.0.0";
        };
        ingester = {
          lifecycler = {
            ring = {
              kvstore.store = "inmemory";
              replication_factor = 1;
            };
          };
          chunk_idle_period = "5m";
          chunk_retain_period = "30s";
        };
        schema_config = {
          configs = [
            {
              from = "2020-10-24";
              store = "tsdb";
              object_store = "filesystem";
              schema = "v13";
              index.prefix = "index_";
              index.period = "24h";
            }
          ];
        };
        storage_config = {
          tsdb_shipper = {
            active_index_directory = "/var/lib/loki/tsdb-index";
            cache_location = "/var/lib/loki/tsdb-cache";
          };
          filesystem.directory = "/var/lib/loki/chunks";
        };
        compactor = {
          working_directory = "/var/lib/loki/compactor";
          compactor_ring.kvstore.store = "inmemory";
        };
      };
    };

    # ── Grafana (visualization; auth-proxy and tailnet-only) ─────
    services.grafana = {
      enable = true;
      settings = {
        server = {
          http_addr = "0.0.0.0";
          http_port = 3000;
          serve_from_sub_path = true;
          root_url = "http://localhost:8080/grafana/";
        };
        security.admin_user = credentials.grafana.adminUser;
        security.admin_password = credentials.grafana.adminPassword;
        security.secret_key = credentials.grafana.secretKey;
        "auth.proxy" = {
          enabled = true;
          header_name = "X-Authentik-Username";
          header_property = "username";
          auto_sign_up = true;
          headers = "Name:X-Authentik-Name Email:X-Authentik-Email";
          whitelist = "100.64.0.0/10, 192.168.1.0/24";
        };
        users.auto_assign_org_role = "Viewer";
      };
      provision.datasources.settings = {
        datasources = [
          {
            name = "Loki";
            uid = "loki";
            type = "loki";
            access = "proxy";
            url = "http://127.0.0.1:3100";
            isDefault = true;
          }
        ];
      };
      provision.dashboards.settings = {
        providers = [
          {
            name = "Zeek";
            options.path = "/etc/grafana/dashboards/zeek";
            orgId = 1;
            type = "file";
            updateIntervalSeconds = 30;
          }
          {
            name = "Suricata";
            options.path = "/etc/grafana/dashboards/suricata";
            orgId = 1;
            type = "file";
            updateIntervalSeconds = 30;
          }
          {
            name = "Authz";
            options.path = "/etc/grafana/dashboards/authz";
            orgId = 1;
            type = "file";
            updateIntervalSeconds = 30;
          }
          {
            name = "Tetragon";
            options.path = "/etc/grafana/dashboards/tetragon";
            orgId = 1;
            type = "file";
            updateIntervalSeconds = 30;
          }
          {
            name = "Vulnix";
            options.path = "/etc/grafana/dashboards/vulnix";
            orgId = 1;
            type = "file";
            updateIntervalSeconds = 60;
          }
        ];
      };

      provision.alerting.rules.settings = {
        apiVersion = 1;
        groups = [
          {
            orgId = 1;
            name = "suricata";
            folder = "Security";
            interval = "30s";
            rules = [
              {
                uid = "testzero-suricata-signature";
                title = "SuricataSignatureFired";
                condition = "C";
                for = "0m";
                noDataState = "OK";
                execErrState = "Error";
                labels = {
                  severity = "warning";
                  team = "testzero";
                };
                annotations = {
                  summary = "Suricata signature fired on the sensor (vm3)";
                  description = "One or more Suricata alert events landed in Loki in the last 5 minutes. See the Suricata Alerts dashboard for details.";
                };
                data = [
                  {
                    refId = "A";
                    relativeTimeRange = {
                      from = 600;
                      to = 0;
                    };
                    datasourceUid = "loki";
                    model = {
                      refId = "A";
                      hide = false;
                      datasource = {
                        type = "loki";
                        uid = "loki";
                      };
                      expr = "sum(count_over_time({job=\"suricata\"} | json | event_type=\"alert\" [5m]))";
                      queryType = "range";
                      editorMode = "code";
                      intervalMs = 1000;
                      maxDataPoints = 43200;
                    };
                  }
                  {
                    refId = "B";
                    relativeTimeRange = {
                      from = 0;
                      to = 0;
                    };
                    datasourceUid = "__expr__";
                    model = {
                      refId = "B";
                      hide = false;
                      datasource = {
                        type = "__expr__";
                        uid = "__expr__";
                      };
                      type = "reduce";
                      expression = "A";
                      reducer = "last";
                      conditions = [ ];
                    };
                  }
                  {
                    refId = "C";
                    relativeTimeRange = {
                      from = 0;
                      to = 0;
                    };
                    datasourceUid = "__expr__";
                    model = {
                      refId = "C";
                      hide = false;
                      datasource = {
                        type = "__expr__";
                        uid = "__expr__";
                      };
                      type = "threshold";
                      expression = "B";
                      conditions = [
                        {
                          evaluator = {
                            type = "gt";
                            params = [ 0 ];
                          };
                          operator = {
                            type = "and";
                          };
                          query = {
                            params = [ "C" ];
                          };
                          reducer = {
                            params = [ ];
                            type = "last";
                          };
                          type = "query";
                        }
                      ];
                    };
                  }
                ];
              }
            ];
          }
          {
            orgId = 1;
            name = "authz";
            folder = "Security";
            interval = "30s";
            rules = [
              {
                uid = "testzero-authz-deny";
                title = "AuthzDeniedFired";
                condition = "C";
                for = "0m";
                noDataState = "OK";
                execErrState = "Error";
                labels = {
                  severity = "warning";
                  team = "testzero";
                };
                annotations = {
                  summary = "OPA denied one or more authorization requests";
                  description = "Requests were denied by the central authz policy in the last 5 minutes. See the Authz Decisions (OPA) dashboard for user/method/path detail.";
                };
                data = [
                  {
                    refId = "A";
                    relativeTimeRange = {
                      from = 600;
                      to = 0;
                    };
                    datasourceUid = "loki";
                    model = {
                      refId = "A";
                      hide = false;
                      datasource = {
                        type = "loki";
                        uid = "loki";
                      };
                      expr = "sum(count_over_time({job=\"authz\"} | json | decision=\"deny\" [5m]))";
                      queryType = "range";
                      editorMode = "code";
                      intervalMs = 1000;
                      maxDataPoints = 43200;
                    };
                  }
                  {
                    refId = "B";
                    relativeTimeRange = {
                      from = 0;
                      to = 0;
                    };
                    datasourceUid = "__expr__";
                    model = {
                      refId = "B";
                      hide = false;
                      datasource = {
                        type = "__expr__";
                        uid = "__expr__";
                      };
                      type = "reduce";
                      expression = "A";
                      reducer = "last";
                      conditions = [ ];
                    };
                  }
                  {
                    refId = "C";
                    relativeTimeRange = {
                      from = 0;
                      to = 0;
                    };
                    datasourceUid = "__expr__";
                    model = {
                      refId = "C";
                      hide = false;
                      datasource = {
                        type = "__expr__";
                        uid = "__expr__";
                      };
                      type = "threshold";
                      expression = "B";
                      conditions = [
                        {
                          evaluator = {
                            type = "gt";
                            params = [ 0 ];
                          };
                          operator = {
                            type = "and";
                          };
                          query = {
                            params = [ "C" ];
                          };
                          reducer = {
                            params = [ ];
                            type = "last";
                          };
                          type = "query";
                        }
                      ];
                    };
                  }
                ];
              }
            ];
          }
          {
            orgId = 1;
            name = "tetragon";
            folder = "Security";
            interval = "30s";
            rules = [
              {
                uid = "testzero-tetragon-event";
                title = "TetragonEventFired";
                condition = "C";
                for = "0m";
                noDataState = "OK";
                execErrState = "Error";
                labels = {
                  severity = "warning";
                  team = "testzero";
                };
                annotations = {
                  summary = "Tetragon runtime tripwire fired on a workload VM";
                  description = "Shell exec or sensitive-file open detected by Tetragon on vm5/vm6 in the last 5 minutes. See the Runtime Security (Tetragon) dashboard.";
                };
                data = [
                  {
                    refId = "A";
                    relativeTimeRange = {
                      from = 600;
                      to = 0;
                    };
                    datasourceUid = "loki";
                    model = {
                      refId = "A";
                      hide = false;
                      datasource = {
                        type = "loki";
                        uid = "loki";
                      };
                      expr = "sum(count_over_time({job=\"tetragon\"} [5m]))";
                      queryType = "range";
                      editorMode = "code";
                      intervalMs = 1000;
                      maxDataPoints = 43200;
                    };
                  }
                  {
                    refId = "B";
                    relativeTimeRange = {
                      from = 0;
                      to = 0;
                    };
                    datasourceUid = "__expr__";
                    model = {
                      refId = "B";
                      hide = false;
                      datasource = {
                        type = "__expr__";
                        uid = "__expr__";
                      };
                      type = "reduce";
                      expression = "A";
                      reducer = "last";
                      conditions = [ ];
                    };
                  }
                  {
                    refId = "C";
                    relativeTimeRange = {
                      from = 0;
                      to = 0;
                    };
                    datasourceUid = "__expr__";
                    model = {
                      refId = "C";
                      hide = false;
                      datasource = {
                        type = "__expr__";
                        uid = "__expr__";
                      };
                      type = "threshold";
                      expression = "B";
                      conditions = [
                        {
                          evaluator = {
                            type = "gt";
                            params = [ 0 ];
                          };
                          operator = {
                            type = "and";
                          };
                          query = {
                            params = [ "C" ];
                          };
                          reducer = {
                            params = [ ];
                            type = "last";
                          };
                          type = "query";
                        }
                      ];
                    };
                  }
                ];
              }
            ];
          }
          {
            orgId = 1;
            name = "vulnix";
            folder = "Security";
            interval = "5m";
            rules = [
              {
                uid = "testzero-vulnix-high";
                title = "VulnixHighSeverityFound";
                condition = "C";
                for = "0m";
                noDataState = "OK";
                execErrState = "Error";
                labels = {
                  severity = "warning";
                  team = "testzero";
                };
                annotations = {
                  summary = "High or critical CVE finding reported by vulnix";
                  description = "A high/critical severity CVE finding landed in Loki in the last 24 hours. See the Vulnerability Management dashboard; suppress known false positives via variables/vulnix-whitelist.toml.";
                };
                data = [
                  {
                    refId = "A";
                    relativeTimeRange = {
                      from = 86400;
                      to = 0;
                    };
                    datasourceUid = "loki";
                    model = {
                      refId = "A";
                      hide = false;
                      datasource = {
                        type = "loki";
                        uid = "loki";
                      };
                      expr = "sum(count_over_time({job=\"vulnix\"} | json | severity=~\"high|critical\" [24h]))";
                      queryType = "range";
                      editorMode = "code";
                      intervalMs = 1000;
                      maxDataPoints = 43200;
                    };
                  }
                  {
                    refId = "B";
                    relativeTimeRange = {
                      from = 0;
                      to = 0;
                    };
                    datasourceUid = "__expr__";
                    model = {
                      refId = "B";
                      hide = false;
                      datasource = {
                        type = "__expr__";
                        uid = "__expr__";
                      };
                      type = "reduce";
                      expression = "A";
                      reducer = "last";
                      conditions = [ ];
                    };
                  }
                  {
                    refId = "C";
                    relativeTimeRange = {
                      from = 0;
                      to = 0;
                    };
                    datasourceUid = "__expr__";
                    model = {
                      refId = "C";
                      hide = false;
                      datasource = {
                        type = "__expr__";
                        uid = "__expr__";
                      };
                      type = "threshold";
                      expression = "B";
                      conditions = [
                        {
                          evaluator = {
                            type = "gt";
                            params = [ 0 ];
                          };
                          operator = {
                            type = "and";
                          };
                          query = {
                            params = [ "C" ];
                          };
                          reducer = {
                            params = [ ];
                            type = "last";
                          };
                          type = "query";
                        }
                      ];
                    };
                  }
                ];
              }
            ];
          }
        ];
      };
    };

    environment.etc."grafana/dashboards/zeek/zeek-overview.json".source = zeekDashboard;
    environment.etc."grafana/dashboards/suricata/suricata-alerts.json".source = suricataDashboard;
    environment.etc."grafana/dashboards/authz/authz-decisions.json".source = authzDashboard;
    environment.etc."grafana/dashboards/tetragon/tetragon-runtime.json".source = tetragonDashboard;
    environment.etc."grafana/dashboards/vulnix/vulnix.json".source = vulnixDashboard;

    networking.firewall.interfaces.tailscale0.allowedTCPPorts = [
      3000
      3100
    ];
  };
}
