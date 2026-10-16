# modules/caddy.nix: gateway reverse proxy — the north-south front door.
#
# Purpose: route :8080 zones through authn (Authentik) → authz (OPA shim)
#   → mTLS upstreams; public landing and the Anubis-checked spotlight
#   stay open.
# Contents: :8080 vhost in five zones (/, /spotlight, /api/*, /grafana/*,
#   catch-all), forward_auth chain, JSON access log (CrowdSec-monitored),
#   workload client certs for vm5/vm6.
# VMs: vm1 only.
{
  config,
  pkgs,
  lib,
  role,
  ...
}:

let
  isGateway = role == "vm1";
  port = 8080;
in
{
  config = lib.mkIf isGateway {

    services.caddy = {
      enable = true;
      virtualHosts.":${builtins.toString port}" = {
        logFormat = ''
          output file ${config.services.caddy.logDir}/access-:${builtins.toString port}.log {
            mode 0640
          }
        '';
        extraConfig = ''

          handle /outpost.goauthentik.io/* {
            reverse_proxy localhost:9000
          }

          respond /favicon.ico 204

          handle /.within.website/* {
            reverse_proxy 127.0.0.1:8923 {
              header_up X-Real-Ip {remote_host}
            }
          }

          handle /spotlight {
            route {
              reverse_proxy /.within.website/* 127.0.0.1:8923 {
                header_up X-Real-Ip {remote_host}
              }
              forward_auth 127.0.0.1:8923 {
                uri /.within.website/x/cmd/anubis/api/check
                trusted_proxies private_ranges
                header_up X-Real-Ip {remote_host}
                @unauthorized status 401
                handle_response @unauthorized {
                  redir * /.within.website/?redir={uri} 307
                }
              }
              reverse_proxy https://vm5:8090 {
                transport http {
                  tls
                  tls_client_auth /var/lib/mtls/caddy.crt /var/lib/mtls/caddy.key
                  tls_trust_pool file /var/lib/mtls/root_ca.crt
                }
              }
            }
          }

          # --- PUBLIC ZONE -----------------------------------------------------
          handle / {
            reverse_proxy https://vm5:8090 {
              transport http {
                tls
                tls_client_auth /var/lib/mtls/caddy.crt /var/lib/mtls/caddy.key
                tls_trust_pool file /var/lib/mtls/root_ca.crt
              }
            }
          }

          # --- INTERNAL API (vm6), /api/* prefix stripped --------------------
          handle_path /api/* {
            forward_auth localhost:9000 {
              uri /outpost.goauthentik.io/auth/caddy
              copy_headers X-Authentik-Username X-Authentik-Groups X-Authentik-Email X-Authentik-Name
              trusted_proxies private_ranges
            }
            forward_auth vm2:8288 {
              uri /
            }
            reverse_proxy https://vm6:8091 {
              transport http {
                tls
                tls_client_auth /var/lib/mtls/caddy.crt /var/lib/mtls/caddy.key
                tls_trust_pool file /var/lib/mtls/root_ca.crt
              }
            }
          }

          # --- GRAFANA (vm4), prefix preserved (serve_from_sub_path) -----------
          handle /grafana/* {
            forward_auth localhost:9000 {
              uri /outpost.goauthentik.io/auth/caddy
              copy_headers X-Authentik-Username X-Authentik-Groups X-Authentik-Email X-Authentik-Name
              trusted_proxies private_ranges
            }
            forward_auth vm2:8288 {
              uri /
            }
            reverse_proxy vm4:3000
          }

          # --- WEB APP (vm5), catch-all for the protected member pages --------
          handle {
            forward_auth localhost:9000 {
              uri /outpost.goauthentik.io/auth/caddy
              copy_headers X-Authentik-Username X-Authentik-Groups X-Authentik-Email X-Authentik-Name
              trusted_proxies private_ranges
            }
            forward_auth vm2:8288 {
              uri /
            }
            reverse_proxy https://vm5:8090 {
              transport http {
                tls
                tls_client_auth /var/lib/mtls/caddy.crt /var/lib/mtls/caddy.key
                tls_trust_pool file /var/lib/mtls/root_ca.crt
              }
            }
          }
        '';
      };
    };

    networking.firewall.allowedTCPPorts = [ port ];

    virtualisation.forwardPorts = [
      {
        from = "host";
        host.port = port;
        guest.port = port;
      }
    ];
  };
}
