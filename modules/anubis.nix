# modules/anubis.nix: Anubis proof-of-work bot gate for /spotlight.
#
# Purpose: block browser-like bots from the anonymous page with no login —
#   Caddy forward_auths /spotlight hits to Anubis's check API.
# Contents: loopback instance :8923 (subrequest/check mode), difficulty 4,
#   vm2-scraper UA bypass (Victoriametrics|Prometheus), :9093 metrics.
# VMs: vm1 only.
{
  lib,
  role,
  ...
}:

{
  config = lib.mkIf (role == "vm1") {
    services.anubis.instances.gateway = {
      settings = {
        BIND_NETWORK = "tcp";
        BIND = "127.0.0.1:8923";
        METRICS_BIND_NETWORK = "tcp";
        METRICS_BIND = "127.0.0.1:9093";
        TARGET = " ";
        DIFFICULTY = 4;
        SERVE_ROBOTS_TXT = true;
        OG_PASSTHROUGH = true;
      };
      policy.extraBots = [
        {
          name = "vm2-scraper";
          user_agent_regex = "Victoriametrics|Prometheus";
          action = "ALLOW";
        }
      ];
    };
  };
}
