# modules/suricata.nix: Suricata signature IDS on the sensor.
#
# Purpose: alert on known-bad traffic; eve.json alerts ship to Loki for
#   the Grafana dashboard + alert rule.
# Contents: libpcap capture on tailscale0 (HOME_NET 100.64.0.0/10),
#   ET/Open + OISF TrafficID via suricata-update, local demo tripwires
#   (SIDs 8000001–8000011), startup wait for tailscaled (tun device).
# VMs: vm3 only.
{
  config,
  pkgs,
  lib,
  role,
  ...
}:

let
  isSensor = role == "vm3";
in
{
  config = lib.mkIf isSensor {
    services.suricata = {
      enable = true;
      settings = {
        vars.address-groups.HOME_NET = "100.64.0.0/10";

        pcap = [ { interface = "tailscale0"; } ];

        app-layer.protocols = {
          dnp3 = {
            enabled = "yes";
            detection-enabled = "yes";
          };
          modbus = {
            enabled = "yes";
            detection-enabled = "yes";
          };
        };

        outputs = [
          {
            eve-log = {
              enabled = true;
              filetype = "regular";
              filename = "eve.json";
              community-id = true;
              types = [ { alert.tagged-packets = "no"; } ];
            };
          }
        ];

        rule-files = [
          "suricata.rules"
          "/etc/suricata/local.rules"
        ];
      };

      enabledSources = [
        "et/open"
        "oisf/trafficid"
      ];

      disabledRules = [
        "2270000"
        "2270001"
        "2270002"
        "2270003"
        "2270004"
        "2270005"
        "2270006"
      ];
    };

    systemd.services.suricata = {
      after = [ "tailscaled.service" ];
      wants = [ "tailscaled.service" ];

      serviceConfig.ExecStart = lib.mkForce "!${config.services.suricata.package}/bin/suricata -c ${config.services.suricata.configFile} --pcap=tailscale0";
    };

    systemd.tmpfiles.rules = [
      "f /var/lib/suricata/rules/suricata.rules 0644 suricata suricata - -"
    ];

    environment.etc."suricata/local.rules".text = ''
      alert tcp any any -> $HOME_NET 9100 (msg:"TESTZERO node-exporter /metrics scrape on sensor vm3"; flow:established,to_server; content:"GET /metrics"; depth:20; classtype:policy-violation; sid:8000001; rev:1;)
      alert tcp any any -> $HOME_NET 22 (msg:"TESTZERO SSH connection to sensor vm3 over tailnet"; flow:to_server; flags:S,12; threshold:type both, track by_src, count 1, seconds 60; classtype:attempted-recon; sid:8000002; rev:1;)
      alert tcp any any -> $HOME_NET any (msg:"TESTZERO tripwire payload observed"; flow:established,to_server; content:"X5O!P%@AP[4|5C|PZX54(P^)7CC)7}$TESTZERO-TRIPWIRE"; classtype:trojan-activity; sid:8000003; rev:1;)
      alert ip any any -> any any (msg:"TZ-CANARY any-ip"; sid:8000010; rev:1;)
      alert tcp any any -> any any (msg:"TZ-CANARY any-tcp"; flow:established,to_server; sid:8000011; rev:1;)
    '';
  };
}
