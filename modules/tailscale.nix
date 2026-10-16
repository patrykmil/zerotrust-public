# modules/tailscale.nix: tailnet identity for every VM.
#
# Purpose: join all VMs to the tailnet with per-role tags and Tailscale
#   SSH, so ACLs and `tailscale ssh` work mesh-wide.
# Contents: auth key from credentials, --advertise-tags per role, --ssh.
# VMs: all — vm1 tag:identity, vm2 tag:policy, vm3 tag:sensor,
#   vm4 tag:observe, vm5 tag:workload, vm6 tag:internal.
{
  config,
  pkgs,
  lib,
  role,
  credentials,
  ...
}:

let
  tags = {
    vm1 = "tag:identity";
    vm2 = "tag:policy";
    vm3 = "tag:sensor";
    vm4 = "tag:observe";
    vm5 = "tag:workload";
    vm6 = "tag:internal";
  };
in
{
  environment.etc."tailscale/authkey".text = credentials.tailscale.authKey;

  services.tailscale = {
    enable = true;
    authKeyFile = "/etc/tailscale/authkey";
    extraUpFlags = [
      "--advertise-tags=${tags.${role}}"
      "--ssh"
    ];
  };
}
