# modules/network.nix: inter-VM networking (eth1 bus, firewall, forwards).
#
# Purpose: wire the three NICs — NAT outbound, multicast eth1 bus,
#   tailnet overlay — and expose SSH of every VM to the host.
# Contents: eth1 on 192.168.1.0/24 (no gateway), firewall opens :22,
#   host→guest SSH forward (ports from vms.nix).
# VMs: all (vm1–vm6).
{
  config,
  pkgs,
  lib,
  nixpkgs,
  role,
  ip,
  sshPorts,
  ...
}:

let
  nodeNum = lib.last (lib.splitString "." ip);
  mac = "52:54:00:12:01:0${nodeNum}";
in
{
  # ── Inter-VM networking ─────────────────────────────────────────
  virtualisation.qemu.networkingOptions = lib.mkAfter [
    "-netdev socket,id=eth1,mcast=230.0.0.1:1234"
    "-device virtio-net-pci,netdev=eth1,mac=${mac}"
  ];

  networking.interfaces.eth1.ipv4.addresses = [
    {
      address = ip;
      prefixLength = 24;
    }
  ];

  networking.interfaces.eth1.ipv4.routes = lib.mkForce [ ];

  networking.firewall.allowedTCPPorts = [ 22 ];

  virtualisation.forwardPorts = [
    {
      from = "host";
      host.port = sshPorts.${role};
      guest.port = 22;
    }
  ];
}
