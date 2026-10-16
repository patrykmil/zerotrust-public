# modules/vms.nix: fleet definition — IPs, SSH ports, per-VM assembly.
#
# Purpose: single place mapping role names to static networking and
#   injecting role/ip/credentials into each VM via specialArgs.
# Contents: eth1 IPs (192.168.1.0/24), host→guest SSH forwards (2201–2206),
#   mkVM builder over qemu-vm.nix + configuration.nix.
# VMs: all (vm1–vm6); build-time only, no runtime config.
{
  lib,
  system,
  nixpkgs,
}:

let
  credentials = import ../variables/credentials.nix;

  ips = {
    vm1 = "192.168.1.1";
    vm2 = "192.168.1.2";
    vm3 = "192.168.1.3";
    vm4 = "192.168.1.4";
    vm5 = "192.168.1.5";
    vm6 = "192.168.1.6";
  };

  sshPorts = {
    vm1 = 2201;
    vm2 = 2202;
    vm3 = 2203;
    vm4 = 2204;
    vm5 = 2205;
    vm6 = 2206;
  };

  mkVM =
    name: extraModules:
    lib.nixosSystem {
      inherit system;
      specialArgs = {
        inherit nixpkgs;
        role = name;
        ip = ips.${name};
        inherit ips sshPorts credentials;
      };
      modules = [
        "${nixpkgs}/nixos/modules/virtualisation/qemu-vm.nix"
        ./configuration.nix
      ]
      ++ extraModules;
    };
in
{
  inherit ips sshPorts mkVM;
}
