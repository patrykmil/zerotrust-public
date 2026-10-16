# modules/configuration.nix: shared base system for every VM.
#
# Purpose: headless QEMU defaults, users/SSH, per-VM RAM, and the module
#   import list — the one file all six VMs evaluate.
# Contents: module imports, graphics off, memory sizes, passwords
#   (user/root `pass`), SSH, serial autologin; vm1 also gets a fake
#   vulnerable openssl package as vulnix-scan bait.
# VMs: all (vm1–vm6).
{
  config,
  pkgs,
  lib,
  role,
  credentials,
  ...
}:

{
  imports = [
    ./network.nix
    ./tailscale.nix
    ./zeek.nix
    ./suricata.nix
    ./dashboard.nix
    ./authentik.nix
    ./caddy.nix
    ./anubis.nix
    ./opa.nix
    ./metrics.nix
    ./web.nix
    ./api.nix
    ./wid.nix
    ./tetragon.nix
    ./crowdsec.nix
    ./vulnscan.nix
  ];

  virtualisation.graphics = false;

  virtualisation.memorySize =
    {
      vm1 = 4096;
      vm2 = 4096;
      vm3 = 4096;
      vm4 = 4096;
      vm5 = 2048;
      vm6 = 2048;
    }
    .${role};

  system.stateVersion = lib.mkDefault "26.05";
  boot.kernelPackages = pkgs.linuxPackages_latest;
  networking.hostName = role;
  environment.systemPackages =
    (with pkgs; [ jq ])
    ++ lib.optionals (role == "vm1") [
      (pkgs.runCommand "openssl-1.0.1e" { } "mkdir -p $out/bin; echo vuln > $out/bin/openssl")
    ];

  services.openssh = {
    enable = true;
    settings.PermitRootLogin = "prohibit-password";
  };
  users.users.root.initialPassword = credentials.ssh.rootPassword;

  users.users.user = {
    isNormalUser = true;
    initialPassword = credentials.ssh.userPassword;
    extraGroups = [ "wheel" ];
  };

  services.getty.autologinUser = "user";

  services.xserver.enable = false;
}
