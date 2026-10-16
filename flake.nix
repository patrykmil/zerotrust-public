{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs =
    { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
      lib = nixpkgs.lib;
      vms = import ./modules/vms.nix { inherit lib system nixpkgs; };
    in
    {
      nixosConfigurations = {
        vm1 = vms.mkVM "vm1" [ ];
        vm2 = vms.mkVM "vm2" [ ];
        vm3 = vms.mkVM "vm3" [ ];
        vm4 = vms.mkVM "vm4" [ ];
        vm5 = vms.mkVM "vm5" [ ];
        vm6 = vms.mkVM "vm6" [ ];
      };

      packages.${system} = {
        vm1 = self.nixosConfigurations.vm1.config.system.build.vm;
        vm2 = self.nixosConfigurations.vm2.config.system.build.vm;
        vm3 = self.nixosConfigurations.vm3.config.system.build.vm;
        vm4 = self.nixosConfigurations.vm4.config.system.build.vm;
        vm5 = self.nixosConfigurations.vm5.config.system.build.vm;
        vm6 = self.nixosConfigurations.vm6.config.system.build.vm;
        default = pkgs.symlinkJoin {
          name = "testzero-vms";
          paths = [
            self.nixosConfigurations.vm1.config.system.build.vm
            self.nixosConfigurations.vm2.config.system.build.vm
            self.nixosConfigurations.vm3.config.system.build.vm
            self.nixosConfigurations.vm4.config.system.build.vm
            self.nixosConfigurations.vm5.config.system.build.vm
            self.nixosConfigurations.vm6.config.system.build.vm
          ];
        };
      };
    };
}
