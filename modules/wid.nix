# modules/wid.nix: workload identity — east-west mTLS via step-ca.
#
# Purpose: services prove identity with short-lived certs instead of
#   trusting network location; vm6 requires + authorizes client certs.
# Contents: step-ca on vm2 :8443; 24h cert issue/rotate timer (6h) for
#   svc:caddy (vm1), svc:vm5-web (vm5), svc:api-vm6 (vm6); consumer
#   reload wiring on vm1/vm5/vm6.
# VMs: CA on vm2; clients on vm1, vm5, vm6.
{
  config,
  pkgs,
  lib,
  role,
  credentials,
  ...
}:

let
  isCa = role == "vm2";

  caUrl = "https://vm2:8443";
  caPort = 8443;

  clients = {
    vm1 = {
      cn = "svc:caddy";
      file = "caddy";
      san = "vm1";
      deps = [ "caddy.service" ];
    };
    vm5 = {
      cn = "svc:vm5-web";
      file = "web";
      san = "vm5";
      deps = [ "testzero-web.service" ];
    };
    vm6 = {
      cn = "svc:api-vm6";
      file = "api";
      san = "vm6";
      deps = [ "testzero-api.service" ];
    };
  };
  cl = clients.${role} or null;
  isClient = cl != null;

  certDir = "/var/lib/mtls";

  issueScript = pkgs.writeShellScript "mtls-issue" ''
    set -eu
    export PATH=${
      lib.makeBinPath [
        pkgs.step-cli
        pkgs.curl
        pkgs.coreutils
      ]
    }
    export HOME=/tmp

    install -d -m 0750 -o root -g mtls ${certDir}

    # 1. Root cert. TOFU: fetched without TLS verification because the
    #    fingerprint is only known after CA init. Transport is still the
    #    WireGuard mesh, ACL-scoped to tag:policy:8443.
    until curl -sfk ${caUrl}/roots.pem -o ${certDir}/.root_ca.crt.tmp; do
      echo "mtls: waiting for step-ca at ${caUrl} ..."
      sleep 5
    done
    mv ${certDir}/.root_ca.crt.tmp ${certDir}/root_ca.crt

    # 2. Fresh 24h keypair (real rotation: new key on every run).
    rm -f ${certDir}/.${cl.file}.crt.tmp ${certDir}/.${cl.file}.key.tmp
    until
      step ca certificate ${cl.cn} \
        ${certDir}/.${cl.file}.crt.tmp ${certDir}/.${cl.file}.key.tmp \
        --provisioner admin \
        --provisioner-password-file /etc/mtls/provisioner_password \
        --ca-url ${caUrl} \
        --root ${certDir}/root_ca.crt \
        --san ${cl.san} \
        --not-after 24h
    do
      echo "mtls: waiting for step-ca to accept issuance ..."
      sleep 5
    done

    # 3. Install atomically, readable by the service group only.
    chmod 0640 ${certDir}/.${cl.file}.crt.tmp ${certDir}/.${cl.file}.key.tmp
    chown root:mtls ${certDir}/.${cl.file}.crt.tmp ${certDir}/.${cl.file}.key.tmp
    mv ${certDir}/.${cl.file}.crt.tmp ${certDir}/${cl.file}.crt
    mv ${certDir}/.${cl.file}.key.tmp ${certDir}/${cl.file}.key
    chmod 0640 ${certDir}/root_ca.crt
    chown root:mtls ${certDir}/root_ca.crt
  '';
in
lib.mkMerge [

  # ── vm2: the CA ─────────────────────────────────────────────────
  (lib.mkIf isCa {
    services.step-ca = {
      enable = true;
      address = "0.0.0.0";
      port = caPort;
      settings = { };
      intermediatePasswordFile = "/etc/mtls/ca_password";

      package = pkgs.step-ca.overrideAttrs (old: {
        postInstall = (old.postInstall or "") + ''
          substituteInPlace $out/lib/systemd/system/step-ca.service \
            --replace-fail "ReadWriteDirectories=/etc/step-ca/db" "" \
            --replace-fail "StartLimitInterval=30" ""
        '';
      });
    };

    systemd.tmpfiles.rules = [
      "f /etc/mtls/ca_password 0440 root step-ca - ${credentials.mtls.caPassword}"
      "f /etc/mtls/provisioner_password 0440 root step-ca - ${credentials.mtls.provisionerPassword}"
    ];

    systemd.services.step-ca = {
      after = [
        "network-online.target"
        "tailscaled.service"
      ];
      wants = [ "network-online.target" ];
      serviceConfig = {
        Environment = [ "STEPPATH=/var/lib/step-ca" ];
        ExecStart = lib.mkForce [
          ""
          "${config.services.step-ca.package}/bin/step-ca /var/lib/step-ca/config/ca.json --password-file \${CREDENTIALS_DIRECTORY}/intermediate_password"
        ];
        Restart = "on-failure";
        RestartSec = "5s";
      };
      preStart = ''
        if [ ! -f /var/lib/step-ca/config/ca.json ]; then
          ${pkgs.step-cli}/bin/step ca init \
            --deployment-type standalone \
            --name testzero \
            --dns vm2 --dns localhost \
            --address 0.0.0.0:${builtins.toString caPort} \
            --provisioner admin \
            --password-file /etc/mtls/ca_password \
            --provisioner-password-file /etc/mtls/provisioner_password
        fi
        chown -R step-ca:step-ca /var/lib/step-ca 2>/dev/null || true
      '';
    };

    networking.firewall.interfaces.tailscale0.allowedTCPPorts = [ caPort ];
  })

  # ── vm1/vm5/vm6: cert issuance + rotation ───────────────────────
  (lib.mkIf isClient {
    users.groups.mtls = { };

    systemd.tmpfiles.rules = [
      "f /etc/mtls/provisioner_password 0400 root root - ${credentials.mtls.provisionerPassword}"
    ];

    systemd.services.mtls-certs = {
      description = "mTLS workload certificate issuance/rotation";
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = issueScript;
        TimeoutStartSec = "300";
      };
      postStart = ''
        ${pkgs.systemd}/bin/systemctl try-reload-or-restart ${lib.concatStringsSep " " cl.deps} || true
      '';
    };

    # Rotate every 6h (certs live 24h).
    systemd.timers.mtls-certs = {
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnCalendar = "0/6:00:00";
        Persistent = true;
      };
    };
  })

  # ── vm1: caddy consumes the cert ────────────────────────────────
  (lib.mkIf (role == "vm1") {
    systemd.services.caddy = {
      requires = [ "mtls-certs.service" ];
      after = [ "mtls-certs.service" ];
      serviceConfig.SupplementaryGroups = [ "mtls" ];
    };
  })

  # ── vm5 / vm6: python services consume the cert ─────────────────
  (lib.mkIf (role == "vm5") {
    systemd.services.testzero-web = {
      requires = [ "mtls-certs.service" ];
      after = [ "mtls-certs.service" ];
      serviceConfig.SupplementaryGroups = [ "mtls" ];
    };
  })
  (lib.mkIf (role == "vm6") {
    systemd.services.testzero-api = {
      requires = [ "mtls-certs.service" ];
      after = [ "mtls-certs.service" ];
      serviceConfig.SupplementaryGroups = [ "mtls" ];
    };
  })
]
