# modules/authentik.nix: Authentik identity provider (authn for the chain).
#
# Purpose: who-are-you hop of the gateway chain — Caddy forward_auths
#   protected zones here; anonymous users get a 302 to login.
# Contents: server+worker (allinone :9000, host forward), PostgreSQL +
#   Redis (loopback-only), bootstrap admin seed.
# VMs: vm1 only.
{
  config,
  pkgs,
  lib,
  role,
  credentials,
  ...
}:

let
  isAuthentik = role == "vm1";
  port = 9000;
  redisPort = 6379;
  authPG = credentials.authentik.postgresql;

  sharedEnv = {
    AUTHENTIK_SECRET_KEY = credentials.authentik.secretKey;
    AUTHENTIK_POSTGRESQL__HOST = "127.0.0.1";
    AUTHENTIK_POSTGRESQL__PORT = "5432";
    AUTHENTIK_POSTGRESQL__NAME = authPG.name;
    AUTHENTIK_POSTGRESQL__USER = authPG.user;
    AUTHENTIK_POSTGRESQL__PASSWORD = authPG.password;
    AUTHENTIK_CACHE__URL = "redis://127.0.0.1:${builtins.toString redisPort}/0";
    AUTHENTIK_CHANNELS__URL = "redis://127.0.0.1:${builtins.toString redisPort}/1";
  };
in
{
  config = lib.mkIf isAuthentik {

    services.postgresql = {
      enable = true;
      package = pkgs.postgresql_16;
      ensureDatabases = [ authPG.name ];
      ensureUsers = [
        {
          name = authPG.user;
          ensureDBOwnership = true;
        }
      ];
      authentication = ''
        local ${authPG.name} ${authPG.user} scram-sha-256
        host  ${authPG.name} ${authPG.user} 127.0.0.1/32 scram-sha-256
      '';
    };

    services.redis.servers.authentik = {
      enable = true;
      port = redisPort;
      bind = "127.0.0.1";
    };

    users = {
      users.authentik = {
        isSystemUser = true;
        home = "/var/lib/authentik";
        createHome = true;
        group = "authentik";
      };
      groups.authentik = { };
    };

    systemd.tmpfiles.settings."10-authentik" = {
      "/var/lib/authentik/data".d = {
        mode = "0755";
        user = "authentik";
        group = "authentik";
      };
      "/var/lib/authentik/certs".d = {
        mode = "0755";
        user = "authentik";
        group = "authentik";
      };
      "/var/lib/authentik/media".d = {
        mode = "0755";
        user = "authentik";
        group = "authentik";
      };
    };

    systemd.services.authentik-db-setup = {
      description = "Authentik Database Password Setup";
      after = [
        "postgresql.service"
        "postgresql-setup.service"
      ];
      requires = [
        "postgresql.service"
        "postgresql-setup.service"
      ];
      before = [ "authentik-migrate.service" ];
      wantedBy = [ "authentik-migrate.service" ];
      serviceConfig = {
        Type = "oneshot";
        User = "postgres";
      };
      script = ''
        ${pkgs.postgresql_16}/bin/psql -d postgres -c "ALTER ROLE ${authPG.user} PASSWORD '${authPG.password}';"
      '';
    };

    systemd.services.authentik-migrate = {
      description = "Authentik Database Migration";
      after = [
        "postgresql.service"
        "redis-authentik.service"
        "authentik-db-setup.service"
      ];
      requires = [
        "postgresql.service"
        "authentik-db-setup.service"
      ];
      before = [
        "authentik.service"
      ];
      wantedBy = [
        "authentik.service"
      ];
      serviceConfig = {
        Type = "oneshot";
        User = "authentik";
        Group = "authentik";
        WorkingDirectory = "/var/lib/authentik";
      };
      script = "${pkgs.authentik}/bin/ak migrate";
      environment = sharedEnv;
    };

    systemd.services.authentik = {
      description = "Authentik Server + Worker";
      after = [
        "postgresql.service"
        "redis-authentik.service"
        "network-online.target"
        "authentik-migrate.service"
      ];
      requires = [
        "postgresql.service"
        "redis-authentik.service"
        "network-online.target"
      ];
      wants = [ "authentik-migrate.service" ];
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        Type = "simple";
        User = "authentik";
        Group = "authentik";
        Restart = "on-failure";
        RestartSec = "10s";
        WorkingDirectory = "/var/lib/authentik";
      };
      script = "${pkgs.authentik}/bin/ak allinone";
      environment = sharedEnv // {
        AUTHENTIK_LISTEN__HTTP = "0.0.0.0:${builtins.toString port}";
        AUTHENTIK_LOG_LEVEL = "info";
        AUTHENTIK_EMAIL__HOST = "localhost";
        AUTHENTIK_EMAIL__PORT = "25";
        AUTHENTIK_EMAIL__USE_TLS = "false";
        AUTHENTIK_EMAIL__USE_SSL = "false";
        AUTHENTIK_EMAIL__FROM = "authentik@testzero.local";
        AUTHENTIK_BOOTSTRAP_PASSWORD = credentials.authentik.bootstrapPassword;
        AUTHENTIK_BOOTSTRAP_EMAIL = credentials.authentik.bootstrapEmail;
        AUTHENTIK_BOOTSTRAP_TOKEN = credentials.authentik.bootstrapToken;
      };
    };

    networking.firewall.allowedTCPPorts = [
      22
      port
    ];

    virtualisation.forwardPorts = [
      {
        from = "host";
        host.port = port;
        guest.port = port;
      }
    ];
  };
}
