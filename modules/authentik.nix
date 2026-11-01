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

    systemd.services.authentik-provision = {
      description = "Authentik provision providers, outpost and demo users";
      after = [ "authentik.service" "network-online.target" ];
      requires = [ "authentik.service" ];
      wants = [ "network-online.target" ];
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        Type = "oneshot";
        WorkingDirectory = "/var/lib/authentik";
      };
      path = with pkgs; [ curl jq tailscale ];
      script = ''
        set -euo pipefail
        shopt -s inherit_errexit
        BASE=http://localhost:${builtins.toString port}/api/v3
        TOK="${credentials.authentik.bootstrapToken}"

        # Wait until the API answers with valid JSON (migrate may still be
        # running at boot; a bare connect can succeed before the DB is up).
        for i in $(seq 1 60); do
          if curl -fsS --max-time 5 -H "Authorization: Bearer $TOK" "$BASE/core/applications/" | jq -e '.pagination' >/dev/null 2>&1; then
            break
          fi
          sleep 2
        done
        curl -fsS --max-time 5 -H "Authorization: Bearer $TOK" "$BASE/core/applications/" | jq -e '.pagination' >/dev/null

        api() { # method path [json-body]
          local m=$1 p=$2 d=''${3:-}
          if [ -n "$d" ]; then
            curl --fail-with-body -sS --max-time 15 -X "$m" -H "Authorization: Bearer $TOK" \
              -H 'Content-Type: application/json' -d "$d" "$BASE$p"
          else
            curl --fail-with-body -sS --max-time 15 -X "$m" -H "Authorization: Bearer $TOK" "$BASE$p"
          fi
        }

        flows=$(api GET /flows/instances/)
        authorization_flow=$(printf '%s' "$flows" | jq -er '.results[] | select(.slug=="default-provider-authorization-implicit-consent") | .pk')
        invalidation_flow=$(printf '%s' "$flows" | jq -er '.results[] | select(.slug=="default-provider-invalidation-flow") | .pk')

        # Ensure a proxy provider for the gateway address and return only its pk.
        ensure_provider() { # name slug external-host
          local name=$1 slug=$2 host=$3
          local providers pk payload
          providers=$(api GET /providers/proxy/)
          pk=$(printf '%s' "$providers" | jq -r --arg h "$host" '.results[] | select(.external_host==$h) | .pk' | head -1)
          if [ -z "$pk" ]; then
            payload=$(jq -nc --arg n "$name" --arg h "$host" --arg a "$authorization_flow" --arg i "$invalidation_flow" \
              '{name:$n,authorization_flow:$a,invalidation_flow:$i,external_host:$h,mode:"forward_single"}')
            pk=$(api POST /providers/proxy/ "$payload" | jq -er '.pk | numbers')
            echo "  created provider '$name'" >&2
          else
            echo "  provider '$name' exists" >&2
          fi

          local apps app
          apps=$(api GET /core/applications/)
          app=$(printf '%s' "$apps" | jq -r --arg s "$slug" '.results[] | select(.slug==$s) | .slug' | head -1)
          if [ -z "$app" ]; then
            api POST /core/applications/ "{\"name\":\"$name\",\"slug\":\"$slug\",\"provider\":$pk}" >/dev/null
            echo "  created application '$slug'" >&2
          else
            api PATCH "/core/applications/$slug/" "{\"provider\":$pk}" >/dev/null
            echo "  application '$slug' exists" >&2
          fi
          printf '%s' "$pk"
        }

        echo "== providers =="
        local_pk=$(ensure_provider "grafana-proxy" "grafana" "http://localhost:8080")
        IP=$(tailscale ip -4 | head -1)
        test -n "$IP" || { echo "no tailnet IP"; exit 1; }
        ip_pk=$(ensure_provider "grafana-proxy-ip" "grafana-ip" "http://$IP:8080")

        # Outpost: own both providers and point login at the tailnet IP.
        echo "== outpost =="
        out=$(api GET /outposts/instances/ | jq -c '.results[] | select(.name|contains("Embedded"))')
        out_pk=$(printf '%s' "$out" | jq -er '.pk')
        body=$(printf '%s' "$out" | jq -c --argjson a "$local_pk" --argjson b "$ip_pk" --arg h "http://$IP:${builtins.toString port}" \
          '{providers:([.providers[]?,$a,$b]|unique),config:(.config+{authentik_host:$h,authentik_host_browser:$h})}')
        api PATCH "/outposts/instances/$out_pk/" "$body" >/dev/null
        echo "  outpost owns providers $local_pk $ip_pk, login host $IP"

        # Demo users: viewer1 in 'viewers', stranger1 in no group; password = username.
        echo "== users =="
        groups=$(api GET /core/groups/)
        group_pk=$(printf '%s' "$groups" | jq -r '.results[] | select(.name=="viewers") | .pk' | head -1)
        if [ -z "$group_pk" ]; then
          group_pk=$(api POST /core/groups/ '{"name":"viewers"}' | jq -er '.pk')
          echo "  created group 'viewers'"
        fi

        for u in viewer1 stranger1; do
          users=$(api GET /core/users/?ordering=username)
          upk=$(printf '%s' "$users" | jq -r --arg u "$u" '.results[] | select(.username==$u) | .pk' | head -1)
          if [ -z "$upk" ]; then
            upk=$(api POST /core/users/ "{\"username\":\"$u\",\"name\":\"$u\",\"is_active\":true}" | jq -er '.pk | numbers')
            echo "  created user '$u'"
          else
            echo "  user '$u' exists"
          fi
          api POST "/core/users/$upk/set_password/" "{\"password\":\"$u\"}" >/dev/null
          if [ "$u" = viewer1 ]; then
            api POST "/core/groups/$group_pk/add_user/" "{\"pk\":$upk}" >/dev/null
          fi
        done
        echo "  passwords set to username"
      '';
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
