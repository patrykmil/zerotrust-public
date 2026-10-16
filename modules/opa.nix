# modules/opa.nix: central policy engine + gateway authz bridge.
#
# Purpose: one decision point for user authz (gateway chain) and workload
#   authz (vm6 API calls); the authz-shim translates Caddy subrequests.
# Contents: OPA :8181 (host forward) with testzero.authz, testzero.workload
#   and system.authz (bearer-token API guard) policies; authz-shim :8288
#   (tailnet-only); Alloy ships shim decisions to Loki.
# VMs: vm2 only (queried by vm1 Caddy/shim and the vm6 API over the mesh).
{
  config,
  pkgs,
  lib,
  role,
  credentials,
  ...
}:

let
  isPolicy = role == "vm2";
  opaPort = 8181;
  shimPort = 8288;

  opaToken = credentials.opa.token;

  systemAuthzPolicy = pkgs.writeText "system-authz.rego" ''
    package system.authz

    import rego.v1

    default allow := false

    allow if {
        input.identity == "${opaToken}"
    }
  '';

  authzPolicy = pkgs.writeText "authz.rego" ''
    package testzero.authz

    import rego.v1

    default allow := false

    allow if {
        "authentik Admins" in input.groups
    }

    allow if {
        "viewers" in input.groups
        input.method in { "GET", "HEAD", "OPTIONS" }
    }

    viewer_write_paths := ["/dashboard", "/api", "/api/", "/grafana", "/grafana/"]

    allow if {
        "viewers" in input.groups
        input.method == "POST"
        some p in viewer_write_paths
        startswith(input.path, p)
    }

    reason := "allowed: admin group membership" if {
        "authentik Admins" in input.groups
    } else := "allowed: viewer browse access" if {
        "viewers" in input.groups
        input.method in { "GET", "HEAD", "OPTIONS" }
    } else := "allowed: viewer write on application path" if {
        "viewers" in input.groups
        input.method == "POST"
        some p in viewer_write_paths
        startswith(input.path, p)
    } else := sprintf("denied: no rule matched (user=%v groups=%v method=%v path=%v)", [
        object.get(input, "user", "?"),
        object.get(input, "groups", []),
        object.get(input, "method", "?"),
        object.get(input, "path", "?"),
    ])
  '';

  workloadAuthzPolicy = pkgs.writeText "workload.rego" ''
    package testzero.workload

    import rego.v1

    default allow := false

    # Gateway callers (user requests proxied by Caddy) hit both endpoints.
    allow if {
        input.workload == "svc:caddy"
        input.method in { "GET", "POST" }
        input.path in { "/status", "/echo" }
    }

    # Web tier calls the API server-side for its dashboard: status only.
    allow if {
        input.workload == "svc:vm5-web"
        input.method == "GET"
        input.path == "/status"
    }

    reason := "allowed: gateway workload full access" if {
        input.workload == "svc:caddy"
        input.method in { "GET", "POST" }
        input.path in { "/status", "/echo" }
    } else := "allowed: web tier status read" if {
        input.workload == "svc:vm5-web"
        input.method == "GET"
        input.path == "/status"
    } else := sprintf("denied: no rule matched (workload=%v method=%v path=%v)", [
        object.get(input, "workload", "?"),
        object.get(input, "method", "?"),
        object.get(input, "path", "?"),
    ])
  '';

  authzShim = pkgs.writeText "authz-shim.py" ''
    #!/usr/bin/env python3
    """
    authz-shim: bridges Caddy forward_auth subrequests to OPA.

    Caddy's forward_auth directive passes the proxied request's method and
    URI as X-Forwarded-Method / X-Forwarded-Uri.  The Authentik hop has
    already injected X-Authentik-Username / X-Authentik-Groups / etc.

    This shim assembles an OPA /v1/data/testzero/authz/allow query and
    returns 200 to Caddy (proceed) or 403 (deny).  OPA's Rego policy
    lives in /etc/opa/policies/authz.rego.
    """

    import json
    import urllib.request
    from http.server import BaseHTTPRequestHandler, HTTPServer

    OPA_URL = "http://127.0.0.1:${builtins.toString opaPort}/v1/data/testzero/authz/allow"


    def parse_groups(raw):
        """Authentik emits groups pipe-separated, but tolerate JSON/comma too."""
        if not raw:
            return []
        try:
            v = json.loads(raw)
            if isinstance(v, list):
                return [str(g) for g in v]
        except (json.JSONDecodeError, ValueError):
            pass
        for sep in ("|", ","):
            if sep in raw:
                return [g.strip() for g in raw.split(sep) if g.strip()]
        return [raw.strip()]


    class Handler(BaseHTTPRequestHandler):
        def _check(self):
            user = self.headers.get("X-Authentik-Username", "")
            email = self.headers.get("X-Authentik-Email", "")
            groups = parse_groups(self.headers.get("X-Authentik-Groups", ""))
            method = self.headers.get("X-Forwarded-Method", self.command)
            path = self.headers.get("X-Forwarded-Uri", self.path)

            payload = json.dumps({
                "input": {
                    "user": user,
                    "email": email,
                    "groups": groups,
                    "method": method,
                    "path": path,
                }
            }).encode()

            req = urllib.request.Request(
                OPA_URL, data=payload,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": "Bearer ${opaToken}",
                },
            )
            try:
                with urllib.request.urlopen(req, timeout=5) as resp:
                    allowed = json.loads(resp.read()).get("result", False)
            except Exception as e:
                print(f"opa error: {e}", flush=True)
                allowed = False

            print(json.dumps({
                "event": "authz",
                "user": user,
                "email": email,
                "groups": groups,
                "method": method,
                "path": path,
                "decision": "allow" if allowed else "deny",
            }), flush=True)
            self.send_response(200 if allowed else 403)
            self.end_headers()

        do_GET = _check
        do_POST = _check
        do_PUT = _check
        do_DELETE = _check
        do_HEAD = _check
        do_OPTIONS = _check

        def log_message(self, fmt, *args):
            pass


    if __name__ == "__main__":
        HTTPServer(("0.0.0.0", ${builtins.toString shimPort}), Handler).serve_forever()
  '';
in
{
  config = lib.mkIf isPolicy {

    environment.etc."opa/policies/authz.rego".source = authzPolicy;
    environment.etc."opa/policies/system-authz.rego".source = systemAuthzPolicy;
    environment.etc."opa/policies/workload.rego".source = workloadAuthzPolicy;
    environment.etc."authz-shim/shim.py".source = authzShim;

    # ── OPA decision engine ────────────────────────────────────────
    systemd.services.opa = {
      description = "Open Policy Agent";
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        ExecStart = "${pkgs.open-policy-agent}/bin/opa run --server --addr 0.0.0.0:${builtins.toString opaPort} --set decision_logs.console=true --authentication=token --authorization=basic /etc/opa/policies";
        Restart = "on-failure";
        RestartSec = "5s";
        DynamicUser = true;
      };
    };

    # ── Authz shim (Caddy ↔ OPA bridge) ───────────────────────────
    systemd.services.authz-shim = {
      description = "Caddy forward_auth to OPA bridge";
      after = [ "opa.service" ];
      requires = [ "opa.service" ];
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        ExecStart = "${pkgs.python3}/bin/python3 /etc/authz-shim/shim.py";
        Restart = "on-failure";
        RestartSec = "5s";
        DynamicUser = true;
      };
    };

    networking.firewall.allowedTCPPorts = [ opaPort ];
    networking.firewall.interfaces.tailscale0.allowedTCPPorts = [ shimPort ];

    virtualisation.forwardPorts = [
      {
        from = "host";
        host.port = opaPort;
        guest.port = opaPort;
      }
    ];

    # ── Ship authz decisions to Loki on vm4 ────────────────────────
    environment.etc."alloy/config.alloy".text = ''
      // Authz decisions (authz-shim journald lines) → Loki on vm4.
      loki.write "authz" {
          endpoint {
              url = "http://vm4:3100/loki/api/v1/push"
          }
      }

      loki.source.journal "authz" {
          matches    = "_SYSTEMD_UNIT=authz-shim.service"
          labels     = { job = "authz", host = "${role}" }
          forward_to = [loki.write.authz.receiver]
      }
    '';

    systemd.services.alloy.serviceConfig.SupplementaryGroups = [ "systemd-journal" ];
  };
}
