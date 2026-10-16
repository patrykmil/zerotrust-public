# modules/api.nix: internal API behind mTLS + workload authz.
#
# Purpose: east-west backend for the gateway (/api/*) and the web tier's
#   dashboard call — reachable only with a step-ca client cert for a known
#   workload CN, authorized per call against OPA (fail-closed).
# Contents: testzero-api (Python :8091, CERT_REQUIRED), GET /status and
#   POST /echo gated by the testzero.workload policy on vm2.
# VMs: vm6 only (callers: vm1 as svc:caddy, vm5 as svc:vm5-web).
{
  config,
  pkgs,
  lib,
  role,
  credentials,
  ...
}:

let
  isApi = role == "vm6";
  port = 8091;

  apiServer = pkgs.writeText "apiserver.py" ''
    #!/usr/bin/env python3
   
    import datetime
    import json
    import ssl
    import urllib.request
    from http.server import BaseHTTPRequestHandler, HTTPServer

    IDENTITY_HEADERS = (
        "X-Authentik-Username",
        "X-Authentik-Email",
        "X-Authentik-Groups",
        "X-Authentik-Name",
    )

    OPA_URL = "http://vm2:8181/v1/data/testzero/workload"
    OPA_TOKEN = "${credentials.opa.token}"

    CERT = "/var/lib/mtls/api.crt"
    KEY = "/var/lib/mtls/api.key"
    ROOT = "/var/lib/mtls/root_ca.crt"


    class Handler(BaseHTTPRequestHandler):
        server_version = "testzero-api/1.0"

        def _json(self, code, obj):
            body = (json.dumps(obj, indent=2) + "\n").encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _caller(self):
            return {
                h: self.headers.get(h)
                for h in IDENTITY_HEADERS
                if self.headers.get(h) is not None
            }

        def _workload(self):
            peer = self.connection.getpeercert()
            return dict(t[0] for t in peer.get("subject", ())).get("commonName", "?")

        def _authorize(self):
            payload = json.dumps({
                "input": {
                    "workload": self._workload(),
                    "method": self.command,
                    "path": self.path,
                }
            }).encode()
            req = urllib.request.Request(
                OPA_URL, data=payload,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": "Bearer " + OPA_TOKEN,
                },
            )
            try:
                with urllib.request.urlopen(req, timeout=3) as resp:
                    decision = json.loads(resp.read()).get("result", {})
            except Exception as e:
                print(f"api opa error: {e}", flush=True)
                return False
            print(f"api policy: {decision.get('reason', '?')}", flush=True)
            return bool(decision.get("allow", False))

        def _log(self, outcome):
            print(
                f"api {self.address_string()} {self.command} {self.path} "
                f"workload={self._workload()} "
                f"caller={self.headers.get('X-Authentik-Username', '-')} -> {outcome}",
                flush=True,
            )

        def do_GET(self):
            if not self._authorize():
                self._log("REJECTED: denied by workload policy")
                self._json(403, {
                    "error": "denied by workload policy",
                    "workload": self._workload(),
                })
                return
            if self.path == "/status":
                self._log("OK")
                self._json(200, {
                    "service": "internal-api",
                    "time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "reached_by": self._caller(),
                    "workload": self._workload(),
                    "note": "requires a step-ca client cert + OPA workload-allow; mesh ACL still applies",
                })
                return
            self._log("NOT FOUND")
            self._json(404, {"error": "unknown path", "known": ["/status", "/echo"]})

        def do_POST(self):
            if not self._authorize():
                self._log("REJECTED: denied by workload policy")
                self._json(403, {
                    "error": "denied by workload policy",
                    "workload": self._workload(),
                })
                return
            if self.path == "/echo":
                length = int(self.headers.get("Content-Length", "0") or 0)
                body = self.rfile.read(length).decode("utf-8", "replace")
                self._log("OK")
                self._json(200, {
                    "service": "internal-api",
                    "caller": self._caller(),
                    "workload": self._workload(),
                    "you_sent": body,
                })
                return
            self._log("NOT FOUND")
            self._json(404, {"error": "unknown path", "known": ["/status", "/echo"]})

        def do_PUT(self):
            self._log("REJECTED BY API")
            self._json(405, {"error": "write methods are admin-only in this demo"})

        do_DELETE = do_PUT

        def log_message(self, fmt, *args):
            pass


    def main():
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.load_cert_chain(CERT, KEY)
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(ROOT)
        httpd = HTTPServer(("0.0.0.0", ${builtins.toString port}), Handler)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        httpd.serve_forever()


    if __name__ == "__main__":
        main()
  '';
in
{
  config = lib.mkIf isApi {

    environment.etc."testzero-api/api.py".source = apiServer;

    systemd.services.testzero-api = {
      description = "Testzero internal API";
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        ExecStart = "${pkgs.python3}/bin/python3 /etc/testzero-api/api.py";
        Restart = "on-failure";
        RestartSec = "5s";
        DynamicUser = true;
      };
    };

    networking.firewall.interfaces.tailscale0.allowedTCPPorts = [ port ];
  };
}
