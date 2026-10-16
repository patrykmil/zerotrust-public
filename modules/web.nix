# modules/web.nix: public web workload (landing/spotlight/dashboard).
#
# Purpose: user-facing tier behind the gateway — anonymous pages plus the
#   member dashboard with its server-side API call to vm6.
# Contents: testzero-web (Python :8090, mTLS CERT_REQUIRED, gateway-CN
#   only), routes /, /spotlight, /dashboard; tailnet-only, no host forward.
# VMs: vm5 only (reached via vm1 Caddy).
{
  config,
  pkgs,
  lib,
  role,
  ...
}:

let
  isWeb = role == "vm5";
  port = 8090;

  webApp = pkgs.writeText "webapp.py" ''
    #!/usr/bin/env python3
    """
    testzero web workload (vm5).

    Two zones, split by path:

      GET /          anonymous landing — no identity headers expected
      GET /spotlight anonymous bot-checked page — Caddy runs the Anubis
                   PoW check only (no authentik, no OPA)
      GET /dashboard member area     — Caddy has already run
                                       authentik (authn) + OPA (authz);
                                       X-Authentik-* headers are trusted here

    /dashboard also calls the internal API (https://vm6:8091/status) over the
    tailnet, forwarding the user's identity headers.  That east-west hop now
    requires a step-ca client certificate (workload identity svc:vm5-web,
    issued/rotated by modules/wid.nix) — PLUS the Tailscale ACL allowing
    tag:workload -> tag:internal:8091.  Neither layer alone is sufficient.

    INBOUND this server requires mutual TLS too: only callers presenting a
    valid step-ca client certificate may connect, and the certificate CN
    must be svc:caddy (the gateway — both the anonymous landing and the
    protected pages are proxied through it).  "Anonymous" applies to the
    USER at the gateway, never to the network hop: a random tailnet device
    cannot even finish the TLS handshake against this port.
    """

    import datetime
    import json
    import ssl
    import urllib.request
    from http.server import BaseHTTPRequestHandler, HTTPServer

    API_STATUS_URL = "https://vm6:8091/status"

    # Workload identity: short-lived certs from the step-ca on vm2.
    # mtls-certs.service must run before this service starts (requires/after).
    MTLS_CTX = ssl.create_default_context(cafile="/var/lib/mtls/root_ca.crt")
    MTLS_CTX.load_cert_chain("/var/lib/mtls/web.crt", "/var/lib/mtls/web.key")

    # Server side: serve HTTPS and require a client certificate whose CN is
    # the gateway's workload identity.
    SERVER_CERT = "/var/lib/mtls/web.crt"
    SERVER_KEY = "/var/lib/mtls/web.key"
    SERVER_ROOT = "/var/lib/mtls/root_ca.crt"
    GATEWAY_CN = "svc:caddy"

    PAGE = """<!doctype html>
    <html>
    <head>
      <title>testzero workload</title>
      <style>
        body {{ font-family: sans-serif; margin: 3em auto; max-width: 46em;
               background: #101418; color: #d8dee4; }}
        a {{ color: #6cb6ff; }}
        .card {{ background: #1c2128; border: 1px solid #30363d;
                border-radius: 8px; padding: 1em 1.5em; margin: 1em 0; }}
        .ok  {{ color: #3fb950; }} .bad {{ color: #f85149; }}
        code {{ background: #30363d; padding: 2px 6px; border-radius: 4px; }}
        table {{ border-collapse: collapse; }} td, th {{ padding: 4px 12px;
                border: 1px solid #30363d; }}
      </style>
    </head>
    <body>{body}</body>
    </html>"""

    def landing():
        return PAGE.format(body="""
      <h1>testzero public landing</h1>
      <p class="card">You reached the workload VM (vm5) <b>without
        authenticating</b>. This page is the anonymous zone: Caddy routed
        <code>/</code> straight here, skipping both forward_auth hops.</p>
      <p class="card">Try the protected areas:
        <ul>
          <li><a href="/spotlight">/spotlight</a> — bot-checked page
            (Anubis proof-of-work, no login)</li>
          <li><a href="/dashboard">/dashboard</a> — member area
            (requires Authentik login, then OPA allow)</li>
          <li><a href="/api/status">/api/status</a> — internal API on vm6
            via the gateway chain</li>
          <li><a href="/grafana/">/grafana/</a> — observability via the chain</li>
        </ul></p>
      <p class="card">From a tailnet host, verify segmentation:
        <code>curl -m 3 http://vm6:8091/status</code> should time out —
        only the gateway and this workload tier may reach the API.</p>
    """)

    def spotlight():
        return PAGE.format(body="""
      <h1>spotlight: bot-checked, no login</h1>
      <p class="card">You solved the Anubis proof-of-work challenge on the
        gateway (vm1) <b>without authenticating</b>. No Authentik login, no
        OPA policy — just proof you run a real browser. Bots (curl, scrapers)
        get the challenge page instead of this content.</p>
      <p><a href="/">&larr; back to public landing</a></p>
    """)

    def dashboard(user, groups, email, api_status, api_error):
        rows = f"""
      <tr><th>user</th><td>{user or '(none)'}</td></tr>
      <tr><th>email</th><td>{email or '(none)'}</td></tr>
      <tr><th>groups</th><td>{groups or '(none)'}</td></tr>"""
        if api_error is not None:
            api_block = f'<p class="bad">API call FAILED: {api_error}</p>'
        else:
            pretty = json.dumps(api_status, indent=2)
            api_block = f"<pre>{pretty}</pre>"
        return PAGE.format(body=f"""
      <h1>member dashboard</h1>
      <p class="card">Identity headers injected by the gateway chain:</p>
      <table>{rows}</table>
      <p class="card">Internal API response (<code>GET https://vm6:8091/status</code>,
        mTLS server-side over the mesh — this workload presents cert
        <code>svc:vm5-web</code>, and the ACL allows
        <code>tag:workload -&gt; tag:internal</code>; neither alone suffices):</p>
      {api_block}
      <p><a href="/">&larr; back to public landing</a></p>
    """)


    class Handler(BaseHTTPRequestHandler):
        server_version = "testzero-web/1.0"

        def _send_html(self, html):
            body = html.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _get(self, url, headers):
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=5, context=MTLS_CTX) as resp:
                return json.loads(resp.read())

        def _workload(self):
            """Certificate CN of the TLS peer — its workload identity."""
            peer = self.connection.getpeercert()
            return dict(t[0] for t in peer.get("subject", ())).get("commonName", "?")

        def do_GET(self):
            wl = self._workload()
            if wl != GATEWAY_CN:
                # Valid cert, wrong workload: authenticated at TLS level,
                # denied at workload-authz level.
                print(f"web REJECTED: client cert CN {wl!r} != {GATEWAY_CN}", flush=True)
                self.send_response(403)
                self.end_headers()
                self.wfile.write(b"workload identity not allowed\n")
                return

            if self.path == "/" or self.path == "/index.html":
                self._send_html(landing())
                return

            if self.path == "/spotlight":
                self._send_html(spotlight())
                return

            if self.path == "/dashboard":
                user = self.headers.get("X-Authentik-Username", "")
                email = self.headers.get("X-Authentik-Email", "")
                groups = self.headers.get("X-Authentik-Groups", "")

                # East-west call to the internal API.  Forward the user
                # identity so the API log shows who triggered the call —
                # the API itself decides whether the headers are trustworthy
                # (only tag:workload and tag:identity can even reach it).
                fwd = {
                    "X-Authentik-Username": user,
                    "X-Authentik-Email": email,
                    "X-Authentik-Groups": groups,
                }
                try:
                    api_status = self._get(API_STATUS_URL, fwd)
                    api_error = None
                except Exception as e:  # ACL/rule change? show the failure
                    api_status, api_error = None, e

                self._send_html(dashboard(user, groups, email, api_status, api_error))
                return

            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"not found")

        def log_message(self, fmt, *args):
            print(f"web {self.address_string()} {fmt % args}", flush=True)


    def main():
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.load_cert_chain(SERVER_CERT, SERVER_KEY)
        ctx.verify_mode = ssl.CERT_REQUIRED  # no client cert, no handshake
        ctx.load_verify_locations(SERVER_ROOT)
        httpd = HTTPServer(("0.0.0.0", ${builtins.toString port}), Handler)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        httpd.serve_forever()


    if __name__ == "__main__":
        main()
  '';
in
{
  config = lib.mkIf isWeb {

    environment.etc."testzero-web/app.py".source = webApp;

    systemd.services.testzero-web = {
      description = "Testzero public web workload";
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        ExecStart = "${pkgs.python3}/bin/python3 /etc/testzero-web/app.py";
        Restart = "on-failure";
        RestartSec = "5s";
        DynamicUser = true;
      };
    };

    networking.firewall.interfaces.tailscale0.allowedTCPPorts = [ port ];
  };
}
