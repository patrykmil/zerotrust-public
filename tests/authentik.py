"""Live lab smoke test: python3 tests/authentik.py <vm1-tailnet-ip>."""

import base64
import http.cookiejar
import json
import os
import sys
import urllib.error
import urllib.request
from urllib.parse import parse_qs, urlsplit


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request(client, url, data=None, headers=None):
    if data is not None:
        data = json.dumps(data).encode()
        headers = {"Content-Type": "application/json", **(headers or {})}
    try:
        return client.open(urllib.request.Request(url, data, headers or {}), timeout=20)
    except urllib.error.HTTPError as response:
        return response


def check(condition, message):
    if not condition:
        raise AssertionError(message)


ip = sys.argv[1]
auth = f"http://{ip}:9000"
gateways = ("http://localhost:8080", f"http://{ip}:8080")
anonymous = urllib.request.build_opener(NoRedirect())
token = os.environ.get("AUTHENTIK_TOKEN", "testzero-bootstrap-token")


def api(path):
    response = request(anonymous, auth + "/api/v3/" + path,
                       headers={"Authorization": "Bearer " + token})
    check(response.status == 200, f"API {path}: {response.status}")
    return json.load(response)["results"]


providers = api("providers/proxy/")
apps = api("core/applications/")
users = {user["username"]: user for user in api("core/users/")}
viewers = next(group for group in api("core/groups/") if group["name"] == "viewers")
check(viewers["pk"] in users["viewer1"]["groups"], "viewer1 missing viewers group")
check(not users["stranger1"]["groups"], "stranger1 should have no groups")
outpost = next(out for out in api("outposts/instances/") if "Embedded" in out["name"])
check(outpost["config"]["authentik_host_browser"] == auth, "Wrong outpost login host")
for gateway, slug in zip(gateways, ("grafana", "grafana-ip")):
    matching = [provider for provider in providers if provider["external_host"] == gateway]
    check(len(matching) == 1, f"Expected one provider for {gateway}")
    pk = matching[0]["pk"]
    check(pk in outpost["providers"], f"Unassigned provider: {gateway}")
    check(any(app["slug"] == slug and app["provider"] == pk for app in apps),
          f"Application {slug} has no matching provider")
    check(request(anonymous, gateway + "/").status == 200, "Landing page not public")
    for path in ("/dashboard", "/api/status", "/grafana/"):
        response = request(anonymous, gateway + path)
        check(response.status == 302, f"Anonymous {gateway}{path}: {response.status}")
        location = response.headers["Location"]
        check(location.startswith(auth + "/application/o/authorize/"), "Wrong login redirect")
        state = parse_qs(urlsplit(location).query)["state"][0].split(".")[1]
        state = json.loads(base64.urlsafe_b64decode(state + "=" * (-len(state) % 4)))
        check(state["redirect"] == gateway + path, f"Login loses path: {state['redirect']}")

for username, expected in (("viewer1", 200), ("stranger1", 403)):
    client = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    flow = auth + "/api/v3/flows/executor/default-authentication-flow/"
    check(json.load(request(client, flow))["component"] == "ak-stage-identification", "No login flow")
    challenge = json.load(request(client, flow, {"uid_field": username}))
    check(challenge["component"] == "ak-stage-password", f"No password stage for {username}")
    challenge = json.load(request(client, flow, {"password": username}))
    check(challenge["component"] == "xak-flow-redirect", f"Login failed for {username}")
    for gateway in gateways:
        for path in ("/dashboard", "/api/status", "/grafana/"):
            response = request(client, gateway + path)
            check(response.status == expected, f"{username} {gateway}{path}: {response.status}")
            check("/if/flow/" not in response.url, f"Still at login: {response.url}")
    print(f"{username}: login and protected paths OK ({expected})")

print("Provisioning, anonymous redirects, public landing and both gateway addresses OK")
