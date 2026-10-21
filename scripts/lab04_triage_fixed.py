"""Local fixed-state verification for SecureLab LR04 points 11 and 12."""

import argparse
import http.cookiejar
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request


ALICE_NEW = "20000000-0000-0000-0000-000000000003"
SUBJECTS = {
    "alice": "10000000-0000-0000-0000-000000000001",
    "morgan": "10000000-0000-0000-0000-000000000003",
}


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
        safe["body"] = {key: body[key] for key in ("id", "title", "status", "traceId") if key in body}
    print(json.dumps(safe, ensure_ascii=False))


def details(client, expected_status, label):
    result = client.request("/api/incidents/" + ALICE_NEW)
    emit(label, result)
    require(result[0] == 200 and result[2]["status"] == expected_status,
            label + ": unexpected resource state")


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

    clients = {}
    for user, subject_id in SUBJECTS.items():
        client = Client(args.host.rstrip("/"))
        login = client.request("/api/auth/login", {"userName": user, "password": password})
        require(login[0] == 204, user + ": login failed")
        me = client.request("/api/me")
        require(me[0] == 200 and me[2]["id"] == subject_id, user + ": wrong principal")
        print(user + "_login_status=204")
        clients[user] = client

    alice, morgan = clients["alice"], clients["morgan"]
    details(alice, "New", "P11 Reporter reads target before deny")
    denied = alice.request("/api/incidents/" + ALICE_NEW + "/triage", {
        "role": "Analyst", "ownerUserId": SUBJECTS["morgan"],
        "status": "Triaged", "isTransitionAllowed": True
    }, method="POST")
    emit("P11 Reporter forged-body triage", denied)
    require(denied[0] == 403 and isinstance(denied[2], dict), "Reporter was not denied")
    trace_id = denied[2].get("traceId")
    require(isinstance(trace_id, str) and bool(trace_id), "Denied response lacks trace id")
    print("denied_trace_id=" + trace_id)
    details(alice, "New", "P11 Reporter reads target after deny")

    allowed = morgan.request("/api/incidents/" + ALICE_NEW + "/triage", method="POST")
    emit("P11 Analyst triage", allowed)
    require(allowed[0] == 204, "Analyst transition was denied")
    details(morgan, "Triaged", "P11 Analyst reads target after allow")
    invalid_state = morgan.request("/api/incidents/" + ALICE_NEW + "/triage", method="POST")
    emit("P11 Analyst repeats triage", invalid_state)
    require(invalid_state[0] == 409, "Invalid status transition was accepted")
    print("triage_fixed_contract_verified=true")


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
