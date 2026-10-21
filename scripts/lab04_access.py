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
ALICE_PUBLIC_COMMENT = "30000000-0000-0000-0000-000000000001"
BOB_PUBLIC_COMMENT = "30000000-0000-0000-0000-000000000002"
ALICE_INTERNAL_COMMENT = "30000000-0000-0000-0000-000000000003"
OBRIEN_TITLE = "O'Brien classroom report"
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


def normalize_problem(body):
    """Keep an evidence-safe Problem Details copy for the policy-404 comparison."""
    require(isinstance(body, dict), "Expected a Problem Details JSON object")
    return {key: value for key, value in body.items()
            if key not in ("traceId", "requestId")}


def details(client, incident_id, expected, label):
    result = client.request("/api/incidents/" + incident_id)
    emit(label, result)
    require(result[0] == expected, label + ": unexpected status")
    require(result[1] == ("application/json" if expected == 200 else
                          "application/problem+json"), label + ": unexpected content type")
    if expected == 200:
        require(result[2]["id"] == incident_id, label + ": wrong resource")
    return result


def comment(client, comment_id, expected, label):
    result = client.request("/api/incident-comments/" + comment_id)
    emit(label, result)
    require(result[0] == expected, label + ": unexpected status")
    require(result[1] == ("application/json" if expected == 200 else
                          "application/problem+json"), label + ": unexpected content type")
    if expected == 200:
        require(result[2]["id"] == comment_id, label + ": wrong resource")
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
        foreign_normalized = normalize_problem(foreign[2])
        missing_normalized = normalize_problem(unknown[2])
        # These two saved JSON lines are safe to copy into the report: correlation
        # identifiers were deliberately removed before comparison and output.
        print("A-10 foreign_normalized_body=" +
              json.dumps(foreign_normalized, ensure_ascii=False, sort_keys=True))
        print("A-10 missing_normalized_body=" +
              json.dumps(missing_normalized, ensure_ascii=False, sort_keys=True))
        require(foreign_normalized == missing_normalized, "Foreign/missing bodies differ")
        print("A-10 normalized_bodies_equal=true")
    details(bob, BOB, 200, "Bob -> Bob")
    details(bob, ALICE, 200 if vulnerable else 404, "Bob -> Alice")
    details(morgan, ALICE, 200, "A-03R Morgan -> Alice")
    details(morgan, BOB, 200, "Morgan -> Bob")

    anonymous = Client(args.host)
    require(anonymous.request("/api/me")[0] == 401, "Anonymous unexpectedly authenticated")
    require(len(anonymous.jar) == 0, "Anonymous client has a cookie")
    details(anonymous, BOB, 200 if vulnerable else 401, "A-01 Anonymous -> Bob")

    if args.perimeter:
        # Required A-05/A-11 checks for the existing collection routes.
        for path, label, evidence_key, is_foreign_row in [
            ("/api/incidents", "A-05 Alice list", "containsBob",
             lambda row: row["id"] == BOB),
            ("/api/incidents/search?" + urllib.parse.urlencode({"q": "Невідома спроба входу"}),
             "A-11 Alice search Bob title", "containsBob",
             lambda row: row["id"] == BOB),
            ("/api/incidents/search?" + urllib.parse.urlencode({"q": "O'Brien"}),
             "A-11 Alice search O'Brien", "containsOBrien",
             lambda row: row.get("title") == OBRIEN_TITLE),
        ]:
            status, _, body = alice.request(path)
            require(status == 200 and isinstance(body, list), label + ": unexpected result")
            contains_foreign = any(is_foreign_row(row) for row in body)
            print(json.dumps({"scenario": label, "status": status,
                              evidence_key: contains_foreign, "count": len(body)}))
            require(contains_foreign == vulnerable, label + ": unexpected visibility")
        status, _, summary = alice.request("/api/incidents/severity-summary")
        require(status == 200 and isinstance(summary, list), "Summary failed")
        print(json.dumps({"scenario": "A-11 Alice summary", "status": status,
                          "counts": [{"severity": row["severity"], "count": row["count"]}
                                     for row in summary]}))
        counts = {row["severity"]: row["count"] for row in summary}
        if vulnerable:
            require(counts.get("Critical", 0) == 0 and counts.get("High", 0) == 1
                    and counts.get("Medium", 0) == 1 and counts.get("Low", 0) == 3
                    and sum(counts.values()) == 5,
                    "Vulnerable summary no longer exposes the full seed")
        else:
            require(counts.get("Critical", 0) == 0 and counts.get("High", 0) == 0
                    and counts.get("Medium", 0) == 1 and counts.get("Low", 0) == 2
                    and sum(counts.values()) == 3,
                    "Fixed summary is not restricted to Alice incidents")
        print("a11_summary_scope_verified=true")

        if not vulnerable:
            # A-12: direct child identifier must be governed by the same
            # parent Incident read rule as details, plus IsInternal visibility.
            comment(alice, ALICE_PUBLIC_COMMENT, 200, "A-12 Alice -> own public comment")
            comment(alice, BOB_PUBLIC_COMMENT, 404, "A-12 Alice -> Bob comment")
            comment(alice, ALICE_INTERNAL_COMMENT, 404, "A-12 Alice -> own internal comment")
            comment(morgan, BOB_PUBLIC_COMMENT, 200, "A-12 Morgan -> Bob comment")
            comment(morgan, ALICE_INTERNAL_COMMENT, 200, "A-12 Morgan -> internal comment")
            comment(anonymous, BOB_PUBLIC_COMMENT, 401, "A-12 Anonymous -> Bob comment")
            print("a12_child_parent_scope_and_internal_visibility_verified=true")

    if args.mutation:
        own_path = "/api/incidents/" + ALICE
        own_before = details(alice, ALICE, 200, "Positive: Alice reads own before update")[2]
        own_payload = {"title": "LR04 positive owner update",
                       "description": "Контрольована позитивна зміна власного інциденту для регресії ЛР 4."}
        own_changed = False
        try:
            own_result = alice.request(own_path, own_payload, method="PUT")
            own_changed = own_result[0] == 204
            emit("A-02b Alice updates own Incident", own_result)
            require(own_result[0] == 204, "Owner update was denied")
            own_after = details(alice, ALICE, 200, "Positive: Alice reads own after update")[2]
            require(own_after["title"] == own_payload["title"]
                    and own_after["description"] == own_payload["description"],
                    "Owner update did not change content")
            for key in ("id", "severity", "status", "ownerDisplayName", "occurredAtUtc", "createdAtUtc", "comments"):
                require(own_after[key] == own_before[key], "Owner update changed protected field: " + key)
            print("owner_update_status=204; owner_content_changed=true")
        finally:
            if own_changed:
                restored = alice.request(own_path, {"title": own_before["title"],
                                                    "description": own_before["description"]}, method="PUT")
                require(restored[0] == 204, "Owner failed to restore own original content")
                require(details(alice, ALICE, 200, "Positive: Alice restores own content")[2] == own_before,
                        "Own original response content was not restored")
                print("owner_content_restored=true")

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
            forged = dict(payload, ownerUserId=SUBJECTS["alice"], status="Closed",
                          severity="Critical", role="Administrator")
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

        if not vulnerable:
            # A-04 also covers the independent DELETE mutation perimeter.
            delete_before = details(bob, BOB, 200, "Delete: Bob reads before")[2]
            foreign_delete = alice.request(path, method="DELETE")
            emit("A-04 Alice deletes Bob", foreign_delete)
            require(foreign_delete[0] == 404, "Foreign delete must be concealed")
            require(details(bob, BOB, 200, "Delete: Bob reads after")[2] == delete_before,
                    "Denied delete changed Bob resource")
            require(anonymous.request(path, method="DELETE")[0] == 401,
                    "Anonymous delete must require login")
            print("foreign_delete_status=404; foreign_delete_state_unchanged=true; anonymous_delete_status=401")

            create_payload = {
                "title": "LR04 positive owner delete",
                "description": "Synthetic incident created and removed only by the isolated fixed PoC.",
                "severity": "Low",
                "occurredAtUtc": "2026-10-01T12:00:00+00:00",
            }
            created = alice.request("/api/incidents", create_payload, method="POST")
            emit("Positive: Alice creates disposable Incident", created)
            require(created[0] == 201, "Could not create disposable owner Incident")
            disposable_id = created[2]["id"]
            owner_delete = alice.request("/api/incidents/" + disposable_id, method="DELETE")
            emit("Positive: Alice deletes own disposable Incident", owner_delete)
            require(owner_delete[0] == 204, "Owner delete was denied")
            details(alice, disposable_id, 404, "Positive: owner-deleted Incident is absent")
            print("owner_delete_status=204; owner_delete_verified=true")

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
