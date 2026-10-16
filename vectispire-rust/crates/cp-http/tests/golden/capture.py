"""Records what the Java control plane answers at the HTTP layer, as golden files for cp-http.

Usage: python3 -I capture.py <base-url> <bootstrap-password> <out-dir>

Run against a throwaway control plane (see capture.sh). Each golden is the status line, the headers
in the order the server sent them (Date dropped: it is the one header that changes every run), a
blank line and the body. Values that differ per run — sessions, keys, correlation ids — are replaced
by a placeholder before writing, and the placeholder names what was there.
"""
import http.client, json, re, sys, time, urllib.parse, os

base, bootstrap_password, out = sys.argv[1], sys.argv[2], sys.argv[3]
url = urllib.parse.urlparse(base)


def raw(method, path, headers=None, body=None, chunks=None):
    conn = http.client.HTTPConnection(url.hostname, url.port, timeout=60)
    conn.putrequest(method, path, skip_accept_encoding=True)
    headers = dict(headers or {})
    if chunks is not None:
        headers["Transfer-Encoding"] = "chunked"
    elif body is not None:
        headers.setdefault("Content-Length", str(len(body)))
    for k, v in headers.items():
        conn.putheader(k, v)
    conn.endheaders()
    if chunks is not None:
        for c in chunks:
            conn.send(b"%x\r\n" % len(c) + c + b"\r\n")
        conn.send(b"0\r\n\r\n")
    elif body is not None:
        conn.send(body)
    r = conn.getresponse()
    data = r.read()
    conn.close()
    return r, data


def scrub(text):
    text = re.sub(r'"secret":"[^"]+"', '"secret":"<secret>"', text)
    text = re.sub(r'"prefix":"[^"]+"', '"prefix":"<prefix>"', text)
    text = re.sub(r'"id":"[0-9a-f-]{36}"', '"id":"<uuid>"', text)
    text = re.sub(r'"(createdAt|expiresAt|lastUsedAt)":"[^"]+"', r'"\1":"<instant>"', text)
    text = re.sub(r'"correlationId":"[^"]+"', '"correlationId":"<correlation-id>"', text)
    text = re.sub(r"reference [0-9a-f-]{8,}", "reference <correlation-id>", text)
    return text


def record(name, method, path, headers=None, body=None, chunks=None):
    r, data = raw(method, path, headers, body, chunks)
    lines = ["%d %s" % (r.status, r.reason)]
    for k, v in r.getheaders():
        if k.lower() in ("date", "keep-alive", "connection"):
            continue
        if k.lower() == "last-modified":
            v = "<last-modified>"
        lines.append("%s: %s" % (k, v))
    text = data.decode("utf-8", "replace")
    # The interface's files are the build's, not the server's: a placeholder keeps the golden small and the diff quiet.
    if r.getheader("Content-Type", "").startswith(("text/html", "text/javascript")) or path.endswith((".js", ".json")) and path.startswith("/i18n/"):
        text = "<%d bytes>" % len(data)
    with open(os.path.join(out, name + ".http"), "w") as f:
        f.write("\n".join(lines) + "\n\n" + scrub(text))
    return r, data


def login(password, username="admin"):
    body = json.dumps({"username": username, "password": password}).encode()
    r, data = raw("POST", "/api/v1/auth/login", {"Content-Type": "application/json"}, body)
    assert r.status == 200, (r.status, data)
    return json.loads(data)["token"]


J = {"Content-Type": "application/json"}

# Anonymous: what the chain itself answers.
record("health-anonymous", "GET", "/actuator/health")
record("api-route-anonymous", "GET", "/api/v1/repositories")
record("unmapped-api-anonymous", "GET", "/api/v1/nothing-here")
record("metrics-anonymous", "GET", "/actuator/metrics")
record("api-docs-anonymous", "GET", "/v3/api-docs")
record("agent-route-anonymous", "GET", "/api/v1/agent/jobs")
record("public-key-anonymous", "GET", "/api/v1/crypto/public-key.pub")
# The firewall.
record("firewall-double-slash", "GET", "/api/v1//projects")
record("firewall-semicolon", "GET", "/api/v1/projects;x=1")
record("firewall-encoded-traversal", "GET", "/api/v1/%2e%2e/projects")
record("firewall-encoded-slash", "GET", "/api/v1/projects%2Fx")
# What StrictHttpFirewall and the container refuse beyond the four above — measured, so that the Rust side does not
# guess at a default it was not told about.
record("firewall-encoded-percent", "GET", "/api/v1/a%25b")
record("firewall-encoded-semicolon", "GET", "/api/v1/a%3Bb")
record("firewall-encoded-backslash", "GET", "/api/v1/a%5Cb")
record("firewall-raw-backslash", "GET", "/api/v1/a\\b")
record("firewall-control-character", "GET", "/api/v1/a%01b")
record("firewall-bad-escape", "GET", "/api/v1/%zz")
record("firewall-dot-segment", "GET", "/api/v1/./repositories")
record("firewall-dot-dot-segment", "GET", "/api/v1/../repositories")
record("firewall-non-ascii", "GET", "/api/v1/a%C3%A9b")
record("firewall-trailing-slash", "GET", "/api/v1/repositories/")
# The SPA's patterns at their edges, anonymous.
record("spa-trailing-slash", "GET", "/projects/")
record("spa-api-bare", "GET", "/api")
record("spa-actuator-bare", "GET", "/actuator")
record("spa-dotless-near-actuator", "GET", "/actuator2")
record("spa-three-deep-slash", "GET", "/a/b/c/")
record("spa-api-subpath", "GET", "/api/foo/bar")
record("scim-anonymous", "GET", "/scim/v2/Users")
record("options-anonymous", "OPTIONS", "/api/v1/repositories")
# The interface.
r, index = record("spa-index", "GET", "/")
record("spa-index-html", "GET", "/index.html")
record("spa-deep-link-1", "GET", "/projects")
record("spa-deep-link-3", "GET", "/projects/1/checklist")
record("spa-deep-link-4", "GET", "/a/b/c/d")
record("spa-dotted-missing", "GET", "/missing.png")
record("spa-assets-missing", "GET", "/assets/missing.png")
scripts = re.findall(rb'src="([^"]+\.js)"', index)
if scripts:
    record("spa-script", "GET", "/" + scripts[0].decode().lstrip("/"))
    record("spa-script-head", "HEAD", "/" + scripts[0].decode().lstrip("/"))
record("spa-favicon", "GET", "/favicon.ico")
record("spa-i18n", "GET", "/i18n/en.json")
# Sign-in and its limits.
record("login-bad-json", "POST", "/api/v1/auth/login", J, b"{not json")
record("login-wrong-password", "POST", "/api/v1/auth/login", J,
       json.dumps({"username": "admin", "password": "wrong"}).encode())
record("login-too-large-declared", "POST", "/api/v1/auth/login", J, b" " * 16385)
record("login-too-large-chunked", "POST", "/api/v1/auth/login", J, chunks=[b" " * 8192] * 3)
record("login-method-not-allowed", "DELETE", "/api/v1/auth/login")
record("login-unsupported-media", "POST", "/api/v1/auth/login", {"Content-Type": "text/plain"}, b"x")
record("bearer-unknown", "GET", "/api/v1/repositories", {"Authorization": "Bearer not-a-real-token"})
record("bearer-not-bearer-scheme", "GET", "/api/v1/repositories", {"Authorization": "Basic YTpi"})

# The sign-in budget is ten a minute per address, and the refusals above spent part of it.
time.sleep(61)
first = login(bootstrap_password)
A = lambda t: {"Authorization": "Bearer " + t}
record("password-change-pending", "GET", "/api/v1/repositories", A(first))
record("password-change-pending-me", "GET", "/api/v1/auth/me", A(first))
rotated = "Vs-rs-http-rotated-Invented-2!"
r, _ = raw("POST", "/api/v1/auth/change-password", {**J, **A(first)},
           json.dumps({"current_password": bootstrap_password, "new_password": rotated}).encode())
assert r.status < 300, r.status
admin = login(rotated)
record("unmapped-api-authenticated", "GET", "/api/v1/nothing-here", A(admin))
record("method-not-allowed-authenticated", "DELETE", "/api/v1/repositories", A(admin))
record("head-authenticated", "HEAD", "/api/v1/repositories", A(admin))
record("trailing-slash-authenticated", "GET", "/api/v1/repositories/", A(admin))
record("options-authenticated", "OPTIONS", "/api/v1/repositories", A(admin))
record("ok-json", "GET", "/api/v1/repositories", A(admin))
record("default-body-limit-declared", "POST", "/api/v1/projects", {**J, **A(admin)}, b" " * (1048576 + 1))
record("api-docs-authenticated", "GET", "/v3/api-docs", A(admin))
record("metrics-admin", "GET", "/actuator/metrics", A(admin))
record("not-found-row", "GET", "/api/v1/projects/987654321", A(admin))
record("bad-request-body", "POST", "/api/v1/repositories", {**J, **A(admin)}, b"[]")
repo = json.dumps({"url": "https://git.example.org/invented/vs-rs-http.git", "name": "vs-rs-http"}).encode()
raw("POST", "/api/v1/repositories", {**J, **A(admin)}, repo)
record("conflict-typed", "POST", "/api/v1/repositories", {**J, **A(admin)}, repo)
record("public-key", "GET", "/api/v1/crypto/public-key.pub", A(admin))
# A user without administration: refused by the role marker, and the actuator for a non-administrator.
r, _ = raw("POST", "/api/v1/users", {**J, **A(admin)}, json.dumps({
    "username": "vs-rs-http-user", "password": "Vs-rs-http-user-Invented-3!", "role": "user",
    "display_name": "Invented User"}).encode())
assert r.status < 300, r.status
user_first = login("Vs-rs-http-user-Invented-3!", "vs-rs-http-user")
record("role-refused-pending", "GET", "/api/v1/users", A(user_first))
r, _ = raw("POST", "/api/v1/auth/change-password", {**J, **A(user_first)},
           json.dumps({"current_password": "Vs-rs-http-user-Invented-3!", "new_password": "Vs-rs-http-user-Rotated-4!"}).encode())
user = login("Vs-rs-http-user-Rotated-4!", "vs-rs-http-user")
record("role-refused", "GET", "/api/v1/users", A(user))
record("metrics-not-administrator", "GET", "/actuator/metrics", A(user))
# An integration key on a route that takes none.
r, data = raw("POST", "/api/v1/api-keys", {**J, **A(admin)},
              json.dumps({"name": "vs-rs-http", "scopes": ["read"]}).encode())
key = json.loads(data)["secret"]
open(os.path.join(out, "api-key-create-response.json"), "w").write(scrub(data.decode()))
if key:
    record("api-key-not-accepted", "GET", "/api/v1/users", A(key))
    record("api-key-not-accepted-header", "GET", "/api/v1/users", {"X-API-Key": key})
    record("api-key-accepted", "GET", "/api/v1/repositories", A(key))
    record("api-key-scope-missing", "POST", "/api/v1/repositories/1/scan", A(key))
# The login throttle: ten attempts a minute from one address, the eleventh refused.
time.sleep(61)
for i in range(12):
    r, data = raw("POST", "/api/v1/auth/login", J, json.dumps({"username": "nobody", "password": "x"}).encode())
record("login-throttled", "POST", "/api/v1/auth/login", J, json.dumps({"username": "nobody", "password": "x"}).encode())
