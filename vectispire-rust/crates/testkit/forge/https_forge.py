"""git's smart HTTP protocol over TLS, with the answers the clone tests need.

/team/...      the repository, behind HTTP Basic: user x-access-token, the token in $FORGE_TOKEN
/public/...    the same repository, anonymous
/forbidden/... 403        /missing/... 404        /flaky/... 503
/moved/...     302 to another host
Every request is logged to /tmp/requests.log with whether it carried credentials.
"""
import base64
import http.server
import os
import ssl
import subprocess

TOKEN = os.environ.get("FORGE_TOKEN", "")
EXPECTED = "Basic " + base64.b64encode(("x-access-token:" + TOKEN).encode()).decode()


class Forge(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def record(self):
        authorization = self.headers.get("Authorization")
        state = "none" if authorization is None else ("token" if authorization == EXPECTED else "other")
        with open("/tmp/requests.log", "a") as log:
            log.write(f"{self.command} {self.path} auth={state}\n")

    def plain(self, status, extra=()):
        body = f"{status}\n".encode()
        self.send_response(status)
        for name, value in extra:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def serve(self):
        self.record()
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        path, _, query = self.path.partition("?")
        top = path.split("/")[1] if path.count("/") > 1 else ""
        if top == "forbidden":
            return self.plain(403)
        if top == "missing":
            return self.plain(404)
        if top == "flaky":
            return self.plain(503)
        if top == "moved":
            return self.plain(302, [("Location", "https://elsewhere.example/team/api.git/info/refs?token=never-logged")])
        if top == "team" and self.headers.get("Authorization") != EXPECTED:
            return self.plain(401, [("WWW-Authenticate", 'Basic realm="forge"')])
        if top not in ("team", "public"):
            return self.plain(404)
        environment = {
            "GIT_PROJECT_ROOT": "/srv/git",
            "GIT_HTTP_EXPORT_ALL": "1",
            "PATH_INFO": "/team" + path[len("/" + top):],
            "QUERY_STRING": query,
            "REQUEST_METHOD": self.command,
            "CONTENT_TYPE": self.headers.get("Content-Type", ""),
            "CONTENT_LENGTH": str(len(body)),
            "PATH": "/usr/bin:/bin",
        }
        result = subprocess.run(["git", "http-backend"], input=body, env=environment, capture_output=True)
        head, _, payload = result.stdout.partition(b"\r\n\r\n")
        status = 200
        headers = []
        for line in head.decode().split("\r\n"):
            name, _, value = line.partition(":")
            if name.lower() == "status":
                status = int(value.strip().split()[0])
            elif name:
                headers.append((name, value.strip()))
        self.send_response(status)
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = serve
    do_POST = serve


context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain("/certs/server.pem", "/certs/server.key")
server = http.server.ThreadingHTTPServer(("0.0.0.0", 443), Forge)
server.socket = context.wrap_socket(server.socket, server_side=True)
# Ready once the socket listens, not before: the entrypoint used to mark it ready and only then start this
# server, and a clone that arrived in between failed with "could not reach its host" (CI, 2026-10-28).
open("/certs/ready", "w").close()
server.serve_forever()
