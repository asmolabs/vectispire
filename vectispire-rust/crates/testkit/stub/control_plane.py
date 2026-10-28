"""A stub control plane for the measurements: answers the hello and holds every long poll for its
wait, then 204 — what an idle agent sees all day."""
import http.server
import json
import time
import urllib.parse


class Stub(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def answer(self, status, body=b""):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        if self.path == "/api/v1/agent/hello":
            identity = {"id": "3f2b6c1e-8d4a-4b7e-9c2f-5a1d0e7b9c34", "name": "measured", "contractVersion": "1",
                        "maxConcurrent": 1, "credentialsMode": "local"}
            return self.answer(200, json.dumps(identity).encode())
        self.answer(404)

    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        if url.path == "/api/v1/agent/jobs":
            time.sleep(int(urllib.parse.parse_qs(url.query).get("wait", ["30"])[0]))
            return self.answer(204)
        self.answer(404)


http.server.ThreadingHTTPServer(("0.0.0.0", 8080), Stub).serve_forever()
