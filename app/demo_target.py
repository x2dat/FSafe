"""Intentionally vulnerable local test target for validating FSafe.

Run: python -m app.demo_target   (serves on 127.0.0.1:9911 — localhost only)
"""
import http.server
import json
import socketserver

PAGE = """<html><head><title>Demo Shop</title>
<script src="/app.js"></script>
<script>var cfg = {apiKey: "AIzaSyD-abc123abc123abc123abc123abc123"};</script>
</head><body>
<a href="/about">About</a> <a href="/login">Login</a> <a href="/admin">Admin</a> <a href="https://external.example.com/x">ext</a>
<form action="/search" method="get"><input name="q"><input type="submit"></form>
<form action="/login" method="post"><input name="user"><input type="password" name="pass"><input type="submit"></form>
</body></html>"""

ABOUT = "<html><head><title>About</title></head><body><a href='/'>home</a></body></html>"

APP_JS = "window.onload=function(){console.log('demo');};"

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/search"):
            # reflected XSS + fake SQL error
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Set-Cookie", "session=abc123")  # missing flags on purpose
            self.end_headers()
            self.wfile.write(f"<html>Results for {self.path}</html>".encode())
        elif self.path == "/app.js":
            self.send_response(200); self.send_header("Content-Type", "application/javascript"); self.end_headers()
            self.wfile.write(APP_JS.encode())
        elif self.path == "/about":
            self.send_response(200); self.send_header("Content-Type", "text/html"); self.end_headers()
            self.wfile.write(ABOUT.encode())
        elif self.path == "/.env":
            self.send_response(200); self.send_header("Content-Type", "text/plain"); self.end_headers()
            self.wfile.write(b"DB_PASSWORD=supersecret\n")
        elif self.path == "/admin":
            self.send_response(200); self.send_header("Content-Type", "text/html"); self.end_headers()
            self.wfile.write(b"<html><h1>Admin panel</h1></html>")
        elif self.path == "/robots.txt":
            self.send_response(200); self.send_header("Content-Type", "text/plain"); self.end_headers()
            self.wfile.write(b"User-agent: *\nDisallow: /admin\n")
        elif self.path == "/":
            self.send_response(200); self.send_header("Content-Type", "text/html")
            self.send_header("X-Powered-By", "Express/4.17.1"); self.end_headers()
            self.wfile.write(PAGE.encode())
        else:
            self.send_response(404); self.end_headers()

    def do_POST(self):
        ln = int(self.headers.get("Content-Length", 0) or 0)
        self.rfile.read(ln)
        self.send_response(302); self.send_header("Location", "/"); self.end_headers()

    def log_message(self, *a):  # quiet
        pass

if __name__ == "__main__":
    with socketserver.TCPServer(("127.0.0.1", 9911), Handler) as s:
        print("demo target on http://127.0.0.1:9911 (Ctrl+C to stop)")
        s.serve_forever()
