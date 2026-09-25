"""Intentionally vulnerable local test target for validating FSafe.

Run: fsafe-demo   (or: python -m fsafe.demo_target — serves on 127.0.0.1:9911, localhost only)
"""
import http.server
import json
import re
import socketserver
import time

PAGE = """<html><head><title>Demo Shop</title>
<script src="/app.js"></script>
<script>var cfg = {apiKey: "AIzaSyD-abc123abc123abc123abc123abc123"};</script>
</head><body>
<a href="/about">About</a> <a href="/login">Login</a> <a href="/admin">Admin</a> <a href="https://external.example.com/x">ext</a>
<a href="/item?id=101">item 101</a>
<a href="/fetch?url=https://example.com/feed">fetch</a> <a href="/page?name=home">page</a>
<a href="/ping?host=localhost">ping</a> <a href="/template?name=guest">template</a>
<a href="/user?user=demo">user</a> <a href="/ldap?cn=demo">ldap</a>
<form action="/search" method="get"><input name="q"><input type="submit"></form>
<form action="/login" method="post"><input name="user"><input type="password" name="pass"><input type="submit"></form>
</body></html>"""

ABOUT = "<html><head><title>About</title></head><body><a href='/'>home</a></body></html>"

APP_JS = """window.onload=function(){
  var p = new URLSearchParams(location.search);
  if(p.get('msg')) document.getElementById('c').innerHTML = p.get('msg');
};
"""

PASSWD = ("root:x:0:0:root:/root:/bin/bash\n"
          "daemon:x:1:1:daemon:/usr/sbin:/bin/false\n")


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "DemoShop/1.0"

    # ---------------- helpers ----------------
    def _html(self, body, code=200, headers=None):
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body.encode())

    def _q(self):
        from urllib.parse import urlsplit, parse_qs
        return parse_qs(urlsplit(self.path).query, keep_blank_values=True)

    # ---------------- GET ----------------
    def do_GET(self):
        path, _, query = self.path.partition("?")
        q = self._q()

        if path == "/search":
            # reflected XSS: raw echo; SQL injection simulator:
            #   quote alone        → database error (error-based)
            #   boolean conditions → different result sets (boolean blind)
            #   SLEEP              → server-side delay (time-based)
            #   UNION              → union error (column count)
            val = (q.get("q") or [""])[0]
            up = val.upper()
            if "SLEEP" in up:
                time.sleep(6)
                self._html("<html>Search</html>")
                return
            if "UNION" in up:
                self._html("<html>Error: The used SELECT statements have a "
                           "different number of columns</html>")
                return
            if "'" in val and (" AND " in up or " OR " in up):
                cond_true = "'1'='1" in val or "1=1" in val
                cond_false = "'1'='2" in val or "1=2" in val
                if cond_true or cond_false:
                    rows = 12 if cond_true else 0
                    items = "".join(f"<li>result {i}</li>" for i in range(rows))
                    self._html(f"<html><title>Search</title><ul>{items}</ul></html>")
                    return
            if "'" in val or "SELECT" in up:
                self._html("<html>Error: You have an error in your SQL syntax; "
                           "check the manual</html>")
                return
            self._html(f"<html><title>Search</title>Results for {val}</html>",
                       headers={"Set-Cookie": "session=abc123"})
            return

        if path == "/item":
            # IDOR: any numeric id returns an 'account' page
            iid = (q.get("id") or ["0"])[0]
            if iid.isdigit():
                self._html(f"<html><h1>Account {iid}</h1>"
                           f"<p>email: user{{'@'}}example.com — name: Demo User</p></html>")
                return
            self._html("<html>not found</html>", 404)
            return

        if path == "/fetch":
            # SSRF: server-side fetch of a user URL (simulated — no real fetch,
            # echoes content markers so probes have evidence to find)
            url = (q.get("url") or [""])[0]
            if "169.254.169.254" in url:
                self._html("<html>ami-id: ami-0abc123 instance-id: i-0abc123</html>")
            elif url.startswith("file://") and "passwd" in url:
                self._html("<html><pre>" + PASSWD + "</pre></html>")
            else:
                self._html("<html>fetch failed: connection error</html>")
            return

        if path == "/page":
            # LFI / path traversal: naive file read
            name = (q.get("name") or [""])[0]
            norm = name.replace("\\", "/")
            while "../" in norm:
                norm = norm.replace("../", "")
            if "etc/passwd" in norm:
                self._html("<html><pre>" + PASSWD + "</pre></html>")
            else:
                self._html("<html>no such page</html>", 404)
            return

        if path == "/ping":
            # OS command injection (simulated): `id` output appears
            host = (q.get("host") or [""])[0]
            if "id" in host.split()[-1:] or "id" in host:
                self._html("<html>uid=1000(demo) gid=1000(demo) groups=1000(demo)</html>")
            else:
                self._html("<html>ping: unknown host</html>")
            return

        if path == "/template":
            # SSTI: evaluates {{7*7}} (simulated Jinja)
            name = (q.get("name") or [""])[0]
            m = re.search(r"\{\{\s*7\*7\s*\}\}", name)
            if m:
                self._html(f"<html>Hello 49</html>")
            else:
                self._html(f"<html>Hello {name}</html>")
            return

        if path == "/user":
            # NoSQL operator injection (simulated MongoDB error)
            u = (q.get("user") or [""])[0]
            if "$ne" in u or "$gt" in u or "$regex" in u:
                self._html('<html>MongoError: Cast to string failed for value "$ne"</html>')
            else:
                self._html(f"<html>profile: {u}</html>")
            return

        if path == "/ldap":
            # LDAP filter injection
            f_ = (q.get("cn") or [""])[0]
            if "*)(|" in f_ or ")(&" in f_:
                self._html("<html>ldap_search(): Bad search filter</html>")
            else:
                self._html("<html>no entries</html>")
            return

        if path == "/app.js":
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.end_headers()
            self.wfile.write(APP_JS.encode())
            return
        if path == "/about":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Set-Cookie", "__Host-bad=1")  # violates __Host- prefix rules
            self.end_headers()
            self.wfile.write(ABOUT.encode())
            return
        if path == "/.env":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"DB_PASSWORD=supersecret\n")
            return
        if path == "/phpinfo.php":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><h1>phpinfo()</h1>PHP Version 8.2.0</html>")
            return
        if path == "/admin":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><h1>Admin panel</h1></html>")
            return
        if path == "/robots.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"User-agent: *\nDisallow: /admin\n")
            return
        if path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("X-Powered-By", "Express/4.17.1")
            self.end_headers()
            self.wfile.write(PAGE.encode())
            return
        self.send_response(404)
        self.end_headers()

    # ---------------- POST ----------------
    def do_POST(self):
        path, _, _ = self.path.partition("?")
        ln = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(ln).decode("utf-8", "replace") if ln else ""

        if path == "/login":
            from urllib.parse import parse_qs
            form = parse_qs(body, keep_blank_values=True)
            user = (form.get("user") or [""])[0]
            pw = (form.get("pass") or [""])[0]

            # vulnerable on purpose: admin:admin works; enumeration via message;
            # no rate limiting or lockout of any kind
            if user == "admin" and pw == "admin":
                self.send_response(302)
                self.send_header("Location", "/admin")
                self.end_headers()
                return
            known = user in ("admin", "root", "demo")
            if known:
                # longer message on purpose: enumeration detectors compare sizes
                msg = ("Wrong password for this account — please try again, use the "
                       "password recovery page, or contact support at support@"
                       "demo-shop.test if you keep having trouble signing in to "
                       "your existing account dashboard.")
            else:
                msg = ("Unknown username — please register first before signing in.")
            self._html(f"<html><h1>Login</h1><p>{msg}</p></html>")
            return

        if path == "/upload":
            fn = ""
            m = re.search(r'filename="([^"]*)"', body)
            if m:
                fn = m.group(1)
            self._html(f"<html>uploaded {fn} saved successfully</html>")
            return

        # generic POST (legacy tests rely on the 302)
        self.send_response(302)
        self.send_header("Location", "/")
        self.end_headers()

    def log_message(self, *a):  # quiet
        pass


def main():
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("127.0.0.1", 9911), Handler) as s:
        print("demo target on http://127.0.0.1:9911 (Ctrl+C to stop)")
        s.serve_forever()


if __name__ == "__main__":
    main()
