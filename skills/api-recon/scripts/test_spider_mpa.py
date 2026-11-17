import contextlib
import http.server
import shutil
import ssl
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path

import spider_mpa as spider


@contextlib.contextmanager
def serve(handler, context=None):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    if context:
        server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


class SpiderSecurityTest(unittest.TestCase):
    def test_origins(self):
        base = spider.url_origin("https://TARGET.example/")
        self.assertEqual(base, spider.url_origin("https://target.example:443/relative?x=1#f"))
        self.assertEqual(spider.url_origin("https://[::1]/"), spider.url_origin("https://[::1]:443/x"))
        for url in ("https://target.example.attacker.invalid/", "https://target.example:444/",
                    "http://target.example/", "https://target.example@evil.invalid/",
                    "https://user@target.example/", "file:///tmp/x", "https://target.example:bad/"):
            self.assertNotEqual(base, spider.url_origin(url), url)
        self.assertNotEqual(spider.url_origin("https://target.example:0/"), base)

    def test_send_and_redirect_boundary(self):
        received = []

        class Handler(http.server.BaseHTTPRequestHandler):
            destination = ""

            def do_GET(self):
                received.append((self.server.server_port, self.path, self.headers.get("Cookie")))
                if self.path.startswith("/redirect/"):
                    self.send_response(int(self.path.split("/")[-1]))
                    self.send_header("Location", self.destination)
                else:
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<html>same-origin</html>")

            def log_message(self, *args):
                pass

        with serve(Handler) as target, serve(Handler) as other:
            base = f"http://127.0.0.1:{target.server_port}"
            origin = spider.url_origin(base)
            opener = spider.make_opener(origin)
            self.assertIn("same-origin", spider.fetch(base, "session=test-only", origin, opener)[0])
            for status in (301, 302, 303, 307, 308):
                Handler.destination = "/ok"
                self.assertTrue(spider.fetch(f"{base}/redirect/{status}", "session=test-only", origin, opener)[0])
                Handler.destination = f"http://127.0.0.1:{other.server_port}/sink"
                self.assertEqual(spider.fetch(f"{base}/redirect/{status}", "session=test-only", origin, opener), ("", ""))
            self.assertEqual(spider.fetch(Handler.destination, "session=test-only", origin, opener), ("", ""))
            self.assertTrue(all(port == target.server_port and cookie == "session=test-only" for port, _, cookie in received))

    def test_tls_default_and_private_ca(self):
        openssl = shutil.which("openssl")
        if not openssl:
            self.skipTest("openssl required for ephemeral TLS fixture")
        with tempfile.TemporaryDirectory() as directory:
            cert, key = Path(directory) / "cert.pem", Path(directory) / "key.pem"
            config = Path(directory) / "openssl.cnf"
            config.write_text("[req]\ndistinguished_name=dn\n[dn]\n", encoding="ascii")
            subprocess.run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                            "-config", str(config), "-addext", "basicConstraints=critical,CA:TRUE",
                            "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
                            "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
            received = []

            class Handler(http.server.BaseHTTPRequestHandler):
                def do_GET(self):
                    received.append(self.headers.get("Cookie"))
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                    self.end_headers()
                    self.wfile.write(b"trusted")

                def log_message(self, *args):
                    pass

            with serve(Handler, context) as server:
                url = f"https://127.0.0.1:{server.server_port}/"
                origin = spider.url_origin(url)
                self.assertEqual(spider.fetch(url, "test-only", origin, spider.make_opener(origin)), ("", ""))
                self.assertEqual(received, [])
                self.assertEqual(spider.fetch(url, "test-only", origin, spider.make_opener(origin, str(cert)))[0], "trusted")
                self.assertEqual(spider.fetch(url, "test-only", origin, spider.make_opener(origin, insecure=True))[0], "trusted")
                self.assertEqual(received, ["test-only", "test-only"])


if __name__ == "__main__":
    unittest.main()
