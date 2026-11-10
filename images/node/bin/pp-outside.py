#!/usr/bin/env python3
"""The internet host's web server. It answers on several ports (TLS on 443 with a throwaway
self-signed certificate) and replies with the source address it saw, which is how the tests
prove that inside clients reach the internet only through NAT."""

import argparse
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"  # keep-alive, so one TCP connection can be held across a change

    def do_GET(self):
        body = f"outside saw {self.client_address[0]}\n".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print(f"{self.server.server_address[1]} {self.client_address[0]} {fmt % args}", flush=True)


def serve(port: int) -> None:
    srv = ThreadingHTTPServer(("0.0.0.0", port), H)
    if port == 443:
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "/tmp/o.key",
                        "-out", "/tmp/o.crt", "-subj", "/CN=www.example.net", "-days", "2"],
                       check=True, capture_output=True)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain("/tmp/o.crt", "/tmp/o.key")
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    srv.serve_forever()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ports", default="80,443,4444")
    ports = [int(p) for p in ap.parse_args().ports.split(",")]
    threads = [threading.Thread(target=serve, args=(p,), daemon=True) for p in ports]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


if __name__ == "__main__":
    main()
