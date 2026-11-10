#!/usr/bin/env python3
"""A tiny app backend: names itself and the client it saw, serves a health check and a 1 MiB
object (used to prove path MTU discovery works across the tunnel and through NAT)."""

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BIG = b"x" * (1024 * 1024)


def handler(name: str):
    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            if self.path == "/health":
                body = b"ok\n"
            elif self.path == "/big":
                body = BIG
            else:
                body = f"{name} saw {self.client_address[0]}\n".encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *args):
            print(f"{self.client_address[0]} {fmt % args}", flush=True)

    return H


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", required=True)
    ap.add_argument("--port", type=int, default=8080)
    a = ap.parse_args()
    ThreadingHTTPServer(("0.0.0.0", a.port), handler(a.name)).serve_forever()


if __name__ == "__main__":
    main()
