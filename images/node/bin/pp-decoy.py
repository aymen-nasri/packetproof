#!/usr/bin/env python3
"""A harmless decoy service: accepts TCP connections, sends a banner, logs the peer, closes.
Used as the database: what matters to the tests is who can open a connection, not SQL."""

import argparse
import socketserver


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--banner", default="DECOY")
    a = ap.parse_args()

    class H(socketserver.BaseRequestHandler):
        def handle(self):
            print(f"connection from {self.client_address[0]}", flush=True)
            self.request.sendall(f"{a.banner}\n".encode())

    socketserver.ThreadingTCPServer.allow_reuse_address = True
    socketserver.ThreadingTCPServer(("0.0.0.0", a.port), H).serve_forever()


if __name__ == "__main__":
    main()
