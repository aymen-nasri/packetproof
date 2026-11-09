#!/usr/bin/env python3
"""Probe helper used by Gate 2 from inside lab containers.

  pp-probe.py tcp IP PORT [--timeout S]     prints open | refused | filtered | unreachable
  pp-probe.py spoof SRC DST DPORT [--sport N] [--count N]
                                            sends TCP SYNs with a forged source address
                                            (a harmless decoy packet; no payload)
  pp-probe.py hold URL --seconds N [--cacert F]
                                            holds ONE keep-alive connection and sends a request
                                            every 0.2 s; prints JSON: ok, failed, connections
"""

import argparse
import errno
import http.client
import json
import ssl
import urllib.parse
import random
import socket
import struct
import sys
import time


def tcp(ip: str, port: int, timeout: float) -> str:
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        return "open"
    except ConnectionRefusedError:
        return "refused"
    except (socket.timeout, TimeoutError):
        return "filtered"
    except OSError as e:
        if e.errno in (errno.EHOSTUNREACH, errno.ENETUNREACH):
            return "unreachable"
        return f"error:{e.errno}"
    finally:
        s.close()


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def spoof(src: str, dst: str, dport: int, sport: int, count: int) -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    saddr, daddr = socket.inet_aton(src), socket.inet_aton(dst)
    for _ in range(count):
        seq = random.getrandbits(32)
        tcp_hdr = struct.pack("!HHLLBBHHH", sport, dport, seq, 0, 5 << 4, 0x02, 64240, 0, 0)
        pseudo = saddr + daddr + struct.pack("!BBH", 0, socket.IPPROTO_TCP, len(tcp_hdr))
        tcp_hdr = tcp_hdr[:16] + struct.pack("!H", _checksum(pseudo + tcp_hdr)) + tcp_hdr[18:]
        ip_hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp_hdr), random.getrandbits(16), 0, 64,
                             socket.IPPROTO_TCP, 0, saddr, daddr)
        ip_hdr = ip_hdr[:10] + struct.pack("!H", _checksum(ip_hdr)) + ip_hdr[12:]
        s.sendto(ip_hdr + tcp_hdr, (dst, 0))
        time.sleep(0.2)


def hold(url: str, seconds: float, cacert: str | None, interval: float = 0.2) -> dict:
    u = urllib.parse.urlsplit(url)
    ctx = ssl.create_default_context(cafile=cacert) if u.scheme == "https" else None

    def connect():
        if ctx:
            return http.client.HTTPSConnection(u.hostname, u.port or 443, timeout=2, context=ctx)
        return http.client.HTTPConnection(u.hostname, u.port or 80, timeout=2)

    stats = {"ok": 0, "failed": 0, "connections": 1, "errors": []}
    conn = connect()
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        try:
            conn.request("GET", u.path or "/")
            resp = conn.getresponse()
            resp.read()
            if resp.status == 200:
                stats["ok"] += 1
            else:
                stats["failed"] += 1
        except Exception as exc:  # any failure counts; reconnect and keep measuring
            stats["failed"] += 1
            stats["errors"].append(type(exc).__name__)
            conn.close()
            conn = connect()
            stats["connections"] += 1
        time.sleep(interval)
    stats["errors"] = stats["errors"][:10]
    return stats


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    t = sub.add_parser("tcp")
    t.add_argument("ip")
    t.add_argument("port", type=int)
    t.add_argument("--timeout", type=float, default=3)
    sp = sub.add_parser("spoof")
    sp.add_argument("src")
    sp.add_argument("dst")
    sp.add_argument("dport", type=int)
    sp.add_argument("--sport", type=int, default=31337)
    sp.add_argument("--count", type=int, default=3)
    hp = sub.add_parser("hold")
    hp.add_argument("url")
    hp.add_argument("--seconds", type=float, default=40)
    hp.add_argument("--cacert")
    a = ap.parse_args()
    if a.cmd == "tcp":
        print(tcp(a.ip, a.port, a.timeout))
    elif a.cmd == "hold":
        print(json.dumps(hold(a.url, a.seconds, a.cacert)))
    else:
        spoof(a.src, a.dst, a.dport, a.sport, a.count)
        print("sent")
    return 0


if __name__ == "__main__":
    sys.exit(main())
