#!/usr/bin/env python3
"""Probe helper used by Gate 2 from inside lab containers.

  pp-probe.py tcp IP PORT [--timeout S]     prints open | refused | filtered | unreachable
  pp-probe.py spoof SRC DST DPORT [--sport N] [--count N]
                                            sends TCP SYNs with a forged source address
                                            (a harmless decoy packet; no payload)
"""

import argparse
import errno
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
    a = ap.parse_args()
    if a.cmd == "tcp":
        print(tcp(a.ip, a.port, a.timeout))
    else:
        spoof(a.src, a.dst, a.dport, a.sport, a.count)
        print("sent")
    return 0


if __name__ == "__main__":
    sys.exit(main())
