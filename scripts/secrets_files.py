#!/usr/bin/env python3
"""Assemble prod's identities into the file SOPS encrypts, and its public half.

  --plain DIR   rtr-a.key, rtr-a.pub, rtr-b.key, rtr-b.pub, root_ca.crt, root_ca.key
  --out-secret  YAML with the private material (to be encrypted, never committed in clear)
  --out-public  YAML with only public material, committed so prod can check what it runs

Never prints a private value.
"""

from __future__ import annotations

import argparse
import hashlib
import ssl
from pathlib import Path

import yaml


class _Literal(str):
    pass


def _literal(dumper, data):
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")


yaml.add_representer(_Literal, _literal)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--plain", type=Path, required=True)
    ap.add_argument("--out-secret", type=Path, required=True)
    ap.add_argument("--out-public", type=Path, required=True)
    a = ap.parse_args()
    p = a.plain
    cert = (p / "root_ca.crt").read_text()
    fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert)).hexdigest()
    secret = {
        "wireguard": {r: (p / f"{r}.key").read_text().strip() for r in ("rtr-a", "rtr-b")},
        "ca": {"root_cert": _Literal(cert), "root_key": _Literal((p / "root_ca.key").read_text())},
    }
    public = {
        "about": "Public half of prod's SOPS-managed identities (secrets/prod.sops.yaml). Safe to publish.",
        "wireguard_public_keys": {r: (p / f"{r}.pub").read_text().strip() for r in ("rtr-a", "rtr-b")},
        "ca_root_fingerprint_sha256": fingerprint,
        "ca_root_cert": _Literal(cert),
    }
    a.out_secret.write_text(yaml.dump(secret, sort_keys=False))
    a.out_public.parent.mkdir(parents=True, exist_ok=True)
    a.out_public.write_text(yaml.dump(public, sort_keys=False))
    print(f"wrote {a.out_public} (CA root fingerprint {fingerprint})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
