"""PacketProof command line.

  python -m packetproof render  [--network network.yaml] [--fault F07] --out build/lab
  python -m packetproof deploy  --render build/lab
  python -m packetproof evidence --render build/lab --out evidence/
  python -m packetproof destroy --render build/lab
  python -m packetproof faults                       list the planted faults
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

from . import faults, render_lab
from .model import ROOT, Network


def cmd_render(args: argparse.Namespace) -> int:
    data = yaml.safe_load(Path(args.network).read_text())
    fault = None
    if args.fault:
        fault = faults.load_faults()[args.fault]
        data = faults.apply_intent(data, fault)
    net = Network(data)
    out = Path(args.out)
    render_lab.render(net, out)
    if fault:
        faults.apply_render(out, fault)
        (out / "fault.json").write_text(json.dumps(fault, indent=2) + "\n")
    print(f"rendered {'with ' + args.fault if args.fault else 'baseline'} into {out}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="packetproof", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("render")
    r.add_argument("--network", default=str(ROOT / "network.yaml"))
    r.add_argument("--fault")
    r.add_argument("--out", required=True)
    for name in ("deploy", "destroy", "evidence"):
        p = sub.add_parser(name)
        p.add_argument("--render", required=True)
        if name == "deploy":
            p.add_argument("--secrets", help="decrypted SOPS file (JSON) with prod's managed identities")
        if name == "evidence":
            p.add_argument("--out", required=True)
    sub.add_parser("faults")
    args = ap.parse_args(argv)

    if args.cmd == "render":
        return cmd_render(args)
    if args.cmd == "faults":
        for f in faults.load_faults().values():
            print(f"{f['id']}  {f['layer']:<9} {f['where']:<14} {f['title']}")
        return 0
    from . import lab  # needs docker; imported only for lab commands
    if args.cmd == "deploy":
        res = lab.deploy(Path(args.render), Path(args.secrets) if args.secrets else None)
        print(json.dumps(res, indent=2))
        return 0 if res.get("deploy_rc") == 0 else 1
    if args.cmd == "evidence":
        lab.evidence(Path(args.render), Path(args.out))
        return 0
    if args.cmd == "destroy":
        lab.destroy(Path(args.render))
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
