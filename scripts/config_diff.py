#!/usr/bin/env python3
"""The network equivalent of a Terraform plan: what a change would do to each router.

For every router, FRR is started with the base branch's config, and `frr-reload.py --test`
reports the lines it would delete and add to reach the pull request's config, without applying
anything. Firewall changes are shown as a plain diff of the rendered rulesets.

Usage: python3 scripts/config_diff.py --base build/base --new build/lab --out results/diff.md
"""

from __future__ import annotations

import argparse
import difflib
import subprocess
import time
from pathlib import Path

ROUTER_IMAGE = "packetproof/router:dev"
MARKER = "<!-- packetproof-config-diff -->"


def run(cmd: list[str], timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def frr_reload_test(router: str, base: Path, new: Path) -> str:
    name = f"pp-diff-{router}"
    run(["docker", "rm", "-f", name])
    d = base / "routers" / router
    # Privileged like the lab's routers: zebra cannot start, and the config never loads, without it.
    run(["docker", "run", "-d", "--name", name, "--hostname", router, "--network", "none", "--privileged",
         "-v", f"{d / 'frr.conf'}:/etc/frr/frr.conf", "-v", f"{d / 'daemons'}:/etc/frr/daemons",
         "-v", f"{d / 'vtysh.conf'}:/etc/frr/vtysh.conf", ROUTER_IMAGE])
    try:
        # vtysh answers before the daemons have read frr.conf; a plan taken then compares against
        # an empty router and lists the whole config (the plans on PRs #2 to #4 did). Wait until
        # the base config is really loaded.
        loaded = False
        for _ in range(60):
            out = run(["docker", "exec", name, "vtysh", "-c", "show running-config"]).stdout
            if "router bgp" in out:
                loaded = True
                break
            time.sleep(1)
        if not loaded:
            return "the base config did not load in 60 s, so no plan; plain diff instead:\n" + plain_diff(
                d / "frr.conf", new / "routers" / router / "frr.conf")
        run(["docker", "cp", str(new / "routers" / router / "frr.conf"), f"{name}:/tmp/new.conf"])
        res = run(["docker", "exec", name, "/usr/lib/frr/frr-reload.py", "--test", "/tmp/new.conf"])
        out = (res.stdout + res.stderr).strip()
        if res.returncode != 0 and "Lines To" not in out:
            return f"frr-reload.py --test failed (rc {res.returncode}); plain diff instead:\n" + plain_diff(
                d / "frr.conf", new / "routers" / router / "frr.conf")
        return out
    finally:
        run(["docker", "rm", "-f", name])


def plain_diff(a: Path, b: Path) -> str:
    left = a.read_text().splitlines() if a.exists() else []
    right = b.read_text().splitlines() if b.exists() else []
    return "\n".join(difflib.unified_diff(left, right, str(a.name) + " (base)", str(b.name) + " (this change)", lineterm=""))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", type=Path, required=True)
    ap.add_argument("--new", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args()
    a.base, a.new = a.base.resolve(), a.new.resolve()
    parts = [MARKER, "## What this change does to the network", ""]
    if not (a.base / "routers").exists():
        parts.append("The base branch has no rendered network yet, so there is nothing to compare against.")
    else:
        for router_dir in sorted((a.new / "routers").iterdir()):
            r = router_dir.name
            frr = frr_reload_test(r, a.base, a.new) if (a.base / "routers" / r / "frr.conf").exists() else "(new router)"
            nft = plain_diff(a.base / "routers" / r / "ruleset.nft", router_dir / "ruleset.nft") if (router_dir / "ruleset.nft").exists() else ""
            parts += [f"### {r}", "", "<details><summary>FRR: frr-reload.py --test</summary>", "", "```", frr or "(no change)", "```",
                      "</details>", ""]
            if nft:
                parts += ["<details><summary>nftables ruleset diff</summary>", "", "```diff", nft, "```", "</details>", ""]
            elif (router_dir / "ruleset.nft").exists():
                parts += ["nftables ruleset: no change", ""]
    text = "\n".join(parts) + "\n"
    if len(text) > 60000:  # GitHub comments are capped at 65536 characters
        text = text[:60000] + "\n\n(truncated: the full plan is in the gate1 artifact)\n"
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(text)
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
