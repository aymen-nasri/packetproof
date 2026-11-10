#!/usr/bin/env python3
"""The "prod" change path: verify, rebuild the previous release, apply the new one in place.

There is no always-on free host, so prod is rebuilt from the previous config bundle and the new
bundle is applied to it in place, as a real change would land. Fresh builds hide ordering and
disruption problems; this path does not.

  fetch    download the two newest config bundles built on main (bundle.yml)
  verify   check each bundle's GitHub attestation and cosign signature, and prove that a
           tampered copy is refused
  extract  unpack a verified bundle into a render directory
  apply    apply a new bundle to the running lab (frr-reload.py --reload, atomic nft -f) while
           two probes each hold one TCP connection and count failed requests, and a ping across
           the tunnel counts lost packets
  drift    compare what runs with what the bundle says (FRR and nftables), after a self-test
           that proves a planted drift is detected
  identities  check that prod runs the SOPS-managed identities: each router's WireGuard key and
           its peer's, and the CA root that the served certificate chains to, against the public
           halves committed in secrets/prod-public.yaml

All results go to --out as JSON. Run from the repository root.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from packetproof import lab  # noqa: E402

REPO = "aymen-nasri/packetproof"
BUNDLE_IDENTITY = f"https://github.com/{REPO}/.github/workflows/bundle.yml@refs/heads/main"
OIDC = "https://token.actions.githubusercontent.com"
ROUTER_IMAGE = "packetproof/router:dev"


def run(cmd: list[str], check: bool = False, timeout: int = 300) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=check)


def fetch(out: Path, from_run: str | None = None, to_run: str | None = None) -> dict:
    runs = json.loads(run(["gh", "run", "list", "-R", REPO, "-w", "bundle.yml", "-b", "main", "-s", "success",
                           "--json", "databaseId,headSha,createdAt", "-L", "50"], check=True).stdout)
    if from_run and to_run:  # a chosen pair, e.g. to re-measure one change
        by_id = {str(r["databaseId"]): r for r in runs}
        runs = [by_id[to_run], by_id[from_run]]
    runs = runs[:2]
    if len(runs) < 2:
        raise SystemExit("need two successful bundle runs on main")
    result = {}
    for role, r in zip(("to", "from"), runs):
        d = out / role
        shutil.rmtree(d, ignore_errors=True)
        run(["gh", "run", "download", str(r["databaseId"]), "-R", REPO, "-n", "config-bundle", "-D", str(d)], check=True)
        result[role] = {"run": r["databaseId"], "commit": r["headSha"], "built": r["createdAt"],
                        "bundle": str(next(d.glob("packetproof-config-*.tgz")))}
    return result


def verify_one(bundle: Path) -> dict:
    att = run(["gh", "attestation", "verify", str(bundle), "-R", REPO,
               "--signer-workflow", f"{REPO}/.github/workflows/bundle.yml"])
    sig = Path(str(bundle)[: -len(".tgz")] + ".sigstore.json")
    cos = run(["cosign", "verify-blob", "--bundle", str(sig), "--certificate-identity", BUNDLE_IDENTITY,
               "--certificate-oidc-issuer", OIDC, str(bundle)])
    return {"attestation_ok": att.returncode == 0, "signature_ok": cos.returncode == 0,
            "attestation_output": (att.stdout + att.stderr)[-400:], "signature_output": (cos.stdout + cos.stderr)[-400:]}


def tamper(bundle: Path, work: Path) -> Path:
    """A meaningful tamper: open the firewall on rtr-a (forward policy accept) and repack."""
    t = work / "tamper"
    shutil.rmtree(t, ignore_errors=True)
    t.mkdir(parents=True)
    with tarfile.open(bundle) as tf:
        tf.extractall(t, filter="data")
    ruleset = t / "lab" / "routers" / "rtr-a" / "ruleset.nft"
    ruleset.write_text(ruleset.read_text().replace("hook forward priority filter; policy drop;",
                                                   "hook forward priority filter; policy accept;"))
    bad = work / bundle.name  # same name, so only the content differs
    with tarfile.open(bad, "w:gz") as tf:
        tf.add(t / "lab", arcname="lab")
    sig = Path(str(bundle)[: -len(".tgz")] + ".sigstore.json")
    shutil.copy(sig, work / sig.name)
    return bad


def verify(fetched: dict, work: Path) -> dict:
    res = {role: verify_one(Path(info["bundle"])) for role, info in fetched.items() if role in ("from", "to")}
    bad = tamper(Path(fetched["to"]["bundle"]), work / "tampered")
    t = verify_one(bad)
    res["tampered"] = {**t, "refused": not t["attestation_ok"] and not t["signature_ok"]}
    res["ok"] = all(res[r]["attestation_ok"] and res[r]["signature_ok"] for r in ("from", "to")) and res["tampered"]["refused"]
    return res


def extract(bundle: Path, dest: Path) -> Path:
    shutil.rmtree(dest, ignore_errors=True)
    dest.mkdir(parents=True)
    with tarfile.open(bundle) as tf:
        tf.extractall(dest, filter="data")
    # Like `tar -m`: files get the extraction time. Bundles built before bundle.yml used the
    # commit time carry mtime 0, and NSD does not load a zone file whose mtime is 0 (prod run
    # 42827614277: every outside DNS query got SERVFAIL).
    for p in dest.rglob("*"):
        os.utime(p, None, follow_symlinks=False)
    return dest / "lab"


def routers(render: Path) -> list[str]:
    return sorted(p.name for p in (render / "routers").iterdir())


def apply(running: Path, new: Path, seconds: int = 45) -> dict:
    probes = {
        "nat_path": ("client-a", "http://192.0.2.10/", ""),
        "tunnel_path": ("client-b", "https://www.packetproof.example/", "--cacert /shared/pki/root_ca.crt"),
    }
    # Both paths must work before the measurement starts, so a failure in the window is the
    # change's doing (prod run 42827614277 lost one request to a DNS error of unknown timing).
    for name, (node, url, extra) in probes.items():
        for _ in range(30):
            if lab.dexec(node, "sh", "-c", f"curl -fsS -o /dev/null --max-time 3 {extra} {url}").returncode == 0:
                break
            time.sleep(1)
    for name, (node, url, extra) in probes.items():
        lab.run(["docker", "exec", "-d", lab.container(node), "sh", "-c",
                 f"pp-probe.py hold {url} --seconds {seconds} {extra} > /tmp/hold-{name}.json"])
    # Router to router across the tunnel, five pings a second for most of the window: a dropped
    # tunnel or a flushed ruleset shows as lost packets even where TCP would retransmit and recover.
    pings = (seconds - 5) * 5
    lab.run(["docker", "exec", "-d", lab.container("rtr-a"), "sh", "-c",
             f"ping -q -i 0.2 -W 1 -c {pings} 172.31.255.1 > /tmp/ping-tunnel.txt 2>&1"])
    probe_start = time.monotonic()
    time.sleep(10)
    steps = []
    t0 = time.monotonic()
    for r in routers(new):
        c = lab.container(r)
        lab.run(["docker", "cp", str(new / "routers" / r / "frr.conf"), f"{c}:/tmp/new-frr.conf"])
        fr = lab.run(["docker", "exec", c, "/usr/lib/frr/frr-reload.py", "--reload", "/tmp/new-frr.conf"], check=False)
        steps.append({"router": r, "step": "frr-reload", "rc": fr.returncode, "output": (fr.stdout + fr.stderr)[-600:]})
        if (new / "routers" / r / "ruleset.nft").exists():
            lab.run(["docker", "cp", str(new / "routers" / r / "ruleset.nft"), f"{c}:/tmp/new.nft"])
            nf = lab.run(["docker", "exec", c, "nft", "-f", "/tmp/new.nft"], check=False)  # one atomic transaction
            steps.append({"router": r, "step": "nft -f", "rc": nf.returncode, "output": (nf.stdout + nf.stderr)[-600:]})
    apply_s = round(time.monotonic() - t0, 2)
    window = [round(t0 - probe_start, 1), round(time.monotonic() - probe_start, 1)]
    time.sleep(seconds - 8)
    results = {}
    for name, (node, _, _) in probes.items():
        out = lab.dexec(node, "cat", f"/tmp/hold-{name}.json").stdout
        try:
            results[name] = json.loads(out)
        except json.JSONDecodeError:
            results[name] = {"error": out[-300:]}
    lost = sum(p.get("failed", 0) for p in results.values())
    broken = sum(max(p.get("connections", 1) - 1, 0) for p in results.values())
    out = lab.dexec("rtr-a", "cat", "/tmp/ping-tunnel.txt").stdout
    m = re.search(r"(\d+) packets transmitted, (\d+) received", out)
    ping = ({"sent": int(m[1]), "received": int(m[2]), "lost": int(m[1]) - int(m[2])} if m
            else {"error": out[-300:]})
    results["tunnel_ping"] = ping
    return {"steps": steps, "apply_seconds": apply_s, "apply_window_s": window, "probes": results,
            "requests_failed": lost, "connections_broken": broken, "pings_lost": ping.get("lost"),
            "ok": all(s["rc"] == 0 for s in steps) and all("error" not in p for p in results.values())}


def _norm_nft(doc: dict) -> list:
    out = []
    for item in doc.get("nftables", []):
        if "metainfo" in item:
            continue
        (kind, body), = item.items()
        body = {k: v for k, v in body.items() if k != "handle"}
        out.append({kind: json.loads(json.dumps(body).replace('"packets"', '"_p"').replace('"bytes"', '"_b"'))})
    text = json.dumps(out, sort_keys=True)
    # Counters move all the time; their values are not configuration.
    import re
    return json.loads(re.sub(r'"_(p|b)": \d+', '"_\\1": 0', text))


def _norm_frr(text: str) -> list[str]:
    skip = ("Building configuration", "Current configuration", "frr version", "!", "end")
    return [line.rstrip() for line in text.splitlines() if line.strip() and not line.strip().startswith(skip)]


_reference_cache: dict[str, list[str]] = {}


def _reference_frr(r: str, want: Path) -> list[str]:
    """What FRR itself prints for the bundle's file, from a fresh router started with it. Comparing
    the live router with this, rather than with the file, keeps FRR's own formatting (version
    string, profile defaults such as `no bgp deterministic-med`) from counting as drift, which is
    what the first prod run reported (42827614277)."""
    if r in _reference_cache:
        return _reference_cache[r]
    d = (want / "routers" / r).resolve()
    name = f"pp-ref-{r}"
    run(["docker", "rm", "-f", name])
    # Privileged like the lab's routers: zebra cannot start, and the config never loads, without it.
    run(["docker", "run", "-d", "--name", name, "--hostname", r, "--network", "none", "--privileged", "-v", f"{d / 'frr.conf'}:/etc/frr/frr.conf",
         "-v", f"{d / 'daemons'}:/etc/frr/daemons", "-v", f"{d / 'vtysh.conf'}:/etc/frr/vtysh.conf", ROUTER_IMAGE])
    try:
        out = ""
        for _ in range(30):
            res = run(["docker", "exec", name, "vtysh", "-c", "show running-config"])
            if res.returncode == 0 and "router bgp" in res.stdout:
                out = res.stdout
                break
            time.sleep(1)
        _reference_cache[r] = _norm_frr(out)
        return _reference_cache[r]
    finally:
        run(["docker", "rm", "-f", name])


def _frr_drift(r: str, want: Path) -> list[str]:
    import difflib
    live = _norm_frr(lab.dexec(r, "vtysh", "-c", "show running-config").stdout)
    ref = _reference_frr(r, want)
    return [line for line in difflib.unified_diff(ref, live, "bundle", "running", lineterm="", n=0)
            if line.startswith(("+", "-")) and not line.startswith(("+++", "---"))]


def _nft_drift(r: str, want: Path) -> bool:
    running = json.loads(lab.dexec(r, "nft", "-j", "list", "ruleset").stdout)
    ifaces = sorted({x for x in lab.dexec(r, "ls", "/sys/class/net").stdout.split() if x.startswith(("eth", "wg"))})
    script = " ".join(f"ip link add {i} type dummy;" for i in ifaces) + " nft -f /r.nft && nft -j list ruleset"
    res = run(["docker", "run", "--rm", "--network", "none", "--cap-add", "NET_ADMIN", "-v",
               f"{(want / 'routers' / r / 'ruleset.nft').resolve()}:/r.nft:ro", "--entrypoint", "sh", ROUTER_IMAGE,
               "-c", script])
    return _norm_nft(running) != _norm_nft(json.loads(res.stdout))


def drift(want: Path) -> dict:
    site_routers = [r for r in routers(want) if (want / "routers" / r / "ruleset.nft").exists()]
    # Self-test first: plant drift in FRR and nftables on rtr-a, check both are seen, then undo.
    c = lab.container("rtr-a")
    lab.run(["docker", "exec", c, "vtysh", "-c", "configure terminal", "-c", "ip prefix-list DRIFT seq 5 permit 10.0.0.0/8"])
    lab.run(["docker", "exec", c, "nft", "insert", "rule", "inet", "pp", "forward", "ip", "saddr", "172.16.20.10", "accept"])
    self_test = {"frr_seen": bool(_frr_drift("rtr-a", want)), "nft_seen": _nft_drift("rtr-a", want)}
    lab.run(["docker", "exec", c, "vtysh", "-c", "configure terminal", "-c", "no ip prefix-list DRIFT"])
    lab.run(["docker", "cp", str(want / "routers" / "rtr-a" / "ruleset.nft"), f"{c}:/tmp/want.nft"])
    lab.run(["docker", "exec", c, "nft", "-f", "/tmp/want.nft"])
    found = {}
    for r in routers(want):
        frr = _frr_drift(r, want)
        nft = _nft_drift(r, want) if r in site_routers else False
        found[r] = {"frr": frr, "nft_differs": nft}
    clean = all(not v["frr"] and not v["nft_differs"] for v in found.values())
    return {"self_test": self_test, "routers": found,
            "ok": clean and self_test["frr_seen"] and self_test["nft_seen"]}


def identities(running: Path, public: Path) -> dict:
    import hashlib
    import ssl

    import yaml

    want = yaml.safe_load(public.read_text())
    keys = want["wireguard_public_keys"]
    wg = {}
    for r, key in keys.items():
        own = lab.dexec(r, "wg", "show", "wg0", "public-key").stdout.strip()
        peers = lab.dexec(r, "wg", "show", "wg0", "peers").stdout.split()
        peer_ok = sorted(peers) == sorted(k for n, k in keys.items() if n != r)
        wg[r] = {"own_key_matches": own == key, "peer_key_matches": peer_ok}
    # Read it inside the lab, as every client does: the CA writes it as root with mode 0600, so the
    # runner's user cannot read the bind-mounted copy (prod run 42880852321).
    pem = lab.dexec("client-a", "cat", "/shared/pki/root_ca.crt").stdout
    fp = hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()
    # The served certificate must chain to the committed root itself, not only to the lab's copy.
    net = lab.load(running)
    zone = net.data["dns"]["zone"]
    lab.run(["docker", "exec", "-i", lab.container("client-a"), "sh", "-c", "cat > /tmp/managed-root.crt"],
            input=want["ca_root_cert"])
    res = lab.dexec("client-a", "curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "10",
                    "--cacert", "/tmp/managed-root.crt", f"https://www.{zone}/")
    ca = {"root_fingerprint_matches": fp == want["ca_root_fingerprint_sha256"],
          "served_cert_verifies_with_committed_root": res.returncode == 0 and res.stdout.strip() == "200",
          "root_fingerprint_sha256": fp}
    ok = all(v["own_key_matches"] and v["peer_key_matches"] for v in wg.values()) and \
        ca["root_fingerprint_matches"] and ca["served_cert_verifies_with_committed_root"]
    return {"wireguard": wg, "ca": ca, "ok": ok}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", choices=["fetch", "verify", "extract", "apply", "drift", "identities"])
    ap.add_argument("--public", type=Path, default=ROOT / "secrets" / "prod-public.yaml")
    ap.add_argument("--work", type=Path, default=Path("prod"))
    ap.add_argument("--bundle", type=Path)
    ap.add_argument("--dest", type=Path)
    ap.add_argument("--running", type=Path)
    ap.add_argument("--new", type=Path)
    ap.add_argument("--from-run")
    ap.add_argument("--to-run")
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args()
    a.work.mkdir(parents=True, exist_ok=True)
    if a.cmd == "fetch":
        res = fetch(a.work, a.from_run or None, a.to_run or None)
    elif a.cmd == "verify":
        res = verify(json.loads((a.work / "fetched.json").read_text()), a.work)
    elif a.cmd == "extract":
        res = {"render": str(extract(a.bundle, a.dest))}
    elif a.cmd == "apply":
        res = apply(a.running, a.new)
    elif a.cmd == "identities":
        res = identities(a.running, a.public)
    else:
        res = drift(a.new)
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(res, indent=2) + "\n")
    print(json.dumps(res, indent=2)[-3000:])
    return 0 if res.get("ok", True) else 1


if __name__ == "__main__":
    sys.exit(main())
