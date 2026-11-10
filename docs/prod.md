# The prod change path

There is no always-on free host, so "prod" is rebuilt in CI from the previous config bundle, and the
new bundle is applied to it in place, as a real change would land ([prod.yml](../.github/workflows/prod.yml),
[scripts/prod.py](../scripts/prod.py)):

1. pull both lab images by digest and verify their cosign signatures before use
2. verify both bundles' GitHub attestation and cosign signature, and prove that a tampered copy
   (rtr-a's forward policy flipped to accept, repacked under the same name) is refused
3. rebuild prod from the previous bundle; 3b. check for drift before the change
4. apply the new bundle in place: `frr-reload.py --reload` and one atomic `nft -f` transaction per
   router, while two probes each hold one keep-alive connection and send a request every 0.2 s:
   one from LAN-A to the internet through NAT, one from site B to the proxy across the tunnel
5. check for drift (after a self-test that planted drift in FRR and nftables is caught), then run all
   of Gate 2 with the tests of the version just applied

## The change measured: a firewall-only change

Bundle A ([3cd8940](https://github.com/aymen-nasri/packetproof/commit/3cd8940)) to bundle B
([52f80f7](https://github.com/aymen-nasri/packetproof/commit/52f80f7)), which adds a counter for what
each router's default-drop policy refuses. Nothing allowed or denied changes.

| Prod run | Bundles verified, tampered refused | Apply took | Failed requests | Broken connections | Gate 2 after | Drift after |
|---|---|---|---|---|---|---|
| [42827614277](https://github.com/aymen-nasri/packetproof/actions/runs/42827614277) | yes, yes | 0.88 s | 1 (a DNS error at an unknown time) | 1 | 110 of 118 | reported on every router (see below) |
| [42836367491](https://github.com/aymen-nasri/packetproof/actions/runs/42836367491) | yes, yes | 1.02 s | 0 | 0 | 118 of 118 | 2 BGP lines on every router |
| [42838516660](https://github.com/aymen-nasri/packetproof/actions/runs/42838516660) | yes, yes | 0.97 s | 0 | 0 | 118 of 118 | 2 BGP lines on every router; none before the apply |

**Result: a firewall-only change applied in place dropped no TCP connections** in the two runs whose
probes were trustworthy: 225 of 225 requests on the NAT path and 224 of 224 across the tunnel, each
over one connection that stayed up through the change. These are two measurements, not a median.

## What the first run got wrong, and what changed

| Problem in run 42827614277 | Cause | Fix ([cb34874](https://github.com/aymen-nasri/packetproof/commit/cb34874)) |
|---|---|---|
| 8 Gate 2 DNS tests failed with SERVFAIL | Bundles were packed with every file's mtime set to 0, and NSD does not load a zone file whose mtime is 0 (its log lacked "read with success") | New bundles use the commit's time (`SOURCE_DATE_EPOCH`); prod resets mtimes on extraction; ns1 now fails readiness without its zone |
| The drift check reported every router | It compared the live router with the file through `frr-reload.py --test`, which counts FRR's own formatting (`frr version 10.7.1_git`, profile defaults) as differences | It compares the live router with a fresh FRR started from the same file |
| One request failed on the tunnel probe | A DNS error at an unknown moment, possibly before the apply | Both paths must work before measuring; every failure is timestamped against the apply window |

## What the drift check found: an FRR bug, now avoided

Bundles A and B have identical FRR configs, yet after the apply all three routers ran with `no bgp
deterministic-med` and without `use-underlays-nexthop-weight`. In run 42838516660 the drift check
before the apply found the routers matching a fresh FRR exactly, so the apply caused it. nftables
showed no drift before or after.

**Cause.** An FRR 10.7.1 bug, [FRRouting/frr#22939](https://github.com/FRRouting/frr/issues/22939). The
`use-underlays-nexthop-weight` command and its config writer use `BGP_WECMP_BEHAVIOR_USE_RECURSIVE_VALUE`,
an enum value of 3, as a mask on `bgp->flags` (`bgpd/bgp_vty.c`, `bgpd/bgp_mpath.h`). Bit 1 of that
mask is `BGP_FLAG_DETERMINISTIC_MED`. With deterministic-med on, which `frr defaults datacenter`
does by default, `show running-config` prints a spurious `use-underlays-nexthop-weight`; removing
it, as `frr-reload.py` does, clears deterministic-med too. It is fixed upstream
([FRRouting/frr#22552](https://github.com/FRRouting/frr/pull/22552), backported to `stable/10.7` on
2026-09-30) but in no release yet: 10.7.1 is the newest.

**Fix.** [42970a2](https://github.com/aymen-nasri/packetproof/commit/42970a2) moves the generator to
`frr defaults traditional`, which leaves deterministic-med off, and sets the fast timers explicitly.
The traditional profile also keeps RFC 8212's `ebgp-requires-policy` on by default.

**Proof.** Prod run [42854055534](https://github.com/aymen-nasri/packetproof/actions/runs/42854055534)
applied the 42970a2 bundle in place on top of itself, the purest test of idempotence:

| Before the apply | Apply | Failed requests | Broken connections | After the apply | Gate 2 after |
|---|---|---|---|---|---|
| no drift on any router (FRR or nftables) | 0.92 s | 0 of 449 | 0 | no drift on any router; the self-test still caught planted drift | 119 of 119 |

The firewall-only measurement above was taken under the old profile; its FRR configs did not change,
so the profile does not affect what it measured.

## Prod with long-lived identities from SOPS

Since PR #9, prod no longer runs throwaway identities. Both routers' WireGuard keys and the lab CA's
root are decrypted from `secrets/prod.sops.yaml` with an age key that only the `prod` environment
holds, and step 5c checks prod against the committed public halves ([secrets.md](secrets.md)). Steps
4 and 5 also gained a ping across the tunnel, five a second, next to the two TCP probes.

| Prod run | Bundles | Identities | Apply | Failed requests | Broken connections | Pings lost | Drift before / after | Gate 2 after |
|---|---|---|---|---|---|---|---|---|
| [42878657349](https://github.com/aymen-nasri/packetproof/actions/runs/42878657349) | verified, tampered refused | **not decrypted**: "unknown identity type" | not run | | | | | |
| [42880852321](https://github.com/aymen-nasri/packetproof/actions/runs/42880852321) | verified, tampered refused | in use (from the evidence); the check itself crashed | 0.71 s | 0 of 450 | 0 | 0 of 200 | none / none | 123 of 123 |
| [42883900778](https://github.com/aymen-nasri/packetproof/actions/runs/42883900778) | verified, tampered refused | **checked: all match** | 0.75 s | 0 of 449 | 0 | 0 of 200 | none / none | 123 of 123 |

**What the check covers** (run 42883900778): each router's own WireGuard public key and its peer's
key are the ones in `secrets/prod-public.yaml`; the lab CA's root has the committed fingerprint
`d4deb1be...d572`; and the certificate HAProxy serves verifies against the committed root itself,
not only against the lab's own copy. The bundles were 04c8e10 (rebuilt) and edff18b (applied).

**What went wrong first, and the fixes:**

- Run 42878657349 could not decrypt. The bootstrap script piped the age key into `gh secret set`, and
  Windows PowerShell 5.1 sends piped text to a native program with a UTF-8 byte-order mark in front
  and a CRLF behind. Fixed in PR #14: prod strips both, and the script now passes the key in a file.
- Run 42880852321 ran with the managed identities (its evidence shows both WireGuard public keys
  and step-ca's root fingerprint matching), but the identity check crashed: it read the root
  certificate from the runner's disk, where the CA had written it as root with mode 0600. Fixed in
  PR #15: the check reads it inside the lab, as clients do.
