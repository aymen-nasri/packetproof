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
