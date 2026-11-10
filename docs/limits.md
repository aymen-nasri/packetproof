# What each gate cannot see

The most useful output of this project is not the network. It is this page. Every row is backed by
a CI run, a planted fault or a week-1 result; run numbers are in [scorecard.md](scorecard.md).

## Gate 1: static checks (about one minute, nothing deployed)

| Tool | Sees | Cannot see | Evidence |
|---|---|---|---|
| JSON Schema | the structure and types of `network.yaml` | anything about meaning | |
| Conftest on the intent | the 13 hand-written invariants, as `network.yaml` states them | template bugs: the intent can be right while the generated config is wrong | F21 (source NAT removed in the template) passed Gate 1 |
| Conftest on the loaded rulesets | the firewall's structure as nftables actually loaded it: default drop, established first, edge filter, reverse-path check | what the rules let through. A broad accept is caught only because it displaced the established/related rule | F13 |
| `vtysh --dryrun` | FRR syntax | meaning. It can exit 0 without checking anything, so Gate 1 first proves it rejects a broken config | week 1, test B |
| Batfish | FRR configs (as Cumulus files): parsing, BGP session compatibility, routes, route leaks | nftables, WireGuard, DNS, TLS, HAProxy. It reports the BGP session over `wg0` as established even when the tunnel is down, and does not model WireGuard keys, endpoints or AllowedIPs. Its grammar lacks `exit`, `log stdout` and `bgp ebgp-requires-policy`, so the snapshot leaves those lines out | week 1 B2; F08, F09, F10 |

## Gate 2: the live copy (about six minutes)

| Sees | Cannot see | Evidence |
|---|---|---|
| Real traffic between real daemons, on one runner | Mistakes another control masks: three faults changed configs but no traffic (below) | F04, F07, F10 |
| Only what a test asks | Anything without a test. The tests are hand-written, which keeps them independent of the generator, but they cover the method's list and nothing more | |
| | Hardware, real latency, real loss: containerlab "does not fully replicate the hardware characteristics" | |
| | The runner's environment leaking in: the host's AppArmor profiles confine `wg` and `bgpd` inside privileged containers | docs/go-no-go.md; evidence file `runner-host.txt` |

### Two blind spots Gate 3 exposed, and how they were closed

| Fault | What went wrong | Fixed in | After the fix |
|---|---|---|---|
| F06: inbound route-map removed on rtr-a | Escaped both gates. FRR's RFC 8212 safety net, `bgp ebgp-requires-policy`, defaults to off under the `frr defaults datacenter` profile the generator uses (FRR 10.7.1, `bgpd/bgp_vty.c`), so rtr-a accepted rtr-b's routes with no policy at all. Batfish agreed with the live network | [b0e2b20](https://github.com/aymen-nasri/packetproof/commit/b0e2b20): the safety net is set explicitly | Escaped, then caught by Gate 2 after b0e2b20: with no inbound policy rtr-a now accepts nothing, and site B becomes unreachable |
| F11: ICMP "fragmentation needed" dropped | Gate 1 caught it, but Gate 2's path-MTU test could not: the 1,400-byte line was the outside host's own, so its TCP MSS kept packets small and path-MTU discovery never ran | [9bd8588](https://github.com/aymen-nasri/packetproof/commit/9bd8588): the outside host advertises a 1460-byte MSS on its 1400-byte line, and a test checks haproxy learned the 1400-byte path | Caught by both gates |

The first attempt at the F11 fix ([b0e2b20](https://github.com/aymen-nasri/packetproof/commit/b0e2b20))
lowered the MTU on one end of the link only. That built a real black hole into the baseline: frames
over 1400 bytes from the outside host were dropped silently by the receiving end, with no ICMP, so
its TLS ClientHello never arrived. An MTU mismatch inside one link is a fault, not a bottleneck.

## The three escapes that remain, and why each changed no traffic

| Fault | What was planted | Why the network still behaved | Would bite when |
|---|---|---|---|
| F04 | rtr-b advertises its own uplink /31 over the tunnel | rtr-a's inbound filter accepts only site B's private /16; it took 2 of the 3 prefixes and dropped the /31 | rtr-a's inbound filter is loosened too |
| F07 | rtr-a sends a default route to rtr-b | rtr-b's inbound filter accepts only site A's /16; it took 6 prefixes and its default still points at its own ISP | rtr-b's inbound filter is loosened too |
| F10 | rtr-a sends to the wrong WireGuard port (51821) | rtr-b's side was right, and WireGuard updates a peer's endpoint from authenticated packets (roaming): `wg show` on rtr-a reported `203.0.113.1:51820` | rtr-b stops initiating, for example behind NAT with no keepalive |

These are latent faults: defence in depth worked, and no traffic test can see them. Only a static
invariant could, for example "a site's tunnel announcements and filters match its zones" or "the
configured WireGuard endpoint is the peer's real port". Adding invariants aimed at known faults
after seeing them escape would flatter the score, so they are left as escapes.

## The prod change path

| Sees | Cannot see | Evidence |
|---|---|---|
| Whether images and bundles are the ones CI built and signed; a tampered bundle is refused | Whether CI itself was honest: provenance proves which workflow built a bundle, not that the workflow is correct | prod runs, step 2 |
| Failed requests and broken connections on two held TCP connections during an apply | Anything the two probes do not cross; loss shorter than one 0.2 s probe interval | prod runs, step 4 |
| Drift in FRR (against a fresh FRR started from the same file) and in nftables | Host services: the in-place apply covers router FRR and nftables only; DNS, CA and proxy changes need a rebuild | prod runs, steps 3b and 5a |

**What the drift check found:** `frr-reload.py --reload` is not idempotent under `frr defaults
datacenter`. Applying a bundle whose FRR configs were unchanged left all three routers running with
`no bgp deterministic-med` and without `use-underlays-nexthop-weight`, which the bundle never asked
for. The routers matched a fresh FRR exactly before the apply, so the apply tool caused it. Neither
setting changes traffic in this topology, but it is configuration nobody chose, and prod reports it
as drift. Moving off the datacenter profile would remove it; that needs Batfish and both gates
re-validated and is not done.

## Gate 3 itself

- It grades only the faults its author planted. Fault types come from common real-world mistakes,
  and the list and the rules were committed before any gate existed ([method.md](method.md)), but
  the author still wrote both sides.
- Timing is measured on shared runners and varies; numbers are medians with ranges.
