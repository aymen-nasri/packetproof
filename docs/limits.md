# What each gate cannot see

The most useful output of this project is not the network. It is this page. Every row is backed by
a CI run, a planted fault or a feasibility check; run numbers are in [scorecard.md](scorecard.md).

## Gate 1: static checks (about one minute, nothing deployed)

| Tool | Sees | Cannot see | Evidence |
|---|---|---|---|
| JSON Schema | the structure and types of `network.yaml` | anything about meaning | |
| Conftest on the intent | the 13 hand-written invariants, as `network.yaml` states them | template bugs: the intent can be right while the generated config is wrong | F21 (source NAT removed in the template) passed Gate 1 |
| Conftest on the loaded rulesets | the firewall's structure as nftables actually loaded it, found by hook and device: default drop, established first, edge filter on the uplink's source addresses, reverse-path check on every zone interface | what the rules let through. A broad accept is caught only because it displaced the established/related rule. Until v1.1.0 it found chains by name, so a template that dropped a chain's hook would have passed ([review](review-v1.0.0.md)) | F13; 8 policy unit tests |
| `vtysh --dryrun` | FRR syntax | meaning. It can exit 0 without checking anything, so Gate 1 first proves it rejects a broken config | [feasibility test B](feasibility.md#test-b-batfish-reads-the-generated-frr-configs) |
| Batfish | FRR configs (as Cumulus files): parsing, BGP session compatibility, routes, route leaks | nftables, WireGuard, DNS, TLS, HAProxy. It reports the BGP session over `wg0` as established even when the tunnel is down, and does not model WireGuard keys, endpoints or AllowedIPs. Its grammar lacks `exit`, `log stdout` and `bgp ebgp-requires-policy`, so the snapshot leaves those lines out | [feasibility test B2](feasibility.md#test-b-batfish-reads-the-generated-frr-configs); F08, F09, F10 |

## Gate 2: the live copy (about four minutes since v1.1.0, six and a half before)

| Sees | Cannot see | Evidence |
|---|---|---|
| Real traffic between real daemons, on one runner | Mistakes another control masks: four faults pass Gate 2 because another layer holds. F04, F07 and F10 escape both gates (below). F26 opens the resolver to the DMZ, but the DMZ has no DNS flow through the firewall and no resolver configured, so no packet can show it; Gate 1 catches it (INV-05). Until amendment A2, F05 passed Gate 2 too: as first written it could not change any route | F04, F07, F10, F26 |
| Paths that exist only in the address plan | Anything off the plan. Until v1.1.0 every container also sat on containerlab's management network, a path around the zone firewall that no attack path tried; Gate 2 now checks each host has only its planned address | [review](review-v1.0.0.md); `test_planes` |
| Whether a probe really ran | Since v1.1.0: nothing; every probe and capture must prove it ran or the test errors. In v1.0.0 the three nmap scans (AP-01, AP-04, AP-08) timed out on every host and reported nothing, so those attack paths proved nothing | PR #19's first run |
| Only what a test asks | Anything without a test. The tests are hand-written, which keeps them independent of the generator, but they cover the method's list and nothing more | |
| | Hardware, real latency, real loss: containerlab "does not fully replicate the hardware characteristics" | |
| | The runner's environment leaking in: the host's AppArmor profiles confine `wg` and `bgpd` inside privileged containers | [feasibility.md](feasibility.md); evidence file `runner-host.txt` |

### Two blind spots Gate 3 exposed, and how they were closed

| Fault | What went wrong | Fixed in | After the fix |
|---|---|---|---|
| F06: inbound route-map removed on rtr-a | Escaped both gates. FRR's RFC 8212 safety net, `bgp ebgp-requires-policy`, defaults to off under the `frr defaults datacenter` profile the generator uses (FRR 10.7.1, `bgpd/bgp_vty.c`), so rtr-a accepted rtr-b's routes with no policy at all. Batfish agreed with the live network | [b0e2b20](https://github.com/aymen-nasri/packetproof/commit/b0e2b20): the safety net set explicitly; since [42970a2](https://github.com/aymen-nasri/packetproof/commit/42970a2) it is the default of the traditional profile | Escaped, then caught by Gate 2 after b0e2b20: with no inbound policy rtr-a now accepts nothing, and site B becomes unreachable |
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
| Drift in FRR (against a fresh FRR started from the same file) and in nftables | Host services and the lab's own wiring: the in-place apply covers router FRR and nftables only; DNS, CA, proxy and topology changes need a rebuild. Before v1.1.0, the drift check reloaded rtr-a's ruleset before comparing it, so nftables drift on rtr-a could not be seen | prod runs, steps 3b and 5a; [review](review-v1.0.0.md) |

**What the drift check found:** under `frr defaults datacenter`, applying a bundle whose FRR configs
were unchanged left all three routers running with `no bgp deterministic-med` and without
`use-underlays-nexthop-weight`. The cause is FRR bug
[FRRouting/frr#22939](https://github.com/FRRouting/frr/issues/22939), fixed upstream but in no release
yet. Since [42970a2](https://github.com/aymen-nasri/packetproof/commit/42970a2) the generator uses the
traditional profile, which does not trigger it, and an in-place apply leaves no drift
([prod.md](prod.md#what-the-drift-check-found-an-frr-bug-now-avoided)). The same bug returns if anyone
turns `bgp deterministic-med` on before FRR ships the fix.

## Gate 3 itself

- It grades only the faults its own author planted. Fault types come from common real-world mistakes,
  and the list and the rules were committed before any gate existed ([method.md](method.md)), but
  one person still wrote both sides.
- Timing is measured on shared runners and varies; numbers are medians with ranges. A faulted lab
  is slow: its probes wait out their timeouts (F15, which drops all return traffic, took 31 minutes
  in run 42902266017).
- A gate that could not judge a fault (a tool, the runner or the harness failed) makes that fault
  void and re-run, never a catch (amendment A2). Before A2, such a failure would have counted as a
  catch; no published run had one.
