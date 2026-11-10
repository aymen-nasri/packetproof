# Method: the rules that judge PacketProof's results

Written and committed on 2026-11-09, **before any test has run and before any test code exists**.
Results must never shape the rules that judge them, so this file follows three rules of its own:

1. **No silent edits.** If a rule has to change after any result exists, the original text stays
   and a dated entry is added under [Amendments](#amendments), saying what changed, why, and which
   results it affects. Affected results are reported under both the old and the new rule.
2. **Every run counts.** Every CI run used as evidence is linked. A run that fails for a reason
   outside the test (for example a GitHub outage or a registry rate limit) is still recorded; it
   may be re-run once, and both runs are reported.
3. **Predictions are not rules.** Where this file predicts which gate will catch a fault, the
   prediction is there to be checked and is scored as right or wrong. It never decides a result.

The design follows the project's brief, a planning document that is not part of this repository.
Its table of feasibility checks is reproduced in part 1 with the exact procedure added. Parts 2 to 5 fix the invariants, the planted
faults, the attack paths and the scoring rules for the later gates, so they too exist before any
gate has run.

**Reading it later.** This file describes the project as planned on 2026-11-09, so "will" and "not
built yet" refer to that day. Every later change to a rule is a dated entry under
[Amendments](#amendments); wording-only edits are listed under [Editorial changes](#editorial-changes).

## Contents

- [Part 1: feasibility tests](#part-1-feasibility-tests)
- [Part 2: the network the gates protect](#part-2-the-network-the-gates-protect)
- [Part 3: hand-written invariants](#part-3-hand-written-invariants)
- [Part 4: 30 planted faults](#part-4-30-planted-faults)
- [Part 5: 12 attack paths, each paired with a legitimate flow](#part-5-12-attack-paths-each-paired-with-a-legitimate-flow)
- [Part 6: how gates and the scorecard are judged](#part-6-how-gates-and-the-scorecard-are-judged)
- [Amendments](#amendments)
- [Editorial changes](#editorial-changes)

---

## Part 1: feasibility tests

Five assumptions are tested. Each gets a recorded **GO** or **NO-GO** in [feasibility.md](feasibility.md), with
links to the CI runs and the tool versions used. Where a test is NO-GO, the fallback listed here is
applied and recorded, not improvised. KVM is not tested: it is kept out of the critical path on
purpose.

### Shared setup

- Runner: GitHub-hosted `ubuntu-latest` in this public repository (4 vCPU, 16 GB). Each job logs
  the runner image version, kernel and Docker version.
- containerlab 0.83.0, installed from the release `.deb` with its SHA-256 checked.
- Router image: `quay.io/frrouting/frr:10.7.1` pinned by digest, plus nftables and wireguard-tools,
  built in the job. Hosts: `alpine:3.24.4` pinned by digest.
- Batfish: `batfish/allinone` pinned by digest (the `latest` build of 2026-08-27) and pybatfish
  2026.9.17.3748.
- All router configs are rendered by one small Python script from one description of the feasibility
  topology, so the configs Batfish reads are the configs the live lab runs.
- Addresses: internal ranges come from 172.16.0.0/12, avoiding Docker's 172.17.0.0/16 and
  containerlab's management 172.20.20.0/24. Simulated public addresses use the documentation
  ranges 198.51.100.0/24, 203.0.113.0/24 and 192.0.2.0/24 (RFC 5737).
- WireGuard keys are generated inside the job and never written to the repository or the logs.

### Feasibility topologies

**`feas-bgp`** (tests A, B, D): `client-a -- rtr-a -- isp -- rtr-b -- client-b`.

| Node | AS | Interfaces |
|---|---|---|
| rtr-a | 65001 | eth1 198.51.100.1/31 to isp; eth2 172.16.10.1/24 (LAN-A); lo 172.16.255.1/32 |
| isp | 65000 | eth1 198.51.100.0/31; eth2 203.0.113.0/31 |
| rtr-b | 65002 | eth1 203.0.113.1/31 to isp; eth2 172.24.10.1/24 (LAN-B); lo 172.24.255.1/32 |
| client-a | | 172.16.10.10/24, default route via 172.16.10.1 |
| client-b | | 172.24.10.10/24, default route via 172.24.10.1 |

eBGP sessions rtr-a to isp and isp to rtr-b. Each site router redistributes connected routes, and
its outbound route-map to isp allows only its LAN: 172.16.10.0/24 from rtr-a, 172.24.10.0/24 from
rtr-b. The loopbacks must never leave their router.

**`feas-wg`** (test C): the same five nodes. isp runs no BGP and has no route to either LAN. rtr-a
and rtr-b reach each other's eth1 address through isp by static routes. wg0 is 172.31.255.0/31 on
rtr-a and 172.31.255.1/31 on rtr-b, MTU 1420, UDP port 51820, kernel WireGuard, AllowedIPs limited
to the peer's tunnel address and LAN. eBGP 65001 to 65002 runs over the wg0 addresses.

### The planted error used in the feasibility tests (FEAS-F)

In rtr-a's outbound prefix-list to isp, the line `permit 172.16.10.0/24` is replaced by
`permit 172.16.0.0/16 le 32`. Effect: rtr-a's loopback 172.16.255.1/32 leaks to isp. Pings still
work, so only a routing-table check can see it.

### Test A: containerlab runs on a free runner

| | |
|---|---|
| Procedure | 5 independent jobs (a matrix of 5) in one workflow run. Each deploys `feas-bgp`, waits up to 120 s for convergence, runs the checks, saves evidence, destroys the lab. |
| Checks | (1) every BGP session is Established, seen from both ends; (2) rtr-a has 172.24.10.0/24 and rtr-b has 172.16.10.0/24, learned by BGP; (3) isp has exactly 172.16.10.0/24 and 172.24.10.0/24 from inside 172.16.0.0/12, nothing else; (4) `ping -c 5` client-a to client-b and back, at least 4 of 5 replies each way. |
| Timing | From the start of `containerlab deploy` to the end of the checks. Tool install and image build are timed separately (test D). |
| **GO if** | 5 of 5 runs pass every check, and every run's deploy-plus-checks time is under 5 minutes. |
| If not | Pin containerlab and Docker versions and re-run once. As a last resort, use plain Docker networks via compose and lose the point-to-point links. |

### Test B: Batfish reads the generated FRR configs

| | |
|---|---|
| Procedure | Render the 3 routers of `feas-bgp` as a Cumulus-style snapshot (one file per router: hostname, `/etc/network/interfaces`, `/etc/cumulus/ports.conf`, `frr.conf`), load it in `batfish/allinone` on the runner, and ask `fileParseStatus`, `parseWarning`, `initIssues`, `bgpSessionCompatibility`, `bgpSessionStatus` and `routes`. Then load the same snapshot with the planted error FEAS-F and ask `routes` again. |
| **GO if** | All five hold: (1) every file's parse status is PASSED; (2) zero parse warnings (the renderer emits only features the project uses, so any unrecognized line is in a used feature); (3) no init issue that names BGP, a prefix-list, a route-map, an interface address or a static route; other init issues are listed in the result; (4) every configured BGP session is a unique compatible match and Established; (5) isp's routes contain 172.16.255.1/32 in the FEAS-F snapshot and not in the baseline. |
| Recorded, not judged (B2) | The `feas-wg` routers as a second snapshot: whether Batfish recognises `wg0` and whether it reports the rtr-a to rtr-b session over it. This does not change the verdict. It decides which Batfish questions Gate 1 may rely on later, because the real design runs its main BGP session over the tunnel. |
| If not | Drop Batfish. Gate 1 becomes `vtysh -C`, the `frr-reload.py --test` diff, Conftest and Python route-policy checks. File the parse gap upstream and say why in the scorecard. |

### Test C: WireGuard works inside containers

| | |
|---|---|
| Procedure | In each of the same 5 jobs as test A, after `feas-bgp` is destroyed: load the `wireguard` module on the runner host, generate keys, deploy `feas-wg`, wait up to 120 s. |
| Checks | (1) `wg show wg0 latest-handshakes` is non-zero on both ends; (2) the BGP session over wg0 is Established on both ends. Extra evidence: (3) client-a and client-b ping each other, at least 4 of 5 replies each way; (4) isp has no route to 172.16.10.0/24 or 172.24.10.0/24; (5) during a ping, a capture on isp sees UDP 51820 and no ICMP between the two LAN addresses. Checks 3 to 5 prove that traffic really crossed the tunnel. |
| **GO if** | The brief's rule: handshake and BGP up (checks 1 and 2) on the runner, in every run. If checks 3 to 5 fail while 1 and 2 pass, the verdict is still GO, and the failure is recorded as a risk for the full lab. |
| If not | Use userspace wireguard-go. If WSL2 fails (test E), run the tunnel in CI only. |

### Test D: the CI time budget holds

| | |
|---|---|
| Full run | One job doing, in order, everything a PR gate will do: check out, install containerlab, build the router image, render configs, start Batfish and ask test B's questions, deploy `feas-wg`, run test C's checks, destroy. Timed from the job's first step to its last. |
| One planted fault | In the same job, after the full run, with tools, image and Batfish already warm: render with FEAS-F, ask Batfish `routes`, deploy `feas-bgp` with the fault, run test A's checks until they report the leak, destroy. Timed from render start to destroy end. |
| **GO if** | Full run under 15 minutes, and the planted fault under 3 minutes. |
| Caveat | This full run is a proxy: the real pull-request gate has more nodes and tests. It is re-measured once built and reported as a median with its range. |
| If not | Run Gate 3 nightly as parallel matrix jobs, and shrink the topology. |

### Test E: local development on Windows

| | |
|---|---|
| Inventory (2026-11-09, before the test) | Windows 10 Pro 19045, WSL 3.0.1, WSL kernel 6.18.40.1, only distribution `docker-desktop` (stopped), 15.3 GB RAM with 1.9 GB free at the time, virtualization enabled in firmware. Docker Desktop is installed but not running. |
| Procedure | With the repository owner's approval for the download, install the WSL-Containerlab distribution 0.83.0-1.0 (it brings its own Docker engine and needs WSL 2.4.4 or newer). Deploy `feas-bgp` once and run test A's checks. Then deploy `feas-wg` once and record test C's checks as information. |
| **GO if** | The 3-router lab comes up locally: test A's checks 1, 2 and 4 pass. |
| If not | Use GitHub Codespaces (120 core-hours a month free, more with the student Pro plan). Otherwise develop in CI only. |

---

## Part 2: the network the gates protect

This is the target design. It is not built yet, and every later test refers to these names.

| Zone | Prefix | Hosts |
|---|---|---|
| LAN-A (site A users) | 172.16.10.0/24 | client-a .10, admin .20 |
| DMZ | 172.16.20.0/24 | haproxy .10, ns1 (authoritative DNS) .53 |
| APP | 172.16.30.0/24 | app1 .11, app2 .12 |
| DB | 172.16.40.0/24 | db .10 |
| SVC | 172.16.50.0/24 | resolver (recursive DNS) .53, step-ca .10 |
| LAN-B (site B users) | 172.24.10.0/24 | client-b .10 |
| Router loopbacks | 172.16.255.1/32 (rtr-a), 172.24.255.1/32 (rtr-b) | |
| Tunnel | 172.31.255.0/31 | rtr-a .0, rtr-b .1 |
| Site A public | 198.51.100.64/27, uplink 198.51.100.0/31 | public service address 198.51.100.65 |
| Site B public | 203.0.113.64/27, uplink 203.0.113.0/31 | |
| Outside | 192.0.2.0/24 | outside host .10 (web server and an authoritative DNS server for `example.net`) |

Routing: eBGP rtr-a (65001) to isp (65000) and rtr-b (65002) to isp, carrying only public
prefixes; eBGP rtr-a to rtr-b over wg0, carrying only private prefixes. Firewalls: nftables on both
site routers, with a stateful zone firewall (inet filter, default drop) and a stateless edge filter
on the uplink (netdev ingress). NAT: masquerade for LAN egress, port-forwards from
198.51.100.65 TCP 443 to haproxy and UDP/TCP 53 to ns1. DNS: the resolver gives internal answers
for `packetproof.example` to inside clients; ns1 gives public answers to the outside. TLS: step-ca
issues short-lived certificates by ACME (HTTP-01) to HAProxy, which balances app1 and app2 with
health checks.

## Part 3: hand-written invariants

These are written by hand, not generated from `network.yaml`, so that a wrong intent cannot pass
both the configs and their tests. Gate 1 checks the intent against them with Conftest; Gate 2
checks them with traffic.

| ID | Invariant |
|---|---|
| INV-01 | The DB zone accepts connections only from the APP zone, only on TCP 5432 (plus admin SSH, INV-02). |
| INV-02 | Router management (SSH on any router address, either site) is reachable only from admin 172.16.10.20. |
| INV-03 | From the outside, only 198.51.100.65 TCP 443 (to haproxy) and UDP/TCP 53 (to ns1) are reachable. Nothing else inside either site answers. |
| INV-04 | Only LAN-A and LAN-B start connections to the outside, only on TCP 80 and 443, only through NAT. DMZ, APP, DB and SVC start none, except the resolver to outside port 53. |
| INV-05 | The resolver recurses only for LAN-A, LAN-B and APP. It refuses DMZ and DB. |
| INV-06 | No prefix inside 172.16.0.0/12 is ever advertised to isp. Only each site's public prefix is. |
| INV-07 | Traffic between the two sites' private prefixes crosses the ISP only inside WireGuard, never in clear. |
| INV-08 | Packets arriving from isp with a source in 172.16.0.0/12, 10.0.0.0/8, 192.168.0.0/16, 127.0.0.0/8 or the site's own public prefix are dropped at the edge, before conntrack. |
| INV-09 | Every forward chain has a default-drop policy, accepts established and related traffic, and lets ICMP "fragmentation needed" through. |
| INV-10 | HAProxy serves only certificates issued by the lab CA, valid now, for the name the client asked for. |
| INV-11 | Inside names (`db`, `app1`, `ca` and so on under `packetproof.example`) never resolve from the outside. |
| INV-12 | Allowed flows between zones are exactly these: LAN-A and LAN-B to haproxy 443 and resolver 53; LAN-A and LAN-B to the outside 80/443; admin to every host and router on 22; haproxy to app1 and app2 on 8080; haproxy to step-ca on 9000 (ACME); step-ca to haproxy on 80 (HTTP-01 challenge); APP to db 5432 and resolver 53; resolver to the outside on 53; outside to 198.51.100.65 on 443 and 53. Everything else is dropped. |
| INV-13 | On every internal zone interface, a packet whose source address is outside that zone's prefix is dropped (reverse-path check), so one zone cannot pretend to be another. |

## Part 4: 30 planted faults

Each fault is one change, planted on a throwaway branch, as a pull request would bring it. "Where"
says what the change edits: the intent (`network.yaml`), a template, or a generated file. Fault
types follow the brief's list and common real-world network mistakes. The prediction column is
scored, not used as a rule.

| ID | Layer | Fault | Where | Predicted first gate |
|---|---|---|---|---|
| F01 | BGP | Prefix-list removed on rtr-a's export to isp: private prefixes leak to the ISP | template | Gate 1 |
| F02 | BGP | Wrong remote AS for the tunnel peer on rtr-b (65003 instead of 65001) | intent | Gate 1 |
| F03 | BGP | Typo in rtr-b's export prefix-list: 172.24.10.0/25 instead of /24, so LAN-B vanishes from site A | intent | Gate 1 |
| F04 | BGP | rtr-b advertises its own uplink /31 over the tunnel: recursive routing breaks the tunnel | intent | Gate 2 |
| F05 | Routing | Static route on rtr-b for 172.16.0.0/16 via isp: lower distance than BGP, so site-to-site traffic leaves in clear and dies (superseded by amendment A2) | intent | Gate 2 |
| F06 | BGP | Inbound route-map removed for the tunnel peer on rtr-a: session Established, zero prefixes accepted | template | Gate 1 |
| F07 | BGP | rtr-a sends a default route to rtr-b: site B's internet traffic hairpins through site A | intent | Gate 2 |
| F08 | WireGuard | AllowedIPs on rtr-a lists only the tunnel address, not LAN-B: BGP up, data dropped | intent | Gate 2 |
| F09 | WireGuard | Wrong peer public key on rtr-b: no handshake | intent | Gate 2 |
| F10 | WireGuard | Wrong endpoint port on rtr-a (51821): no handshake | intent | Gate 2 |
| F11 | MTU | ICMP "fragmentation needed" dropped by rtr-a's forward chain: small pings cross the tunnel, large TCP transfers hang (effect corrected by amendment A2) | template | Gate 2 |
| F12 | Firewall | Hole into the DB zone: TCP 5432 accepted from any zone, not just APP | intent | Gate 1 |
| F13 | Firewall | A broad accept from DMZ to 172.16.0.0/16 placed above the specific drops (shadowing) | template | Gate 2 |
| F14 | Firewall | Forward-chain default policy changed from drop to accept on rtr-a | template | Gate 1 |
| F15 | Firewall | The established/related accept rule removed: replies dropped, legitimate flows break | template | Gate 2 |
| F16 | Firewall | Anti-spoofing removed from the stateless edge filter on rtr-a | template | Gate 2 |
| F17 | Firewall | SSH to the router accepted from every zone in rtr-a's input chain | intent | Gate 1 |
| F18 | Firewall | DB interface placed in the APP zone set, so DB is treated as APP | intent | Gate 1 |
| F19 | Firewall | DMZ allowed to start connections to the outside on any port (exfiltration path) | intent | Gate 1 |
| F20 | NAT | Port-forward exposes an internal port: 198.51.100.65 TCP 5432 to db | intent | Gate 1 |
| F21 | NAT | Masquerade removed for LAN-A: users lose the internet | template | Gate 2 |
| F22 | NAT | Masquerade also applied to traffic into wg0: site B sees rtr-a's address instead of the real client | template | Gate 2 |
| F23 | NAT | Port-forward 443 sent to haproxy port 80: HTTPS from the outside fails | intent | Gate 2 |
| F24 | DNS | Stale record: inside view `www` points to 172.16.20.99, an old address | intent | Gate 2 |
| F25 | DNS | Inside name `db.packetproof.example` added to the outside view | intent | Gate 1 |
| F26 | DNS | Resolver access-control allows recursion for DMZ: DNS exfiltration path opens | intent | Gate 1 |
| F27 | DNS | Inside record for `ca.packetproof.example` removed: ACME works by IP, fails by name | intent | Gate 2 |
| F28 | TLS | HAProxy serves an expired certificate | generated file | Gate 2 |
| F29 | TLS | HAProxy's certificate lacks the `www` name (wrong SAN) | intent | Gate 2 |
| F30 | Proxy | "The frontend cannot reach the API": haproxy to APP 8080 dropped by the firewall | intent | Gate 2 |

## Part 5: 12 attack paths, each paired with a legitimate flow

All attacks start from a "compromised" DMZ host: probe containers that share haproxy's network
namespace, so packets carry haproxy's real address. All traffic stays on lab bridges, uses harmless
decoys and has no outside targets beyond the lab's own outside host. An attack path is **blocked**
only if its legitimate pair passes in the same run. A firewall that blocks everything does not pass.

| ID | Attack from the DMZ | Blocked means | Legitimate pair that must pass |
|---|---|---|---|
| AP-01 | TCP port scan of the DB zone (`nmap -Pn`, top 100 ports) | No port reported open | app1 connects to db 5432 |
| AP-02 | Direct database connection to db 5432 | No TCP handshake completes | app2 connects to db 5432 |
| AP-03 | Lateral SSH to app1 and app2 | No TCP handshake on port 22 | admin connects to app1 on 22 |
| AP-04 | Scan of the LAN-A user zone | No port reported open | client-a gets HTTPS from haproxy |
| AP-05 | SSH to rtr-a's DMZ gateway address 172.16.20.1 | No handshake | admin reaches rtr-a on 22 |
| AP-06 | SSH to rtr-a's other addresses (loopback 172.16.255.1, 172.16.40.1) | No handshake on any of them | admin reaches 172.16.255.1 on 22 |
| AP-07 | SSH to rtr-b across the tunnel (172.24.255.1, 172.31.255.1) | No handshake | admin reaches rtr-b on 22 across the tunnel |
| AP-08 | Scan of LAN-B across the tunnel | No port reported open | client-b gets HTTPS from haproxy across the tunnel |
| AP-09 | New TCP connections to the outside host (443, 4444) | No handshake | client-a reaches the outside on 443 through NAT |
| AP-10 | Data hidden in DNS names (`<hex>.exfil.example.net`) sent through the resolver | The outside DNS server's log never contains the marker | client-a resolves `www.example.net`, and the outside server logs that query |
| AP-11 | DNS straight to the outside on UDP 53, bypassing the resolver | No answer, and the marker is never logged | The resolver's own query to the outside is answered |
| AP-12 | Spoofed SYNs to db 5432 with app1's source address 172.16.30.11 | A capture on db sees zero packets from the spoofed source; rtr-a's anti-spoof counter rises | Real app1 connects to db 5432 |

## Part 6: how gates and the scorecard are judged

**Gate 1 (static)** passes when the schema is valid, every Conftest invariant holds, `vtysh -C`
accepts every router config, and, if test B is GO, Batfish reports no parse warnings, every BGP
session compatible, and the expected route-policy answers. It posts the `frr-reload.py --test`
diff on the pull request.

**Gate 2 (live copy)** passes when every pytest test passes on the deployed lab: routing tables,
the allow/deny matrix of INV-12 (each deny paired with an allowed flow), DNS answers from each view,
TLS verification (including wrong-name, expired and untrusted-CA refusals), don't-fragment pings
across the tunnel, NAT as seen from the outside host, and HAProxy health checks.

**A fault is caught** by a gate when that gate fails on the faulted change while the unfaulted
baseline passes in the same workflow run. The failing checks are recorded. If none of them relates
to the fault's layer, the catch is reported separately as **incidental**.

**A fault escapes** when both gates pass on it. Every escape is published with the reason no check
could see it. Escapes are never removed from the list or fixed quietly. A fix is a new commit, and
the fault is scored again and reported as "escaped, then caught after commit X".

**Flaky results.** If the baseline fails, the fault's run is void and re-run, and the void run is
logged. A fault that gives different verdicts across 3 runs is reported as flaky, not as caught.

**Attack paths** are scored per Part 5: blocked, open, or invalid (the legitimate pair failed).

**Timing claims** are medians with minimum and maximum and the number of runs. Shared runners are
noisy, so no timing difference smaller than the observed range is claimed.

**The scorecard** (JSON, published to GitHub Pages) lists every fault with its verdict per gate,
the failing checks, the prediction and whether it was right, and links to the runs. It lists every
attack path with its verdict and its legitimate pair. It states what each gate cannot see.

## Amendments

### A1 (2026-11-09, after CI run 42703883921): containerlab's management network moves out of 172.16.0.0/12

**What happened.** In the first CI run, test A's check (3) ("isp has exactly 172.16.10.0/24 and
172.24.10.0/24 from inside 172.16.0.0/12, nothing else") failed in all 5 runs, while every other
check of test A passed. The extra routes were 172.20.20.0/24 and isp's own /32 on it: containerlab's
management network, connected to every node on eth0. That network is containerlab's out-of-band
access, not part of the lab, and the shared setup above already treated it as outside the address
plan. But it lies inside 172.16.0.0/12, and neither this file nor the check excluded it.

**Change.** The rendered topologies put containerlab's management network on 192.168.254.0/24,
outside 172.16.0.0/12. Check (3) and every other rule stay word for word as written. The first run
stays on record as NO-GO for test A under the original setup.

**Why this and not a narrower check.** Counting only BGP-learned routes would also have passed, but
it would have weakened the check: it would stop seeing a private prefix that reaches isp by any
other means. Moving the management network keeps the check strict.

### A2 (2026-11-10, after an independent review of v1.0.0): what Gate 3 may count, and fault F05

**What happened.** A review of the v1.0.0 code, split into four independent areas, found three
things that touch this method:

1. Gate 3 counted every failure in a fault's own job as a catch, including failures that are not
   the network's: Batfish not answering, a setup step failing, a fault that could not be planted,
   a lab that did not deploy. The baseline runs on another runner, so "the baseline passed in the
   same run" does not exclude them. No published result depended on this: no fault in any run was
   graded on such a failure, and re-grading run 42877631728 under the rules below gives the same
   verdict for every fault and every attack path.
2. F05 could never bite. A static 172.16.0.0/16 on rtr-b loses to the /24s that rtr-b learns over
   the tunnel, because the longest prefix wins before administrative distance is compared. Its
   description ("site-to-site traffic leaves in clear") was false. Gate 1 caught it (INV-07) in
   every run; Gate 2 passed it.
3. F11's description says small pings cross the tunnel while large transfers hang. The tunnel's own
   "fragmentation needed" messages are sent by the routers themselves, through the output hook, so
   F11's forward-chain drop can only affect the 1400-byte path to the outside, which is the path
   Gate 2 tests.

**Changes.**

- A gate result is one of: passed, failed, or **could not judge**. "Could not judge" covers a tool
  that did not run (an exception, a failed self-test, a failing policy unit test), a fault that
  could not be planted, missing results, a lab that did not deploy, and a Gate 2 run in which every
  test errored. A fault whose Gate 1 could not judge, or whose Gate 1 passed while Gate 2 could not
  judge, is **void and re-run**, exactly like a run whose baseline failed. A real Gate 1 failure
  next to a tool error is still a catch. A change the generator rejects (schema or reference
  validation) is still a Gate 1 catch.
- The headline counts related catches. Incidental catches are reported next to it, as Part 6
  already requires; no run so far has had one.
- An attack path whose probe could not run is reported as "not run", not "open", and the scorecard
  refuses to publish unless all 12 attack paths were scored.
- F05 becomes: static route on rtr-b for the DMZ, 172.16.20.0/24, via isp. It has the same length
  as the route learned over the tunnel and a lower distance, so site B's traffic to the DMZ leaves
  in clear and dies at the ISP. Its row in Part 4 stays as written and is marked as superseded. It
  is scored again from the next run on, and its earlier verdicts stay on record.
- F11's expected effect is corrected as in point 3. The fault itself is unchanged.

**What did not change.** Every other fault, invariant, attack path and pass rule stays word for
word as written. Every run before this amendment stays on record as published.

## Editorial changes

Wording-only edits. None changes a rule, threshold, check, fault, attack path or result.

### E1 (2026-11-10): names that only made sense inside the project's schedule

Part 1's tests were first called the "week-1 go/no-go tests", after the brief's week-by-week plan.
They are now the feasibility tests; their topologies `w1-bgp` and `w1-wg` are `feas-bgp` and
`feas-wg`; the planted error W1-F is FEAS-F; the scripts moved from `week1/` to `feasibility/`; and
"the research report" is called the project's brief. Test E's title names the platform it tested
instead of "the laptop". The original wording is at
[2f178eb](https://github.com/aymen-nasri/packetproof/blob/2f178eb/docs/method.md).
