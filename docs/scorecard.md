# Gate 3 scorecard

Gate 3 puts each of the 30 planted faults ([faults.yaml](../faults/faults.yaml)) through Gate 1 and
Gate 2 on its own runner, next to an unfaulted baseline in the same run, and grades the result
by the rules in [method.md](method.md), part 6. The newest run is published at
**https://aymen-nasri.github.io/packetproof/**. Every run below is linked.

## Every run

| Run | Commit | Baseline passed | Caught first by Gate 1 | Caught only by Gate 2 | Escaped | Incidental | Attack paths blocked | Fault job time, median (min to max) |
|---|---|---|---|---|---|---|---|---|
| [42717245768](https://github.com/aymen-nasri/packetproof/actions/runs/42717245768) | [8fd0717](https://github.com/aymen-nasri/packetproof/commit/8fd0717) | yes | 19 | 7 | 4 | 0 | 12 of 12 | 413 s (280 to 1013) |
| [42720416920](https://github.com/aymen-nasri/packetproof/actions/runs/42720416920) | [8fd0717](https://github.com/aymen-nasri/packetproof/commit/8fd0717) | yes | 19 | 7 | 4 | 0 | 12 of 12 | 413 s (274 to 1033) |
| [42720428776](https://github.com/aymen-nasri/packetproof/actions/runs/42720428776) | [8fd0717](https://github.com/aymen-nasri/packetproof/commit/8fd0717) | yes | 19 | 7 | 4 | 0 | 12 of 12 | 412 s (270 to 1011) |
| [42785569385](https://github.com/aymen-nasri/packetproof/actions/runs/42785569385) | [8fd0717](https://github.com/aymen-nasri/packetproof/commit/8fd0717) | yes | 19 | 7 | 4 | 0 | 12 of 12 | 408 s (270 to 1002) |
| [42836207602](https://github.com/aymen-nasri/packetproof/actions/runs/42836207602) | [7e3c7bc](https://github.com/aymen-nasri/packetproof/commit/7e3c7bc) | yes | 19 | 8 | 3 | 0 | 12 of 12 | 410 s (263 to 1028) |
| [42840091894](https://github.com/aymen-nasri/packetproof/actions/runs/42840091894) | [7e3c7bc](https://github.com/aymen-nasri/packetproof/commit/7e3c7bc) | yes | 19 | 8 | 3 | 0 | 12 of 12 | 413 s (279 to 1068) |
| [42840106930](https://github.com/aymen-nasri/packetproof/actions/runs/42840106930) | [7e3c7bc](https://github.com/aymen-nasri/packetproof/commit/7e3c7bc) | yes | 19 | 8 | 3 | 0 | 12 of 12 | 416 s (279 to 1046) |
| [42853952123](https://github.com/aymen-nasri/packetproof/actions/runs/42853952123) | [42970a2](https://github.com/aymen-nasri/packetproof/commit/42970a2) | yes | 19 | 8 | 3 | 0 | 12 of 12 | 416 s (276 to 1038) |
| [42856195978](https://github.com/aymen-nasri/packetproof/actions/runs/42856195978) | [42970a2](https://github.com/aymen-nasri/packetproof/commit/42970a2) | yes | 19 | 8 | 3 | 0 | 12 of 12 | 416 s (271 to 1038) |
| [42857438347](https://github.com/aymen-nasri/packetproof/actions/runs/42857438347) | [42970a2](https://github.com/aymen-nasri/packetproof/commit/42970a2) | yes | 19 | 8 | 3 | 0 | 12 of 12 | 410 s (278 to 1052) |
| [42873879465](https://github.com/aymen-nasri/packetproof/actions/runs/42873879465) | [00ba68c](https://github.com/aymen-nasri/packetproof/commit/00ba68c) | yes | 19 | 8 | 3 | 0 | 12 of 12 | 446 s (295 to 1076) |
| [42877631728](https://github.com/aymen-nasri/packetproof/actions/runs/42877631728) | [86b8f81](https://github.com/aymen-nasri/packetproof/commit/86b8f81) | yes | 19 | 8 | 3 | 0 | 12 of 12 | 446 s (314 to 1080) |
| [42902266017](https://github.com/aymen-nasri/packetproof/actions/runs/42902266017) | [3fb6f3f](https://github.com/aymen-nasri/packetproof/commit/3fb6f3f) | yes | 19 | 8 | 3 | 0 | 12 of 12 | 285 s (248 to 1860) |
| [42902610699](https://github.com/aymen-nasri/packetproof/actions/runs/42902610699) | [3fb6f3f](https://github.com/aymen-nasri/packetproof/commit/3fb6f3f) | yes | 19 | 8 | 3 | 0 | 12 of 12 | 276 s (241 to 1858) |
| [42907526683](https://github.com/aymen-nasri/packetproof/actions/runs/42907526683) | [3fb6f3f](https://github.com/aymen-nasri/packetproof/commit/3fb6f3f) | yes | 19 | 8 | 3 | 0 | 12 of 12 | 276 s (238 to 1840) |

**The commits.**
- [8fd0717](https://github.com/aymen-nasri/packetproof/commit/8fd0717), the first design: 4 runs, identical verdicts for every fault and both gates: yes.
- [7e3c7bc](https://github.com/aymen-nasri/packetproof/commit/7e3c7bc), after the two fixes Gate 3 pointed at: RFC 8212's safety net set explicitly, and a path-MTU test that needs path-MTU discovery: 3 runs, identical verdicts for every fault and both gates: yes.
- [42970a2](https://github.com/aymen-nasri/packetproof/commit/42970a2), after moving FRR from the datacenter to the traditional profile, to avoid FRR bug #22939 that prod's drift check found: 3 runs, identical verdicts for every fault and both gates: yes.
- [00ba68c](https://github.com/aymen-nasri/packetproof/commit/00ba68c), with two more Gate 2 tests: a TCP traceroute from site B across the tunnel, and the DB host's listening sockets: 1 run.
- [86b8f81](https://github.com/aymen-nasri/packetproof/commit/86b8f81), with the outside test server limited to TLS 1.2 and newer: the lab code that v1.0.0 releases: 1 run.
- [3fb6f3f](https://github.com/aymen-nasri/packetproof/commit/3fb6f3f), v1.1.0, after the review of v1.0.0: no management network, the ISP filter at every length, stricter tests whose probes must prove they ran, F05 amended (A2), and grading that voids a fault a gate could not judge: 3 runs, identical verdicts for every fault and both gates: yes.

No fault is flaky under the method's rule. Between consecutive commits, the verdicts that moved:
- 8fd0717 to 7e3c7bc: F06 (escaped to caught by gate 2); F11 (still caught by gate 1; Gate 2 now catches it).
- 7e3c7bc to 42970a2: none.
- 42970a2 to 00ba68c: none.
- 00ba68c to 86b8f81: none.
- 86b8f81 to 3fb6f3f: F05 (still caught by gate 1; Gate 2 now catches it; amendment A2 changed the fault itself).

## Every fault, on the current design (3fb6f3f)

| ID | Layer | Fault | Gate 1 | Gate 2 | Verdict | On the first design | Predicted first gate |
|---|---|---|---|---|---|---|---|
| F01 | BGP | Prefix-list removed on rtr-a's export to isp, so private prefixes leak to the ISP | caught | caught | **caught by gate 1** | same | Gate 1 |
| F02 | BGP | Wrong remote AS for the tunnel peer on rtr-b (65003 instead of 65001) | caught | caught | **caught by gate 1** | same | Gate 1 |
| F03 | BGP | Typo in rtr-b's export prefix-list (172.24.10.0/25 instead of /24), so LAN-B vanishes from site A | caught | caught | **caught by gate 1** | same | Gate 1 |
| F04 | BGP | rtr-b advertises its own uplink /31 over the tunnel (recursive routing) | passed | passed | **escaped** | same | Gate 2 |
| F05 | Routing | Static route on rtr-b for the DMZ 172.16.20.0/24 via isp, same length as BGP's and a lower distance, so site B's traffic to the DMZ leaves in clear | caught | caught | **caught by gate 1** | same verdict; Gate 2 missed it then (the fault as first written; amended by A2) | Gate 2 |
| F06 | BGP | Inbound route-map removed for the tunnel peer on rtr-a (session up, zero prefixes accepted) | passed | caught | **caught by gate 2** | escaped | Gate 1 |
| F07 | BGP | rtr-a sends a default route to rtr-b, so site B's internet traffic would hairpin through site A | passed | passed | **escaped** | same | Gate 2 |
| F08 | WireGuard | AllowedIPs on rtr-a lists only the tunnel address, not site B (BGP up, data dropped) | passed | caught | **caught by gate 2** | same | Gate 2 |
| F09 | WireGuard | Wrong peer public key on rtr-b (no handshake) | passed | caught | **caught by gate 2** | same | Gate 2 |
| F10 | WireGuard | Wrong endpoint port on rtr-a (51821, no handshake) | passed | passed | **escaped** | same | Gate 2 |
| F11 | MTU | ICMP "fragmentation needed" dropped by rtr-a's forward chain (small pings pass, large transfers hang) | caught | caught | **caught by gate 1** | same verdict; Gate 2 missed it then | Gate 2 |
| F12 | Firewall | Hole into the DB zone, TCP 5432 accepted from any zone rather than only APP | caught | caught | **caught by gate 1** | same | Gate 1 |
| F13 | Firewall | A broad accept from the DMZ to 172.16.0.0/16 placed above the specific rules (shadowing) | caught | caught | **caught by gate 1** | same | Gate 2 |
| F14 | Firewall | Forward-chain default policy changed from drop to accept on rtr-a | caught | caught | **caught by gate 1** | same | Gate 1 |
| F15 | Firewall | The established/related accept removed from rtr-a's forward chain (replies dropped) | caught | caught | **caught by gate 1** | same | Gate 2 |
| F16 | Firewall | Anti-spoofing removed from the stateless edge filter on rtr-a | caught | caught | **caught by gate 1** | same | Gate 2 |
| F17 | Firewall | SSH to rtr-a accepted from every zone | caught | caught | **caught by gate 1** | same | Gate 1 |
| F18 | Firewall | DB interface placed in the APP zone, so DB is treated as APP | caught | caught | **caught by gate 1** | same | Gate 1 |
| F19 | Firewall | DMZ allowed to start connections to the outside on any port (exfiltration path) | caught | caught | **caught by gate 1** | same | Gate 1 |
| F20 | NAT | Port-forward exposes an internal port (198.51.100.65 TCP 5432 to db) | caught | caught | **caught by gate 1** | same | Gate 1 |
| F21 | NAT | Source NAT removed on rtr-a, so LAN-A users lose the internet | passed | caught | **caught by gate 2** | same | Gate 2 |
| F22 | NAT | NAT also applied to traffic into wg0, so site B sees rtr-a's address instead of the real client | passed | caught | **caught by gate 2** | same | Gate 2 |
| F23 | NAT | Port-forward 443 sent to haproxy port 80, so HTTPS from the outside fails | caught | caught | **caught by gate 1** | same | Gate 2 |
| F24 | DNS | Stale record, the inside view's www points to 172.16.20.99 (an old address) | passed | caught | **caught by gate 2** | same | Gate 2 |
| F25 | DNS | Inside name db.packetproof.example added to the outside view | caught | caught | **caught by gate 1** | same | Gate 1 |
| F26 | DNS | Resolver access control allows recursion for the DMZ (DNS exfiltration path) | caught | passed | **caught by gate 1** | same | Gate 1 |
| F27 | DNS | Inside record for ca.packetproof.example removed (ACME works by IP, fails by name) | passed | caught | **caught by gate 2** | same | Gate 2 |
| F28 | TLS | HAProxy serves an expired certificate | passed | caught | **caught by gate 2** | same | Gate 2 |
| F29 | TLS | HAProxy's certificate lacks the www name (wrong SAN) | caught | caught | **caught by gate 1** | same | Gate 2 |
| F30 | Proxy | The frontend cannot reach the API, haproxy to APP 8080 dropped by the firewall | caught | caught | **caught by gate 1** | same | Gate 2 |

**Predictions.** The method predicted the first gate for each fault before any gate existed. 18 of 30 were right. Wrong: F04, F05, F06, F07, F10, F11, F13, F15, F16, F23, F29, F30. Of these, 8 were predicted for Gate 2 but a Gate 1 check caught them first, 3 are the escapes, and 1 was predicted for Gate 1 and is caught only by Gate 2. The static gate did better than its author expected.

F06 is reported, as the method requires, as **escaped, then caught by Gate 2 after [b0e2b20](https://github.com/aymen-nasri/packetproof/commit/b0e2b20)**.

## Attack paths

All 12 attack paths from a compromised DMZ host were scored blocked in every run, each with its
legitimate flow passing in the same test ([tests/live/test_attacks.py](../tests/live/test_attacks.py)).
**Up to 86b8f81 (v1.0.0), three of them proved nothing:** the nmap scans behind AP-01, AP-04 and
AP-08 used one command from the first design on. Re-run with a check that the scan finished (PR #19),
that command timed out on every host and reported no ports at all ([review-v1.0.0.md](review-v1.0.0.md)).
From 3fb6f3f (v1.1.0) on, the scans finish, every probe must prove it ran, and a DMZ probe counts as
blocked only when it is dropped ("filtered"), so all 12 are proved.

