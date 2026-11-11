# Feasibility checks: can free CI runners carry this project?

Before any of PacketProof was built, five assumptions it depends on were tested, each with a
**GO** or **NO-GO** verdict: that containerlab, Batfish and WireGuard work on a free GitHub runner,
that a full run fits a CI time budget, and that the lab can run on the Windows workstation used for
development. Recorded on 2026-11-09. The rules that judge these results are in
[method.md](method.md), part 1, committed in
[2f178eb](https://github.com/aymen-nasri/packetproof/commit/2f178eb) before any test code existed.
One amendment (A1) was made after the first run. It is explained there and below.

The scripts are in [`feasibility/`](../feasibility) and the workflow is
[`feasibility.yml`](../.github/workflows/feasibility.yml). It runs on demand and on any pull request
that changes them.

## Verdicts

| Test | Assumption | Verdict | Evidence |
|---|---|---|---|
| A | containerlab runs on a free runner | **GO** (after amendment A1) | 5 of 5 runs passed every check; deploy plus checks 21.8 to 22.9 s (limit 300 s). [Run 4](https://github.com/aymen-nasri/packetproof/actions/runs/42707352812) |
| B | Batfish reads the generated FRR configs | **GO** | All 5 criteria met in every run; the planted error changed Batfish's answer. [Run 4](https://github.com/aymen-nasri/packetproof/actions/runs/42707352812) |
| C | WireGuard works inside containers | **GO** | Handshake and BGP over wg0 up in 5 of 5 runs, and the stricter tunnel-only evidence passed in 5 of 5. [Run 4](https://github.com/aymen-nasri/packetproof/actions/runs/42707352812) |
| D | The CI time budget holds | **GO** | Full run 86.8 s (limit 900 s); one planted fault 22.9 s (limit 180 s), caught by the live check and by Batfish. [Run 4](https://github.com/aymen-nasri/packetproof/actions/runs/42707352812) |
| E | The lab runs on the Windows development workstation | **NO-GO (not attempted)** | The 1.17 GB WSL-Containerlab download was declined; the fallback applies: **development in CI only**. |
| KVM | | Not tested, by design | Kept out of the critical path. |

**What this decided:** Gate 1 keeps Batfish, alongside `vtysh` and Conftest. The lab and tunnel
design stand as planned, and every lab change is developed and checked in CI. Batfish cannot
see whether the WireGuard tunnel is up (see B2 below), so the tunnel is proved only by Gate 2.

## Environment

| | |
|---|---|
| Runner | GitHub-hosted `ubuntu-latest`, resolved to image `ubuntu26 20261101.186.1`, kernel `7.0.0-1019-azure`, 4 vCPU, 15 GB visible |
| Docker | 29.4.2 |
| containerlab | 0.83.0 (release `.deb`, SHA-256 checked) |
| FRR | 10.7.1 (`quay.io/frrouting/frr` pinned by digest) plus nftables, wireguard-tools, tcpdump |
| Batfish | `batfish/allinone` build 2026.08.27.3685 (pinned by digest), pybatfish 2026.9.17.3748 |

## Every run, in order

| Run | Commit | A | B | C | D | What changed before it |
|---|---|---|---|---|---|---|
| [42703883921](https://github.com/aymen-nasri/packetproof/actions/runs/42703883921) | [674898a](https://github.com/aymen-nasri/packetproof/commit/674898a) | NO-GO, 0/5 | GO | NO-GO, 0/5 | GO | First run of the harness |
| [42705724161](https://github.com/aymen-nasri/packetproof/actions/runs/42705724161) | [9ad0a54](https://github.com/aymen-nasri/packetproof/commit/9ad0a54) | GO, 5/5 | GO | NO-GO, 0/5 | GO | Amendment A1; deploy logs kept as evidence; verdict step fixed |
| [42706568780](https://github.com/aymen-nasri/packetproof/actions/runs/42706568780) | [07f03b1](https://github.com/aymen-nasri/packetproof/commit/07f03b1) | GO, 5/5 | GO | NO-GO, 0/5 | GO | The WireGuard setup script logs its own errors |
| [42707352812](https://github.com/aymen-nasri/packetproof/actions/runs/42707352812) | [b8eec88](https://github.com/aymen-nasri/packetproof/commit/b8eec88) | GO, 5/5 | GO | GO, 5/5 | GO | Key file ownership fixed; the vtysh dry-run call fixed |

Each run's per-check JSON, the routing tables and configs of every router, the deploy logs and
the Batfish snapshots are kept as artifacts of that run for 90 days.

## Test A: containerlab on a free runner

**Run 1 failed check (3) in all 5 runs, and passed every other check.** isp's routing table held
172.20.20.0/24 and its own address on it: containerlab's management network, connected to every
node on eth0, which lies inside 172.16.0.0/12. The method had placed that network outside the
address plan, but neither the method nor the check excluded it. Amendment A1 moved the management
network to 192.168.254.0/24 and left check (3) word for word. Under the original setup, test A was
NO-GO; that run stays on record.

From run 2 on, all 5 runs passed every check, every time:

| Run 4, per job | 1 | 2 | 3 | 4 | 5 |
|---|---|---|---|---|---|
| Deploy (s) | 2.1 | 1.9 | 2.2 | 3.0 | 2.0 |
| Convergence (s) | 11.4 | 11.6 | 11.5 | 11.5 | 11.6 |
| Deploy plus checks (s) | 21.8 | 21.9 | 22.0 | 22.9 | 22.0 |

Pings: 5 of 5 replies both ways in every run.

## Test B: Batfish reads the generated FRR configs

GO in all four runs, with identical answers:

1. All three files parsed as `CUMULUS_CONCATENATED` with status PASSED.
2. Zero parse warnings.
3. Zero init issues of any kind.
4. All four BGP session ends were `UNIQUE_MATCH` and `ESTABLISHED`.
5. With the planted error FEAS-F, isp's routes gained 172.16.255.1/32 (rtr-a's loopback). The
   baseline did not have it.

**Rendering choices made before any run, from reading Batfish's FRR grammar:** blocks end with `!`
instead of `exit`, and there is no `log stdout` line, because Batfish's FRR grammar has neither.
FRR accepts both forms. This matters later: FRR 8.2 and newer write `exit` in `show
running-config`, so a running router's config cannot be fed to Batfish as is. Configs must come
from the generator.

**B2 (recorded, not judged): Batfish cannot tell whether the tunnel is up.** For the `feas-wg`
snapshot, Batfish parsed `wg0` with no warning or init issue, and reported the rtr-a to rtr-b
session over it as `ESTABLISHED`. In runs 1 to 3 the real tunnel was down and that session sat in
`Active`, yet Batfish's answer was the same. Batfish treats two /31 addresses on interfaces named
`wg0` as directly connected. It knows nothing about keys, endpoints or AllowedIPs. That is the first
row of the "what each gate cannot see" table: **WireGuard faults (F08, F09, F10) are invisible to
Batfish and must be caught by the live copy.**

**FRR's own syntax check (`vtysh --dryrun`, informational).** In runs 1 to 3 this step was called
wrongly. With `--dryrun`, vtysh checks `frr.conf` in its config directory and ignored `-f`, so it
checked the image's default file and still exited 0. It proved nothing. Run 4 mounts each rendered
directory as the config directory, and all six configs exit 0 with no message. Because the wrong
call also exited 0, Gate 1 now proves this check fails on a broken config before trusting it.

## Test C: WireGuard inside containers

**Runs 1 to 3 failed in all 5 jobs because of a harness bug, not a WireGuard limit.** The setup
script's log (added in run 3) showed `wg set ... private-key` failing with `fopen: Permission
denied`. The key file was mode 0600 and owned by the runner user (uid 1001), and root inside the
container could not read it. From run 4 the key stays 0600 but is owned by uid 0.

Run 4, all 5 jobs:

| Check | Result |
|---|---|
| Handshake on both ends | 5 of 5 |
| BGP over wg0 Established on both ends | 5 of 5 |
| client-a and client-b ping each other | 5 of 5 replies both ways, in every job |
| isp has no route to either LAN | 5 of 5 |
| Capture on isp during a ping | 19 to 23 WireGuard UDP packets, 0 clear ICMP between the LANs |
| Convergence (s) | 11.4, 11.5, 23.6, 11.4, 38.9 |
| Deploy plus checks (s) | 37.7, 38.4, 50.1, 38.1, 65.9 |

Convergence over the tunnel varied more than without it (11 to 39 s against 11 to 12 s). The cause
was not measured; BGP's connect-retry timer waiting for the first handshake is the likely candidate.
The project's generator later set BGP's timers explicitly.

The tunnel was tested on the runner only. The local half of this test did not run (test E), so
per the method the tunnel is developed in CI only.

Private keys were never written to the repository or the logs. Public keys do appear in the
evidence files (`wg show` and the setup script's trace), which is harmless but broader than the
method's wording ("keys ... never written to ... the logs").

## Test D: the CI time budget

| Run | Full run (s) | One planted fault (s) | Fault caught by the live check | Fault caught by Batfish |
|---|---|---|---|---|
| 1 | 203.1 | 22.0 | yes | yes |
| 2 | 201.8 | 23.7 | yes | yes |
| 3 | 204.1 | 23.4 | yes | yes |
| 4 | **86.8** | **22.9** | yes | yes |

Runs 1 to 3 are GO by the numbers, but their full run includes the failing tunnel stage, which spent
120 s waiting for a convergence that never came. Run 4 is the first full run in which every stage
passed, so it is the one quoted. These are single measurements on a shared runner, from the job's
first step to its last, not counting runner start-up. This full run is a proxy: the real
pull-request gate has more nodes and tests, and its own times are measured from its runs (see the
[README](../README.md)).

## Test E: local development on Windows

Inventory before the test (2026-11-09): Windows 10 Pro 19045, WSL 3.0.1, WSL kernel 6.18.40.1,
only distribution `docker-desktop` (stopped), 15.3 GB RAM with 1.9 GB free, virtualization enabled
in firmware. The method's procedure needed the 1.17 GB WSL-Containerlab download (release 0.83.0-1.0,
SHA-256 published by GitHub). It was declined, so the lab was never brought up locally.

Recorded as **NO-GO (not attempted)**. The fallback applies: **all lab work runs in CI**, and the
same scripts (`feasibility/lab.py`) run unchanged on any Linux host with Docker and containerlab.
GitHub Codespaces remains an option.
