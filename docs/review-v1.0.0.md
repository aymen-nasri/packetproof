# What a review of v1.0.0 found

After v1.0.0 was released, its code was reviewed in four independent parts: the generator and the
faults, the live tests and probes, the gates and the prod path, and the workflows. Each reviewer
had to back every finding with a concrete scenario, and every finding was then checked again
before anything was changed. About fifty findings held up. Most were hardening. The ones below
matter, because they change what v1.0.0 could honestly claim. Each is fixed, and each fix is
proved by a run. v1.1.0 is the first release with all of them.

## The findings that change what v1.0.0 claimed

| Finding | What it meant for v1.0.0 | Proof it was real | Fix |
|---|---|---|---|
| **Every container also sat on containerlab's management network** (192.168.254.0/24), one shared segment that never crossed a router | The zone firewall could be walked around: a "compromised" DMZ host reached the database at its management address, port 5432 **open**. The 12 attack paths never tried, because they target only the address plan | draft PR #17, run [42896114239](https://github.com/aymen-nasri/packetproof/actions/runs/42896114239): every host had a 192.168.254.x address; `DMZ -> db 192.168.254.16:5432: open` | PR #18: no node joins the management network (`network-mode: none`); Gate 2 checks every host has only its planned address |
| **The ISP filter's private-space denies had no `le 32`** | They matched only the exact /8, /12 and /16. A more specific private route from the ISP would have been accepted, and would have won over a local /24 | same run: both site routers had accepted 192.168.254.0/24 from the ISP despite `deny 192.168.0.0/16` | PR #18: denied at every length; Gate 2 checks no private route is accepted from the ISP |
| **The three nmap-based attack paths (AP-01, AP-04, AP-08) never finished a host** | Every host hit nmap's 60 s host timeout and was skipped with no port table, so "no open port" was vacuous. **v1.0.0's "12 of 12 attack paths blocked" was 9 proved and 3 that proved nothing** | PR #19's first run: `Skipping host … due to host timeout` for every address of all three scans | PR #19: scans keep a minimum rate and finish; an unfinished scan now fails the test |
| **prod's drift check could not see nftables drift on rtr-a** | Its self-test cleanup reloaded the bundle's ruleset on rtr-a *before* the real comparison. FRR drift on every router and nftables drift on rtr-b were checked for real; "no nftables drift on rtr-a" was not | code (`scripts/prod.py`, v1.0.0) | PR #21: compare first, then plant and remove exactly the self-test's two lines |

## Findings that changed no published number

| Finding | Why no number moved | Fix |
|---|---|---|
| Gate 3 counted a broken tool or runner in a fault's own job as a catch | No fault in any run was graded on such a failure; re-grading run 42877631728 with the fixed code gives the same verdict for every fault | PR #20 and [method amendment A2](method.md#a2-2026-11-10-after-an-independent-review-of-v100-what-gate-3-may-count-and-fault-f05): "could not judge" is void and re-run |
| Gate 1's firewall policy found chains by name, so a template that dropped `hook forward … policy drop` would have passed; INV-11 checked values but not names | No fault exercised either hole | PR #20: chains found by hook and device; 11 policy unit tests, 5 of which fail against v1.0.0's policies (4 on the firewall, 1 on INV-11) |
| Fault F05 (a static /16) could never bite: the tunnel's /24s win on prefix length | Gate 1 caught it every time (INV-07), so its verdict was right for the wrong reason | Amendment A2: F05 is now a /24, which does bite |
| AP-09's legitimate pair was HTTP on 80, not the method's "443 through NAT"; packet captures could not prove they ran; AP-11 had no positive control; DMZ probes counted "refused" as blocked | Every attack path still holds under the stricter tests | PR #19 |
| A green prod run did not require a hitless change, and ran with throwaway keys if the age key was missing | Every published prod run had 0 failed requests and 0 broken connections, and ran the managed keys | PR #21 |
| The weekly image job rebuilt and republished `:main` with whatever packages were current, untested; merges cancelled main's own gate runs; a release recorded whatever `:main` was at release time | v1.0.0's images were the ones prod had verified (digests match prod run 42883900778) | PR #22 |
| Names in `network.yaml` reached shell scripts unescaped; the DNS monitor accepted any answer | `network.yaml` holds no such names | PR #23 |
| v1.0.0's README called prod run 42883900778 "its latest change", but its two bundles have identical router configs: it measured a re-apply, not a change | The numbers stand; the word was wrong. The changes between different router configs were runs 42836367491 and 42838516660 | v1.1.0's README and [prod.md](prod.md) say which runs re-applied the same configs |

## What did not change

The method's rules, invariants, attack paths and faults (apart from F05, by amendment A2), and
every published run, stay on record as they were. The corrections are made here, in
[limits.md](limits.md), in the threat model, and in the v1.1.0 release notes, not by rewriting the
past.
