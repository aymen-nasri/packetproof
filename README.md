# PacketProof

**Prove every network change before it merges.**

PacketProof is a small two-site company network written as code, and a pipeline that refuses to
merge a change until a disposable copy of the whole network has proved it. Then it grades its own
gates against 30 deliberately broken changes and 12 attack paths, and publishes what they missed.

> **Scorecard (Gate 3 on v1.1.0's code, three runs with identical verdicts: [42902266017](https://github.com/aymen-nasri/packetproof/actions/runs/42902266017),
> [42902610699](https://github.com/aymen-nasri/packetproof/actions/runs/42902610699), [42907526683](https://github.com/aymen-nasri/packetproof/actions/runs/42907526683)):** of 30 planted faults, the static gate caught 19,
> the live copy caught 8 more, and 3 escaped both. All three escapes are latent: another control or
> the protocol masked them, and no traffic changed ([why, one by one](docs/limits.md#the-three-escapes-that-remain-and-why-each-changed-no-traffic)).
> All 12 attack paths from a compromised DMZ host were blocked while their legitimate flows passed,
> and every probe proved it ran. (In v1.0.0, three of the 12 [proved nothing](docs/review-v1.0.0.md).)
> The first design had 4 escapes in 4 identical runs (for example [42717245768](https://github.com/aymen-nasri/packetproof/actions/runs/42717245768)); one
> of them exposed a disabled FRR safety net, which was fixed, and the fault was then caught. Every
> one of the 15 runs is listed in [scorecard.md](docs/scorecard.md).
>
> **Prod:** a firewall-only change applied in place in about one second with no failed requests and
> no broken TCP connections (runs [42836367491](https://github.com/aymen-nasri/packetproof/actions/runs/42836367491) and [42838516660](https://github.com/aymen-nasri/packetproof/actions/runs/42838516660)),
> after both images and both config bundles were verified and a tampered bundle was refused. The drift check then caught the apply tool itself, `frr-reload.py`,
> changing two BGP settings nobody asked for: an FRR bug (FRRouting/frr#22939) that the datacenter
> profile triggers. After moving to the traditional profile, an in-place apply leaves no drift
> ([42854055534](https://github.com/aymen-nasri/packetproof/actions/runs/42854055534)). Prod now runs long-lived WireGuard keys and a CA root decrypted
> from SOPS, and checks that it does. The prod runs since then re-applied unchanged router configs,
> which proves an apply is hitless and leaves no drift, not that a change is: on v1.1.0's code,
> every router's ruleset was replaced in one transaction and the apply took 0.95 s, with 0 of 449
> requests failed, 0 connections broken and 0 of 200 pings across the tunnel lost; the drift check
> found none, then proved it can see drift by planting and removing a change of its own ([42902885547](https://github.com/aymen-nasri/packetproof/actions/runs/42902885547); all prod runs in
> [prod.md](docs/prod.md)).
>
> Live scorecard: **https://aymen-nasri.github.io/packetproof/**

## How a change is proved

```
                 network.yaml  (the single source of truth)
                          |  pull request
   +----------------------+----------------------+--------------------------------+
   | Gate 1: static        | Gate 2: live copy     | Gate 3: graded suite (nightly) |
   | about 1 minute        | about 4 minutes       | about 32 minutes, 20 runners   |
   | schema, Conftest on   | the whole network in  | each of 30 planted faults      |
   | intent and on loaded  | containerlab on the   | through Gates 1 and 2, next to |
   | nftables, vtysh,      | runner; 137 tests of  | an unfaulted baseline; 12      |
   | Batfish; the plan     | routing, firewall,    | attack paths; scorecard to     |
   | (frr-reload --test)   | NAT, DNS, TLS, MTU,   | GitHub Pages                   |
   | posted on the PR      | proxy, monitoring     |                                |
   +-----------------------+-----------------------+--------------------------------+
                          |  merge to main
   config bundle -> GitHub attestation + cosign signature; images signed with cosign
                          |
   "prod": verify images and bundles (a tampered bundle is refused) -> rebuild from the
           previous bundle -> apply the new one in place while probes count failures
           -> drift check -> Gate 2 again
```

Times are from successful runs on free runners. Over the 5 pull-request gate runs with v1.1.0's
tests ([42899324990](https://github.com/aymen-nasri/packetproof/actions/runs/42899324990) to [42902138355](https://github.com/aymen-nasri/packetproof/actions/runs/42902138355)), the medians are Gate 1 1.0 min, Gate 2
4.0 min, and the whole gate 4.1 min (3.9 to 4.4). Gate 2 took 6.5 min in v1.0.0, mostly because
three nmap scans waited out their host timeouts. Gate 3 took 31.7 min in the first of the three runs
above. It ends with its slowest fault: F15 drops all return traffic, so every probe in its job
waits out its timeout, and the job takes 31 minutes. The other two runs, started while the first
ran, waited for free runners and took 61 and 62 min. The runs are listed under the [pr-gate](https://github.com/aymen-nasri/packetproof/actions/workflows/pr-gate.yml) and
[gate3](https://github.com/aymen-nasri/packetproof/actions/workflows/gate3.yml) workflows.

## The network

```
[client-b]--LAN-B--[rtr-B]==WireGuard + eBGP via [isp]==[rtr-A]--+-- DMZ:  [haproxy] [ns1]
                                   |                              +-- APP:  [app1] [app2]
                             [outside host]                       +-- DB:   [db]
                                                                  +-- SVC:  [resolver] [step-ca]
                                                                  +-- LAN-A:[client-a] [admin] [mon]
```

- **Routing:** FRR, eBGP to the ISP (public prefixes only) and eBGP over the WireGuard tunnel
  (private prefixes only), prefix-lists on every session. [Address plan](docs/address-plan.md).
- **Firewalls:** nftables on both site routers: a stateless edge filter before conntrack, a
  reverse-path check on every zone, a default-drop zone firewall built from an exact allow list,
  NAT and two published services.
- **Services:** split-horizon DNS (Unbound inside, NSD outside), a private CA (step-ca) issuing
  24-hour certificates over ACME, HAProxy with health-checked backends, and Prometheus with
  blackbox probes.
- **Everything is rendered** by `python -m packetproof render` from [network.yaml](network.yaml):
  router configs, rulesets, DNS zones, proxy and CA settings, the containerlab topology and the
  Batfish snapshot.

## Why the tests can be trusted

- **The method came first.** The pass rules, the 30 faults, the 12 attack paths and the 13
  invariants were committed in [docs/method.md](docs/method.md) before any test code existed. Every
  later change to a rule is a dated amendment.
- **Independent checks.** The invariants (Conftest) and Gate 2's expected values are written by
  hand, never generated from `network.yaml`, so a wrong intent cannot pass both.
- **Every attack has a legitimate twin.** An attack counts as blocked only if a flow that must work
  passes in the same run. A firewall that blocks everything does not pass.
- **Probes must prove they ran.** A probe that cannot run, a scan that does not finish, or a
  capture that never started raises an error instead of reporting "blocked".
- **A gate that could not judge is not a catch.** If a tool or the runner fails in a fault's job,
  the fault is void and re-run ([amendment A2](docs/method.md)).
- **Escapes are published**, with the evidence for why ([limits.md](docs/limits.md)).

## Securing the pipeline itself

Every Action is pinned to a commit SHA, and the repository refuses unpinned ones. The default
workflow token is read-only, and each job asks only for what it needs. zizmor and OpenSSF Scorecard
audit the workflows; Gitleaks scans the whole history. Images are pinned by digest, scanned with
Trivy, given an SBOM and signed with cosign. Config bundles carry a GitHub artifact attestation and a
cosign signature, and prod verifies both before applying anything. Each release is rebuilt from
its tag, must match main's bundle byte for byte, and ships signed checksums and the images' signed
SBOMs ([verify one yourself](docs/verify.md)). WireGuard private keys are
generated inside each pull-request lab's routers and never leave them; prod's long-lived keys and
CA root are SOPS-encrypted in Git, decrypted only by the `prod` environment, and checked in use on
every prod run ([secrets](docs/secrets.md)). SOPS key rotation is proved by a separate test.
Release tags are protected by a ruleset, and releases are immutable once published.
[Threat model](docs/threat-model.md).

## Five diagnoses

Each starts from a symptom and works up the stack with real output from a Gate 3 run:

1. [BGP is up, but site B is unreachable](docs/diagnoses/01-bgp-up-site-unreachable.md) (WireGuard AllowedIPs)
2. [The frontend cannot reach the API](docs/diagnoses/02-frontend-cannot-reach-api.md) (a missing firewall flow)
3. [A stale DNS record took TLS down with it](docs/diagnoses/03-stale-dns-broke-tls.md) (ACME validation)
4. [Which certificate error is this, and why?](docs/diagnoses/04-which-certificate-error.md)
5. [Users lost the internet, and DNS for internet names went with it](docs/diagnoses/05-users-lost-the-internet.md) (a template bug)

## Run it

Any Linux host with Docker, containerlab and sudo:

```bash
pip install -r requirements.txt
docker build -t packetproof/router:dev images/router && docker build -t packetproof/node:dev images/node
python -m packetproof render --out build/lab            # add --fault F08 to plant a fault
python -m packetproof deploy --render build/lab
PP_RENDER=build/lab python -m pytest tests/live         # Gate 2
python -m packetproof destroy --render build/lab
```

The Windows 10 laptop this was built on did not run the lab (see [week 1](docs/go-no-go.md)):
all lab work runs in CI.

## What the gates caught in their own builder

Each of these was found by a check, fixed in a commit that says what it saw, and left in the history:

- **A host's AppArmor follows binaries into containers.** `wg` could not read its key until the key
  moved to `/etc/wireguard`: the runner's profile for `wg` confines it even in a privileged
  container ([go-no-go.md](docs/go-no-go.md)).
- **A green check that did not pass, twice.** Week 1's verdict step and the SOPS rotation test piped
  their result into `tee` without `pipefail`, so they exited 0 on failure; the rotation test printed
  two FAILs and stayed green.
- **Probes that could not run made attacks look blocked.** Every probe now has to prove it ran.
- **A datacenter profile switched off a safety net.** `frr defaults datacenter` disables RFC 8212's
  `ebgp-requires-policy`, which is why fault F06 first escaped ([limits.md](docs/limits.md)).
- **An MTU mismatch is a black hole, not a bottleneck.** The first fix for Gate 2's path-MTU blind
  spot lowered one end of a link and silently dropped TLS ClientHellos.
- **A pipe added a byte-order mark to a secret.** Windows PowerShell 5.1 prefixed the age key piped
  into `gh secret set` with a UTF-8 BOM, and SOPS rejected it in prod. The next run's identity
  check then failed on a file it could not read. Both were fixed and the third run proved the
  identities ([prod.md](docs/prod.md#prod-with-long-lived-identities-from-sops)).
- **Reproducible archives can break servers.** Bundles packed with mtime 0 deployed an NSD that
  never loaded its zone ([prod.md](docs/prod.md)).
- **The apply tool drifted, because of an FRR bug.** Under the datacenter profile, `frr-reload.py
  --reload` of an unchanged config switched off `bgp deterministic-med`. The drift check caught it;
  the cause is FRRouting/frr#22939 (an enum value used as a flag mask), fixed upstream but in no
  release yet. Moving to the traditional profile avoids it, and an in-place apply now leaves no
  drift ([prod.md](docs/prod.md#what-the-drift-check-found-an-frr-bug-now-avoided)).

## What a review of v1.0.0 found

After v1.0.0, the code was reviewed in four independent parts, and every finding was checked before
it was fixed. Four of them change what v1.0.0 could claim, and v1.1.0 fixes all four
([the full account](docs/review-v1.0.0.md)):

- **Every container also sat on containerlab's management network**, a path around the zone
  firewall: a "compromised" DMZ host reached the database there, port 5432 open. The attack paths
  never tried it, because they target only the address plan.
- **The ISP filter matched private space only at the exact /8, /12 and /16**, so both routers
  accepted a more specific private route from the ISP.
- **Three of v1.0.0's 12 attack paths proved nothing**: their nmap scans timed out on every host
  and reported no ports at all. v1.0.0's "12 of 12 blocked" was 9 proved and 3 vacuous.
- **The prod drift check could not see firewall drift on rtr-a**: its self-test reloaded the
  ruleset just before looking.

The first three were shown by a run before they were fixed, the fourth by reading the code. Gate 2
now has a test for each of the first three, and prod now compares before its self-test touches
anything.

## Documents

- [Why this project, and why this design](docs/why.md), with sources
- [What a review of v1.0.0 found](docs/review-v1.0.0.md), and what it changed
- [Method](docs/method.md): the rules, faults, attack paths and invariants, committed before any test
- [Week 1](docs/go-no-go.md): go/no-go checks, with every run linked, including the failures
- [Scorecard](docs/scorecard.md): every Gate 3 run and how each fault was graded
- [What each gate cannot see](docs/limits.md), [the prod change path](docs/prod.md),
  [secrets and their rotation](docs/secrets.md), [verify a release](docs/verify.md),
  [interview map](docs/interview.md),
  [threat model](docs/threat-model.md), [address plan](docs/address-plan.md)

## License

[Apache-2.0](LICENSE)
