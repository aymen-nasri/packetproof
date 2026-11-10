# Why PacketProof is built this way

This page records the reasoning behind the design, with the sources it rests on, and says where
building it changed the plan.

## The problem

A network change is usually reviewed as text: a diff of a router config or a firewall rule. A diff
cannot show that a packet still reaches its destination, that a zone is still sealed, or that DNS,
certificates and the proxy still agree after the change. Static analysis helps (Batfish models
routing well), but no single tool covers routing, a zone firewall, NAT, a tunnel, split-horizon DNS,
a private CA and a proxy together. And a policy file is "a statement of intent", not proof that the
network behaves that way ([ControlPlane](https://control-plane.io/posts/validating-zero-trust/)).

"Network digital twin" pipelines that rebuild a network to test a change are described in the trade
press, but without measured results ([ITOps Times](https://itopstimes.com/?p=10996)). PacketProof is
such a pipeline that measures itself: it rebuilds the whole network for every change, sends real
traffic through it, and then grades its own checks against faults planted on purpose.

## Why one gated network, not one more tool

Each narrower idea (a WireGuard mesh, a firewall test suite, certificate rotation, DNS as code) is
one layer of this one. Building them together makes them depend on each other:

- network as code means little without CI that rebuilds the network from it;
- a segmentation claim means little until packets test it;
- grading the gates against planted faults is a measurement problem in its own right, the method a
  CI/CD security study used with deliberately vulnerable workflows
  ([SoK](https://zmuda.dev/media/SoK_Understanding_CICD_Security.pdf)).

The fundamentals come first (an address plan, a firewall matrix, DNS, TLS); BGP and WireGuard are
the plumbing that connects the sites.

## The decisions, and what building it did to them

| Decision | Reason | What happened |
|---|---|---|
| Containers only, on free public-repository runners | 4 vCPU and 16 GB free, no KVM, no cloud account needed ([GitHub Docs](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)) | Held. A small lab deploys in about 22 s. The lab needs Linux, so all lab work runs in CI ([feasibility.md](feasibility.md)) |
| Addresses in 172.16.0.0/12 | Leaves 10.0.0.0/8 free for a future Kubernetes site ([Cilium docs](https://docs.cilium.io/en/latest/contributing/development/bgp_cplane/)) | Held, after amendment A1 moved containerlab's management network out of the lab's range |
| Hand-written invariants and expectations | Tests generated from the same intent as the configs would pass a wrong intent | Held. Gate 2's values live in `tests/live/expect.py` and are never read from `network.yaml` |
| Batfish only if a feasibility check proves it | It documents FRR only inside the Cumulus format, and models neither nftables nor WireGuard | GO, with a grammar workaround. Its blind spots are the first rows of [limits.md](limits.md) |
| Every attack paired with a legitimate flow | A firewall that drops everything must not pass | Held, and extended: probes must prove they ran, after probes that could not run made attacks look blocked |
| Faults, attack paths and grading rules committed before any result | The person planting the faults also writes the gates | Held. [method.md](method.md) predates every test; rule changes are dated amendments |
| "Prod" rebuilt from the previous bundle, then changed in place | Fresh builds hide ordering and disruption problems | The drift check found an FRR bug this way (FRRouting/frr#22939, [prod.md](prod.md)) |
| Every Action pinned by SHA and every image by digest | The March 2026 Trivy compromise repointed tags; digests were unaffected ([GHSA-69fq-xp46-6x23](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23)) | Held, enforced by zizmor on every pull request |
| SOPS with age for secrets | A free, file-based secrets lifecycle ([major.io](https://major.io/p/encrypted-gitops-secrets-with-flux-and-age/)) | Rotation is proved with throwaway keys; prod's long-lived identities follow [secrets.md](secrets.md) |
| No internet-facing component | Free hosts are unreliable or unavailable without a credit card ([Oracle FAQ](https://www.oracle.com/cloud/free/faq/), [Fly.io](https://docs.fly.io/about/pricing)) | The lab simulates the internet with an ISP router and an outside host; results are published to GitHub Pages |

## Tools chosen, and tools avoided

| Use | Avoid, and why |
|---|---|
| containerlab, FRR, nftables and wireguard-tools in one custom image | Vendor router images: registration or packet-rate limits ([containerlab](https://containerlab.dev/manual/kinds/srl/)) |
| pybatfish, `vtysh --dryrun`, `frr-reload.py --test`, Conftest, JSON Schema | SuzieQ as a dependency: one listed maintainer and long release gaps ([PyPI](https://pypi.org/project/suzieq/)) |
| Unbound and NSD, step-ca with ACME, HAProxy | ingress-nginx, retired in March 2026 ([Kubernetes blog](https://kubernetes.io/blog/2025/11/11/ingress-nginx-retirement/)) |
| SOPS with age, cosign, GitHub artifact attestations, Trivy by checksum, zizmor, Scorecard, Gitleaks, CodeQL | Vault and Terraform (BSL licences), Semgrep rules (restrictive licence) ([The New Stack](https://thenewstack.io/opengrep-launches-as-free-fork-after-semgrep-license-shift/)) |
| Prometheus, blackbox_exporter and Grafana OSS, kept small | Alert routing and on-call tooling: out of scope for a lab |

## Out of scope

A Kubernetes site (a kind cluster with Cilium peering over BGP with rtr-a, and the Gateway API) is
out of scope. The address plan keeps room for it.

## The limit of this reasoning

The design choices above are argued from sources; they were not measured against alternatives.
What is measured is the gates themselves: how many planted faults each one catches, which escape
and why. That is why the most useful page in this repository is [limits.md](limits.md).
