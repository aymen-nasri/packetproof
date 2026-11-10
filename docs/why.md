# Why this project, and why it is built this way

This page records the reasoning behind PacketProof's design, with the sources it rests on. It was
written from the research brief that chose the project, and it also says where the build changed
the plan.

## The gap it fills

Networking is tested in junior DevOps interviews far more than it appears in job ads. None of
networking, DNS, TCP/IP, firewalls, VPNs or load balancing is among the top 30 skills in 1,607 UK
DevOps ads ([ITJobsWatch](https://www.itjobswatch.co.uk/jobs/uk/devops%20engineer.do)). One
interview guide still calls IP addressing and CIDR "the most heavily tested area", and it gives the
classic scenario "the frontend cannot reach the API", answered in the order DNS, route, port,
firewall ([Obelinf](https://obelinf.com/blog/what-a-devops-internship-actually-expects-you-to-know-about-networks/)).
A hiring engineer says he values basic networking over service meshes "because when things break,
you debug at the lowest level" ([Signal Reads](https://signalreads.com/articles/getting-into-devops/)).

The author's other projects already cover the common DevOps keywords (Kubernetes, IaC, CI/CD,
scanning, SBOMs, signing, monitoring). Neither shows a packet moving through a network. So this
project puts the fundamentals first (CIDR plan, firewall matrix, DNS, TLS) and treats BGP and
WireGuard as plumbing. The same guide says BGP is "unlikely to be tested".

## Why a gated network, not one more tool

Each narrower idea the brief compared (a WireGuard mesh, a purple-team pipeline, certificate
rotation, DNS as code) is one layer of this one. Building them together makes the disciplines
depend on each other:

- network as code means nothing without CI that rebuilds the network;
- a segmentation claim means nothing until packets test it: a policy file is "a statement of
  intent", not proof ([ControlPlane](https://control-plane.io/posts/validating-zero-trust/));
- grading the gates against planted faults is a measurement problem in its own right, the method a
  CI/CD security paper used with deliberately vulnerable workflows
  ([SoK](https://zmuda.dev/media/SoK_Understanding_CICD_Security.pdf)).

"Network digital twin" pipelines are described in the trade press without measured results
([ITOps Times](https://itopstimes.com/?p=10996)). The opening this project takes is a version
that is honestly measured and runs in free CI.

## The decisions, and what the build did to them

| Decision | Reason | What happened |
|---|---|---|
| Containers only, on free public-repo runners | 4 vCPU and 16 GB free, no KVM, no cloud account ([GitHub Docs](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)) | Held. A full lab deploys in about 22 s; the laptop could not run it, so all lab work runs in CI ([go-no-go.md](go-no-go.md)) |
| Addresses in 172.16.0.0/12 | Leaves 10/8 free for a later Kubernetes site ([Cilium docs](https://docs.cilium.io/en/latest/contributing/development/bgp_cplane/)) | Held, after amendment A1 moved the management network out of the lab's range |
| Hand-written invariants and expectations | Tests generated from the same intent as the configs pass a wrong intent | Held. Gate 2's values live in `tests/live/expect.py` and are never read from `network.yaml` |
| Batfish only if week 1 proves it | It documents FRR only inside the Cumulus format, and lists neither nftables nor WireGuard | Week 1: GO with a grammar workaround. Its blind spots are the first rows of [limits.md](limits.md) |
| Every attack paired with a legitimate flow | A firewall that drops everything must not pass | Held, and extended: probes must prove they ran, after unrunnable probes made attacks look blocked |
| Fault list committed before any result | The person planting faults also writes the gates | Held. [method.md](method.md) predates every test; one dated amendment |
| "Prod" rebuilt from the previous bundle, then changed in place | Fresh builds hide ordering and disruption problems | It found an FRR bug (FRRouting/frr#22939) through the drift check ([prod.md](prod.md)) |
| Pin every Action by SHA and every image by digest | The March 2026 Trivy compromise repointed tags; digests were unaffected ([GHSA-69fq-xp46-6x23](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23)) | Held, enforced by zizmor on every pull request |
| SOPS with age for secrets | A free, file-based secrets lifecycle ([major.io](https://major.io/p/encrypted-gitops-secrets-with-flux-and-age/)) | Rotation proved with throwaway keys; prod's long-lived identities follow [secrets.md](secrets.md) |
| No internet-facing piece | Free hosts are unreliable or unavailable to a prepaid card ([Oracle FAQ](https://www.oracle.com/cloud/free/faq/), [Fly.io](https://docs.fly.io/about/pricing)) | The lab simulates the internet with an ISP router and an outside host; evidence goes to GitHub Pages |

## Tools chosen, and tools avoided

| Use | Avoid, and why |
|---|---|
| containerlab, FRR, nftables, wireguard-tools in one custom image | Vendor router images: registration or packet-rate limits ([containerlab](https://containerlab.dev/manual/kinds/srl/)) |
| pybatfish, `vtysh --dryrun`, `frr-reload.py --test`, Conftest, JSON Schema | SuzieQ as a dependency: one listed maintainer and long release gaps ([PyPI](https://pypi.org/project/suzieq/)) |
| Unbound and NSD, step-ca with ACME, HAProxy | ingress-nginx, retired in March 2026 ([Kubernetes blog](https://kubernetes.io/blog/2025/11/11/ingress-nginx-retirement/)) |
| SOPS with age, cosign, GitHub artifact attestations, Trivy by checksum, zizmor, Scorecard, Gitleaks, CodeQL | Vault and Terraform (BSL licences), Semgrep rules (restrictive licence) ([The New Stack](https://thenewstack.io/opengrep-launches-as-free-fork-after-semgrep-license-shift/)) |
| Prometheus, blackbox_exporter, Grafana OSS, kept small | Alert-delivery measurement, which the author's BlindSpot project already covers |

## What is deliberately out of scope

The brief's optional tenth week (a kind cluster with Cilium BGP peering to rtr-a, and Gateway
API) was left out of this MVP by choice: weeks 1 to 9 only. The address plan keeps room for it.

## The honest limit of this reasoning

No source measures which projects get students hired. The evidence supports something narrower:
networking fundamentals are tested in interviews; measured, reproducible claims hold up under
questioning; and "here is what my gates missed" shows judgment. That is why the most important file
in this repository is [limits.md](limits.md).
