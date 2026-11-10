# Interview map

Each row ties one part of the project to the place in this repository where it is built and
tested, the interview question it rehearses, and its nearest cloud equivalent, so a lab answer
carries over to an AWS or Azure interview. The cloud column is a bridge for interviews, not a claim
of cloud experience.

| Area | Built in | Proved by | Question it rehearses | Cloud equivalent |
|---|---|---|---|---|
| Address plan, static routes, eBGP with prefix-lists | [address-plan.md](address-plan.md), `packetproof/render_frr.py` | `tests/live/test_routing.py`, Batfish in Gate 1 | "How does a packet get from the branch to the database?" | VPC route tables, transit gateway |
| Stateful zone firewall plus a stateless edge filter | `packetproof/render_nft.py` | `test_matrix.py` (allow/deny matrix), `policy/rendered/firewall.rego` on the loaded ruleset | "Security group or NACL, and why?" | Security groups, NACLs |
| NAT and port forwarding at the edge | `render_nft.py` (`table ip nat`) | `test_nat.py`, attack paths from the outside | "Why can't the outside reach the app directly?" | NAT gateway, public IPs |
| WireGuard site-to-site, MTU and encapsulation overhead | `render_lab.py` (keys, peers), `network.yaml` MTUs | `test_mtu.py`, the traceroute in `test_routing.py`, [diagnosis 01](diagnoses/01-bgp-up-site-unreachable.md) | "Ping works over the VPN but HTTPS hangs" | VPN gateway, peering |
| Split-horizon DNS, recursive and authoritative | `render_services.py` (Unbound, NSD) | `test_dns.py`, [diagnosis 03](diagnoses/03-stale-dns-broke-tls.md) | "It works by IP but not by name" | Route 53 private hosted zones |
| Private PKI with ACME, short-lived certificates | step-ca in `render_services.py` | `test_tls.py`, [diagnosis 04](diagnoses/04-which-certificate-error.md) | "Which certificate error is this, and why?" | ACM, AWS Private CA |
| L7 proxy with health checks | HAProxy in `render_services.py` | `test_proxy.py` | "One backend is down; what do users see?" | Application Load Balancer |
| What a host exposes | every host's start script | `test_surface.py` (`ss`), nmap attack paths | "How do you know nothing else is listening?" | Inspector network reachability |
| Source of truth and templating | [network.yaml](../network.yaml), `packetproof/` | 38 generator unit tests | "How do you avoid config drift between devices?" | Terraform modules, CloudFormation |
| CI gates, matrix jobs, artifacts, the same `make test` locally and in CI | `.github/workflows/`, `Makefile` | every pull request; Gate 3's 31-job matrix | "How do you test infrastructure changes?" | Terraform plan in CI, GitOps |
| In-place apply and drift checks | `scripts/prod.py`, `prod.yml` | [prod.md](prod.md): no failed requests, no broken connections, no drift | "How do you change a running network safely?" | Change sets, AWS Config drift detection |
| Policy as code | `policy/intent/invariants.rego`, `policy/rendered/firewall.rego` | Conftest in Gate 1 | "How do you enforce rules before deploy?" | SCPs, AWS Config rules, Azure Policy |
| Segmentation proved with traffic | `tests/live/test_attacks.py` | 12 attack paths, each with a legitimate twin | "How do you know the control works?" | Reachability Analyzer, VPC flow logs |
| Secrets lifecycle | SOPS with age, `scripts/sops_rotation.sh`, [secrets.md](secrets.md) | `secrets.yml` rotation test; prod's identity check | "How do you rotate a leaked key?" | Secrets Manager, KMS key rotation |
| Signed and attested artifacts, verified before use | `bundle.yml`, `images.yml`, `release.yml` | prod refuses a tampered bundle; [verify.md](verify.md) | "How do you know what you deploy is what you built?" | Binary Authorization, Signer |
| Hardened pipeline | SHA pins, read-only token, zizmor, Scorecard, Gitleaks, CodeQL, ruleset on `main` | `security.yml` on every pull request | "What happened with tj-actions and Trivy, and what did you do about it?" | IAM least privilege for CI roles |
| Monitoring, kept small | Prometheus, blackbox_exporter, Grafana | `test_monitoring.py` | "What would you alert on?" | CloudWatch Synthetics, Azure Monitor |
| Threat model linked to tests | [threat-model.md](threat-model.md) | every row names its test | "What are you defending against?" | Well-Architected security pillar |
| Knowing what a test cannot see | [limits.md](limits.md) | three published escapes, each explained | "What would your tests miss?" | (no service: this is judgment) |

## Five walkthroughs, lowest layer first

Each diagnosis starts from a symptom and works up the stack with real output from a Gate 3 run.
They are the answers to rehearse out loud:

1. [BGP is up, but site B is unreachable](diagnoses/01-bgp-up-site-unreachable.md): WireGuard AllowedIPs
2. [The frontend cannot reach the API](diagnoses/02-frontend-cannot-reach-api.md): a missing firewall flow
3. [A stale DNS record took TLS down with it](diagnoses/03-stale-dns-broke-tls.md): ACME validation
4. [Which certificate error is this, and why?](diagnoses/04-which-certificate-error.md)
5. [Users lost the internet, and DNS for internet names went with it](diagnoses/05-users-lost-the-internet.md): a template bug

## Failure stories worth telling

Hiring guides ask for "a specific failure story". These are real, in the commit history, and each
was caught by a check rather than noticed by luck:

- a green CI step that had failed (no `pipefail`), twice;
- attack paths that looked blocked because the probe could not run;
- `frr defaults datacenter` silently disabling RFC 8212, which let fault F06 escape;
- an FRR bug in `frr-reload.py`, found by the prod drift check and traced to an enum used as a flag
  mask (FRRouting/frr#22939);
- reproducible archives with mtime 0 that NSD refused to load.

## The CV line

> **PacketProof**: proving network changes before merge (Python, containerlab, FRR/BGP,
> WireGuard, nftables, GitHub Actions). A two-site network defined in one YAML file; every pull
> request rebuilds it as a disposable copy on a free runner, which must pass routing, segmentation,
> DNS and TLS tests (median gate time 6.6 min). Graded the gates against 30 planted faults: the
> static gate caught 19, the live copy 8, and 3 documented escapes. 12/12 attack paths from a
> compromised DMZ host blocked while every legitimate flow passed. Configs released signed and
> attested, verified before an in-place apply that dropped no connections.

Every number comes from a linked run: [scorecard.md](scorecard.md) for the faults and attack paths,
[prod.md](prod.md) for the apply, and the median of 14 pull-request gate runs (6.2 to 10.0 minutes)
for the gate time.
