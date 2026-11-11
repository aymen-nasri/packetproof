# Concept map

Each row ties one networking or delivery concept to where it is built in this repository, what
proves it works, the question it answers, and its nearest managed equivalent in a public cloud.
Nothing here runs in a cloud; the last column only names the closest service.

| Concept | Built in | Proved by | Question it answers | Nearest cloud equivalent |
|---|---|---|---|---|
| Address plan, static routes, eBGP with prefix-lists | [address-plan.md](address-plan.md), `packetproof/render_frr.py` | `tests/live/test_routing.py`; Batfish in Gate 1 | How does a packet get from the branch to the database? | VPC route tables, transit gateway |
| Stateful zone firewall plus a stateless edge filter | `packetproof/render_nft.py` | `test_matrix.py` (the allow and deny matrix); `policy/rendered/firewall.rego` on the loaded ruleset | Security group or network ACL, and why? | Security groups, network ACLs |
| NAT and port forwarding at the edge | `render_nft.py` (`table ip nat`) | `test_nat.py`; attack paths to the outside | Why can't the outside reach the app directly? | NAT gateway, public IPs |
| WireGuard site-to-site, MTU and encapsulation overhead | `render_lab.py` (keys, peers), MTUs in `network.yaml` | `test_mtu.py`; the traceroute in `test_routing.py`; [diagnosis 01](diagnoses/01-bgp-up-site-unreachable.md) | Ping works over the VPN but HTTPS hangs: why? | VPN gateway, peering |
| Split-horizon DNS, recursive and authoritative | `render_services.py` (Unbound, NSD) | `test_dns.py`; [diagnosis 03](diagnoses/03-stale-dns-broke-tls.md) | It works by IP but not by name: why? | Route 53 private hosted zones |
| Private PKI with ACME and short-lived certificates | step-ca in `render_services.py` | `test_tls.py`; [diagnosis 04](diagnoses/04-which-certificate-error.md) | Which certificate error is this, and why? | ACM, AWS Private CA |
| L7 proxy with health checks | HAProxy in `render_services.py` | `test_proxy.py` | One backend is down: what do users see? | Application Load Balancer |
| What a host exposes | every host's start script | `test_surface.py` (`ss`); the scan attack paths | How do you know nothing else is listening? | Inspector network reachability |
| Source of truth and templating | [network.yaml](../network.yaml), `packetproof/` | 52 generator unit tests | How do you avoid config drift between devices? | Terraform modules, CloudFormation |
| CI gates, matrix jobs, artifacts; the same `make` targets locally and in CI | `.github/workflows/`, `Makefile` | every pull request; Gate 3's 31-job matrix | How do you test infrastructure changes? | Terraform plan in CI, GitOps |
| In-place apply and drift checks | `scripts/prod.py`, `prod.yml` | [prod.md](prod.md): no failed requests, no broken connections, no drift | How do you change a running network safely? | Change sets, AWS Config drift detection |
| Policy as code | `policy/intent/invariants.rego`, `policy/rendered/firewall.rego` | Conftest in Gate 1, after 11 unit tests of the policies themselves | How do you enforce rules before deploying? | Service control policies, AWS Config rules, Azure Policy |
| Segmentation proved with traffic | `tests/live/test_attacks.py` | 12 attack paths, each with a legitimate twin | How do you know the control works? | Reachability Analyzer, VPC flow logs |
| Secrets lifecycle | SOPS with age, `scripts/sops_rotation.sh`, [secrets.md](secrets.md) | the rotation test in `secrets.yml`; prod's identity check | How do you rotate a leaked key? | Secrets Manager, KMS key rotation |
| Signed and attested artifacts, verified before use | `bundle.yml`, `images.yml`, `release.yml` | prod refuses a tampered bundle; [verify.md](verify.md) | How do you know that what you deploy is what you built? | Binary Authorization, AWS Signer |
| Hardened pipeline | SHA pins, a read-only token, zizmor, Scorecard, Gitleaks, CodeQL, rulesets on `main` and on release tags | `security.yml` on every pull request | What does a compromised CI dependency get, and how do you limit it? | IAM least privilege for CI roles |
| Monitoring, kept small | Prometheus, blackbox_exporter, Grafana | `test_monitoring.py` | What would you alert on? | CloudWatch Synthetics, Azure Monitor |
| A threat model linked to tests | [threat-model.md](threat-model.md) | every row names its test | What are you defending against, and how do you know? | Well-Architected security pillar |
| Knowing what a test cannot see | [limits.md](limits.md), [review-v1.0.0.md](review-v1.0.0.md) | three published escapes, each explained; a published review of what v1.0.0 claimed | What would your tests miss? | (no service: this is judgment) |

## Five walkthroughs, lowest layer first

Each diagnosis starts from a symptom and works up the stack with real output from a Gate 3 run:

1. [BGP is up, but site B is unreachable](diagnoses/01-bgp-up-site-unreachable.md): WireGuard AllowedIPs
2. [The frontend cannot reach the API](diagnoses/02-frontend-cannot-reach-api.md): a missing firewall flow
3. [A stale DNS record took TLS down with it](diagnoses/03-stale-dns-broke-tls.md): ACME validation
4. [Which certificate error is this, and why?](diagnoses/04-which-certificate-error.md)
5. [Users lost the internet, and DNS for internet names went with it](diagnoses/05-users-lost-the-internet.md): a template bug
