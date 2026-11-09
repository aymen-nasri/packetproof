# Threat model

One page, linked to tests: every threat names the control that stops it and the check that proves
the control works. Invariants (INV), attack paths (AP) and planted faults (F) are defined in
[method.md](method.md).

## What is protected

| Asset | Where | Why it matters |
|---|---|---|
| The database | DB zone, db 172.16.40.10 | The crown jewels: only the app may talk to it |
| Router management | SSH on every router address | Whoever manages a router controls every flow |
| Internal names and addresses | the inside DNS view | A map of the network for an attacker |
| Site-to-site traffic | the WireGuard tunnel | Crosses an ISP the company does not control |
| The PKI | step-ca's keys, the issued certificates | A rogue certificate defeats TLS everywhere |
| The change pipeline | workflows, images, config bundles | Whoever changes the pipeline changes the network |

## Who attacks, from where

1. **A compromised DMZ host.** HAProxy faces the internet, so it is the likeliest first foothold.
   Every attack path (AP-01 to AP-12) starts here.
2. **Anyone on the internet.** It can reach site A's public address and send forged packets.
3. **A bad change.** A wrong intent, a broken template or a hand-edited file, merged in good faith.
   This is the most common cause of outages, and the 30 planted faults are this attacker.
4. **A tampered artifact.** A hijacked Action, a replaced image or an edited config bundle
   between build and apply.

## Threats, controls and the checks that prove them

| Threat | Control | Proved by |
|---|---|---|
| DMZ host scans or connects to the DB | zone firewall, DB reachable only from APP on 5432 (INV-01) | AP-01, AP-02; Conftest INV-01; F12 |
| DMZ host moves laterally (SSH, user LANs, site B) | default-drop forward chain, exact allow list (INV-09, INV-12) | AP-03, AP-04, AP-08; F13, F14 |
| Router takeover through management | SSH only from the admin host, on every router address (INV-02) | AP-05, AP-06, AP-07; F17 |
| One zone pretends to be another | reverse-path check on every zone interface (INV-13) | AP-12 |
| Forged private sources from the internet | stateless edge filter before conntrack (INV-08) | Gate 2 edge test; F16 |
| Data leaves from the DMZ | no DMZ egress; DMZ gets no DNS (INV-04, INV-05) | AP-09, AP-10, AP-11; F19, F26 |
| Data hidden in DNS names | the resolver refuses DMZ and DB; only it may query the internet | AP-10, AP-11 |
| Internal names leak | split-horizon DNS, outside view holds public names only (INV-11) | Gate 2 DNS tests; F25 |
| Internal services exposed | only HTTPS and DNS are published (INV-03) | Gate 2 port scan from outside; F20, F23 |
| Private routes leak to the ISP | prefix-lists on every eBGP session (INV-06) | Batfish, Gate 2 ISP table; F01 |
| Site-to-site traffic in clear | private prefixes only over WireGuard (INV-07) | Gate 2 routing tests; F05 |
| Rogue or expired certificates accepted | private CA, short-lived ACME certificates, clients verify (INV-10) | Gate 2 TLS refusals; F28, F29 |
| A hijacked Action or moved tag | every Action pinned to a commit SHA, SHA pinning enforced by the repository, Dependabot with a 7-day cooldown | zizmor and OpenSSF Scorecard on every push |
| Secrets committed to Git | Gitleaks over the whole history; WireGuard keys generated inside each router and never stored | Gitleaks job; key-exchange design |
| A replaced image | images pinned by digest, signed with cosign, verified before prod uses them | images.yml, prod.yml step 1 |
| An edited config bundle | provenance attestation and cosign signature, verified before apply | prod.yml step 2: a tampered bundle is refused |
| Secrets readable after a key is retired | SOPS + age with rotation | secrets.yml rotation test |

## What this model does not cover

- **The runner itself.** GitHub's hosted runners are trusted. A compromised runner could fake every
  result. The defence is reproducibility: anyone can rerun the workflows.
- **Kernel and container escapes.** The lab uses containers, not VMs. Privileged router containers
  share the runner's kernel, and as week 1 showed, even the host's AppArmor profiles.
- **Denial of service, timing and side channels.** Not tested.
- **The grader grading itself.** One person wrote both the faults and the gates. Mitigations:
  the method was committed before any result, fault types come from common real-world mistakes,
  and every escape is published.
