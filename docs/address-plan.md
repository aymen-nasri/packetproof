# Address plan

Every address below lives in [network.yaml](../network.yaml); this page explains the choices.

## Rules

- **Inside addresses come from 172.16.0.0/12.** A future Kubernetes site (Cilium's BGP lab) needs
  container networks to stay out of 10.0.0.0/8, so the plan starts outside it.
- **Avoid what the lab host already uses.** Docker's default bridge is 172.17.0.0/16. containerlab's
  management network is moved to 192.168.254.0/24 (method amendment A1), so it can never be mistaken
  for a lab prefix.
- **"Public" addresses use the documentation ranges** (RFC 5737): 198.51.100.0/24 for site A,
  203.0.113.0/24 for site B and 192.0.2.0/24 for the internet. They can never collide with a real
  network, and every reader knows they are examples.
- **One site, one summarisable block.** Site A is 172.16.0.0/16 and site B is 172.24.0.0/16, so each
  side can accept the other with a single prefix-list line (`172.16.0.0/16 le 32`).
- **Point-to-point links are /31s** (RFC 3021): two addresses, no network or broadcast to waste.

## Site A (rtr-a, AS 65001)

| Zone | Prefix | Gateway (rtr-a) | Hosts | Interface |
|---|---|---|---|---|
| LAN-A (users) | 172.16.10.0/24 | .1 | client-a .10, admin .20, mon .30 | eth2 |
| DMZ | 172.16.20.0/24 | .1 | haproxy .10, ns1 .53 | eth3 |
| APP | 172.16.30.0/24 | .1 | app1 .11, app2 .12 | eth4 |
| DB | 172.16.40.0/24 | .1 | db .10 | eth5 |
| SVC | 172.16.50.0/24 | .1 | ca .10, resolver .53 | eth6 |
| Loopback | 172.16.255.1/32 | | router ID, management | lo |

## Site B (rtr-b, AS 65002)

| Zone | Prefix | Gateway (rtr-b) | Hosts | Interface |
|---|---|---|---|---|
| LAN-B (users) | 172.24.10.0/24 | .1 | client-b .10 | eth2 |
| Loopback | 172.24.255.1/32 | | router ID, management | lo |

## Between the sites

| Link | Prefix | Ends |
|---|---|---|
| WireGuard tunnel (wg0) | 172.31.255.0/31 | rtr-a .0, rtr-b .1; MTU 1420 (1500 minus 80 bytes of WireGuard over IPv4/UDP) |
| rtr-a to the ISP | 198.51.100.0/31 | isp .0, rtr-a .1 (rtr-a's WireGuard endpoint) |
| rtr-b to the ISP | 203.0.113.0/31 | isp .0, rtr-b .1 (rtr-b's WireGuard endpoint) |
| The ISP to the internet | 192.0.2.0/24 | isp .1, outside host .10; MTU 1400 (the outside user's access line) |

## Public addresses

| Address | Use |
|---|---|
| 198.51.100.64/27 | Site A's public block, advertised to the ISP (nailed to a blackhole route so BGP has it) |
| 198.51.100.65 | Published services: TCP 443 to haproxy, UDP and TCP 53 to ns1 |
| 198.51.100.66 | Site A's egress NAT address (LAN-A users, and the resolver's DNS queries) |
| 203.0.113.64/27 | Site B's public block |
| 203.0.113.66 | Site B's egress NAT address |

## Routing in one paragraph

Each site router has two eBGP sessions. The one to the ISP carries only public prefixes: each site
advertises its /27, and accepts everything except private space and its own block, plus a default
route. The one over the tunnel carries only private prefixes: each site advertises its zones and
loopback, and accepts only the other site's /16. Site-to-site traffic therefore always follows the
tunnel, and nothing private reaches the ISP (INV-06, INV-07). Every eBGP session has an explicit
inbound and outbound policy, as FRR requires by default.
