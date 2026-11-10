# 1. "BGP is up, but site B is unreachable"

Planted fault **F08**: AllowedIPs on rtr-a lists only the tunnel address. Evidence: Gate 3 run
[42717245768](https://github.com/aymen-nasri/packetproof/actions/runs/42717245768), artifact
`gate3-F08`.

**Symptom.** From site B, `www.packetproof.example` does not resolve and HTTPS times out. From the
admin host, SSH to rtr-b's loopback fails with "unreachable". Yet nothing looks down.

**First guesses.** The BGP session is down; the firewall drops site B; DNS is broken.

**Commands, bottom up.**

```
rtr-a$ vtysh -c 'show bgp ipv4 unicast summary'
rtr-b(172.31.255.1)  4  65002  101  107  16  0  0 00:04:46   2   6 rtr-b over wg0
rtr-a$ vtysh -c 'show ip route 172.24.10.0/24'
B>* 172.24.10.0/24 [20/0] via 172.31.255.1, wg0
rtr-a$ wg show
peer: CwsAOSzC...
  endpoint: 203.0.113.1:51820
  allowed ips: 172.31.255.1/32
  latest handshake: 46 seconds ago
```

BGP is Established with 2 prefixes received. The route points into wg0. The handshake is fresh.
The firewall rule for site B's users is present. Each layer looks healthy on its own.

**Root cause.** WireGuard routes by key as well as by table: a packet leaves wg0 only if its
destination is in the peer's AllowedIPs, and is accepted only if its source is. `172.24.10.0/24` is
not in rtr-a's list, so rtr-a's kernel drops every packet to site B at the tunnel, and the replies
from site B as well. BGP itself works, because its packets go to `172.31.255.1`, which is listed.

**Fix.** AllowedIPs must cover everything BGP is allowed to send through the tunnel: on rtr-a,
`172.31.255.1/32, 172.24.0.0/16`.

**Prevention, and which gate caught it.** Gate 1 passed it: no static tool here models WireGuard,
and Batfish reports the BGP session over wg0 as established either way. Gate 2 caught it: 9 tests,
every flow from site B. A static invariant would catch it ("AllowedIPs cover the peer's announced
prefixes"), but it is not in the method's list and adding it after seeing this result would only
flatter the score. It is the first row of [limits.md](../limits.md).
