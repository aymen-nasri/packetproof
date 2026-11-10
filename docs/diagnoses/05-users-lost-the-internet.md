# 5. "Users lost the internet, and DNS for internet names went with it"

Planted fault **F21**: the source-NAT rule deleted from rtr-a's ruleset template. The intent was
untouched. Evidence: Gate 3 run [42717245768](https://github.com/aymen-nasri/packetproof/actions/runs/42717245768),
artifact `gate3-F21`.

**Symptom.** From LAN-A, `curl http://192.0.2.10/` hangs. Then a second complaint: `dig
www.example.net` returns nothing for every inside client, including site B and the app servers,
even though site B has its own NAT and was not changed.

**First guesses.** The ISP is down; the resolver crashed; the firewall blocks egress.

**Commands.**

```
client-a$ pp-probe.py tcp 192.0.2.10 443
filtered
rtr-a$ nft list chain ip nat postrouting
chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
}                                   <- empty: no SNAT rule at all
```

Without SNAT, LAN-A's packets leave with their private source address, and nothing on the
internet routes a reply back to 172.16.0.0/12 (the ISP holds no private routes, which Gate 2
checks), so no connection completes.

**Root cause.** One rule did two jobs. Site A's SNAT rule covers LAN-A *and* the SVC zone, because
the resolver's recursive queries to the internet must leave as a public address too. With the rule
gone, LAN-A lost the internet and the resolver lost every internet name. Site B's users ask that
same resolver, so they lost internet names as well, though their own NAT still worked.

**Fix.** Restore the rule: `oifname "eth1" ip saddr { 172.16.10.0/24, 172.16.50.0/24 } snat to 198.51.100.66`.

**Prevention, and which gate caught it.** Gate 1 passed it. The intent still lists the SNAT, so
Conftest is satisfied, and the firewall checks on the loaded ruleset cover filtering structure, not
NAT. This is the textbook template bug: right intent, wrong output. Gate 2 caught it with 10 tests,
including the legitimate halves of three attack-path tests, which is why each attack is paired with
a flow that must work.
