# Hand-written invariants checked against the firewall as nftables actually loaded it: Gate 1
# loads each rendered ruleset into a scratch network namespace and feeds `nft -j list ruleset`
# here, so a broken template is judged, not the intent behind it.
#
# Chains are found by what they are attached to (family, hook, device), not by their names: a
# template that renames a chain or drops its `type ... hook ...; policy drop;` line would otherwise
# leave every rule here vacuously true (review of v1.0.0).
#
# input: {"router": "rtr-a", "public_prefix": "198.51.100.64/27", "zone_ifaces": [...], "nft": {...}}
package main

uplink := "eth1"

items := input.nft.nftables

chains contains c if {
	some i in items
	c := i.chain
}

# Base chains: attached to a hook (a chain with no hook is only reachable by a jump).
base_chains(family, hook) := {c | some c in chains; c.family == family; c.hook == hook; c.type == "filter"}

rules_of(c) := [r |
	some i in items
	r := i.rule
	r.family == c.family
	r.table == c.table
	r.chain == c.name
]

has_verdict(rule, verdict) if {
	some e in rule.expr
	object.keys(e)[_] == verdict
}

mentions(x, value) if {
	walk(x, [_, v])
	v == value
}

# ---- INV-08: the stateless edge filter drops bogon and own-prefix sources ---------------------
required_edge := [
	{"addr": "10.0.0.0", "len": 8},
	{"addr": "172.16.0.0", "len": 12},
	{"addr": "192.168.0.0", "len": 16},
	{"addr": "127.0.0.0", "len": 8},
	{"addr": split(input.public_prefix, "/")[0], "len": to_number(split(input.public_prefix, "/")[1])},
]

on_uplink(c) if c.dev == uplink

on_uplink(c) if uplink in c.dev

on_uplink(c) if uplink in c.devs

edge_chains contains c if {
	some c in base_chains("netdev", "ingress")
	on_uplink(c)
}

deny contains msg if {
	count(edge_chains) == 0
	msg := sprintf("INV-08: %s has no stateless filter on the ingress hook of its uplink %s", [input.router, uplink])
}

deny contains msg if {
	count(edge_chains) > 0
	some p in required_edge
	not edge_drops(p)
	msg := sprintf("INV-08: %s's edge filter does not drop source %s/%d", [input.router, p.addr, p.len])
}

# A drop rule whose match is on the IP source address and covers the prefix (alone or in a set).
edge_drops(p) if {
	some c in edge_chains
	some r in rules_of(c)
	has_verdict(r, "drop")
	some e in r.expr
	e.match.left.payload.field == "saddr"
	mentions(e.match.right, {"prefix": p})
}

# ---- INV-09: default drop, established/related accepted first, ICMP frag-needed let through ----
drop_base_chains(hook) := {c | some c in base_chains("inet", hook); object.get(c, "policy", "accept") == "drop"}

deny contains msg if {
	some hook in ["input", "forward"]
	count(drop_base_chains(hook)) == 0
	msg := sprintf("INV-09: %s has no %s base chain with a drop policy", [input.router, hook])
}

established_accept(r) if {
	has_verdict(r, "accept")
	mentions(r, "established")
	mentions(r, "related")
}

deny contains msg if {
	some c in drop_base_chains("forward")
	not established_accept(rules_of(c)[0])
	msg := sprintf("INV-09: %s's forward chain does not start by accepting established/related traffic", [input.router])
}

deny contains msg if {
	some c in base_chains("inet", "forward")
	some r in rules_of(c)
	has_verdict(r, "drop")
	mentions(r, "destination-unreachable")
	msg := sprintf("INV-09: %s's forward chain drops ICMP destination-unreachable (path MTU discovery)", [input.router])
}

# ---- INV-13: a reverse-path check on every zone interface -------------------------------------
# The reverse-path drop rules: a fib lookup on the source, in a prerouting filter base chain.
rpf_rules contains [c, idx] if {
	some c in base_chains("inet", "prerouting")
	some idx, r in rules_of(c)
	has_verdict(r, "drop")
	some e in r.expr
	e.match.left.fib.flags
}

deny contains msg if {
	count(rpf_rules) == 0
	msg := sprintf("INV-13: %s has no reverse-path check", [input.router])
}

deny contains msg if {
	count(rpf_rules) > 0
	some i in input.zone_ifaces
	not rpf_covers(i)
	msg := sprintf("INV-13: %s's reverse-path check does not cover %s", [input.router, i])
}

# Covered: the drop rule itself names the interface (or names no interface at all), and no rule
# before it in that chain accepts, which would end the chain before the check.
rpf_covers(i) if {
	some pair in rpf_rules
	c := pair[0]
	idx := pair[1]
	r := rules_of(c)[idx]
	names_iface_or_all(r, i)
	count([j | some j, prev in rules_of(c); j < idx; has_verdict(prev, "accept")]) == 0
}

names_iface_or_all(r, i) if mentions(r, i)

names_iface_or_all(r, _) if {
	not iif_match(r)
}

iif_match(r) if {
	some e in r.expr
	e.match.left.meta.key in {"iifname", "iif"}
}
