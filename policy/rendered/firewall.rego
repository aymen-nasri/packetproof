# Hand-written invariants checked against the firewall as nftables actually loaded it: Gate 1
# loads each rendered ruleset into a scratch network namespace and feeds `nft -j list ruleset`
# here, so a broken template is judged, not the intent behind it.
#
# input: {"router": "rtr-a", "public_prefix": "198.51.100.64/27", "zone_ifaces": [...], "nft": {...}}
package main

items := input.nft.nftables

chain(family, table, name) := c if {
	some i in items
	c := i.chain
	c.family == family
	c.table == table
	c.name == name
}

rules(family, table, name) := [r |
	some i in items
	r := i.rule
	r.family == family
	r.table == table
	r.chain == name
]

has_verdict(rule, verdict) if {
	some e in rule.expr
	object.keys(e)[_] == verdict
}

mentions(rule, value) if {
	walk(rule, [_, v])
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

deny contains msg if {
	not chain("netdev", "edge", "uplink_in")
	msg := sprintf("INV-08: %s has no stateless edge filter on its uplink", [input.router])
}

deny contains msg if {
	chain("netdev", "edge", "uplink_in")
	some p in required_edge
	not edge_drops(p)
	msg := sprintf("INV-08: %s's edge filter does not drop source %s/%d", [input.router, p.addr, p.len])
}

edge_drops(p) if {
	some r in rules("netdev", "edge", "uplink_in")
	has_verdict(r, "drop")
	mentions(r, {"prefix": p})
}

# ---- INV-09: default drop, established/related accepted, ICMP frag-needed let through ---------
deny contains msg if {
	some name in ["input", "forward"]
	c := chain("inet", "pp", name)
	c.policy != "drop"
	msg := sprintf("INV-09: %s's %s chain policy is %s, not drop", [input.router, name, c.policy])
}

deny contains msg if {
	some name in ["input", "forward"]
	not chain("inet", "pp", name)
	msg := sprintf("INV-09: %s has no %s chain", [input.router, name])
}

established_accept(r) if {
	has_verdict(r, "accept")
	mentions(r, "established")
	mentions(r, "related")
}

deny contains msg if {
	not established_accept(rules("inet", "pp", "forward")[0])
	msg := sprintf("INV-09: %s's forward chain does not start by accepting established/related traffic", [input.router])
}

deny contains msg if {
	some r in rules("inet", "pp", "forward")
	has_verdict(r, "drop")
	mentions(r, "destination-unreachable")
	msg := sprintf("INV-09: %s's forward chain drops ICMP destination-unreachable (path MTU discovery)", [input.router])
}

# ---- INV-13: a reverse-path check on every zone interface -------------------------------------
deny contains msg if {
	not rpf_rule
	msg := sprintf("INV-13: %s has no reverse-path check", [input.router])
}

rpf_rule if {
	some r in rules("inet", "pp", "antispoof")
	has_verdict(r, "drop")
	walk(r, [_, v])
	v.fib.flags
}

deny contains msg if {
	rpf_rule
	some i in input.zone_ifaces
	not rpf_covers(i)
	msg := sprintf("INV-13: %s's reverse-path check does not cover %s", [input.router, i])
}

rpf_covers(i) if {
	some r in rules("inet", "pp", "antispoof")
	mentions(r, i)
}
