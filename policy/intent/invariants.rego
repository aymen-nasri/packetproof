# Hand-written invariants (docs/method.md, part 3), checked against network.yaml by Conftest.
# These rules are written from the method, not from the generator, so a wrong intent cannot pass
# both the configs and the checks. INV-08, INV-09 and INV-13 concern rendered firewall rules and
# live in policy/rendered.
package main

private := "172.16.0.0/12"

# ---- INV-01: the DB zone accepts only APP on TCP 5432 (plus admin SSH, INV-02) ---------------
reaches_db(d) if d in {"host:db", "zone:db", "all"}

db_flow_ok(f) if {
	f.from == ["zone:app"]
	f.tcp == [5432]
	not f.udp
	not f.any_port
}

db_flow_ok(f) if {
	f.from == ["host:admin"]
	f.tcp == [22]
	not f.udp
	not f.any_port
}

deny contains msg if {
	some f in input.flows
	some d in f.to
	reaches_db(d)
	not db_flow_ok(f)
	msg := sprintf("INV-01: flow %q reaches the DB zone but is neither APP->db:5432 nor admin SSH", [f.name])
}

deny contains msg if {
	some pf in input.nat.port_forwards
	pf.to == "db"
	msg := "INV-01: a port-forward publishes the database"
}

# ---- INV-02: router management only from the admin host --------------------------------------
to_router(d) if startswith(d, "router:")

to_router(d) if d == "all"

deny contains msg if {
	some f in input.flows
	some d in f.to
	to_router(d)
	some s in f.from
	s != "host:admin"
	msg := sprintf("INV-02: flow %q lets %s reach a router", [f.name, s])
}

# ---- INV-03: from the outside, only HTTPS to haproxy and DNS to ns1 ---------------------------
allowed_publish := {"haproxy/tcp/443->443", "ns1/udp/53->53", "ns1/tcp/53->53"}

published contains x if {
	some pf in input.nat.port_forwards
	some proto in ["tcp", "udp"]
	some p in object.get(pf, proto, [])
	x := sprintf("%s/%s/%d->%d", [pf.to, proto, p, object.get(pf, "to_port", p)])
}

deny contains msg if {
	some x in published
	not x in allowed_publish
	msg := sprintf("INV-03: unexpected published service %s", [x])
}

deny contains msg if {
	some x in allowed_publish
	not x in published
	msg := sprintf("INV-03: expected published service %s is missing", [x])
}

deny contains msg if {
	some f in input.flows
	"internet" in f.from
	msg := sprintf("INV-03: flow %q lets the internet in outside the port-forwards", [f.name])
}

# ---- INV-04: only LAN users go out (80/443), and the resolver (53) ----------------------------
internet_flow_ok(f) if {
	every s in f.from {
		s in {"zone:lan-a", "zone:lan-b"}
	}
	every p in object.get(f, "tcp", []) {
		p in {80, 443}
	}
	not f.udp
	not f.any_port
}

internet_flow_ok(f) if {
	f.from == ["host:resolver"]
	every p in object.get(f, "tcp", []) {
		p == 53
	}
	every p in object.get(f, "udp", []) {
		p == 53
	}
	not f.any_port
}

deny contains msg if {
	some f in input.flows
	"internet" in f.to
	not internet_flow_ok(f)
	msg := sprintf("INV-04: flow %q lets something other than LAN users (80/443) or the resolver (53) out", [f.name])
}

# ---- INV-05: recursion only for LAN-A, LAN-B and APP ------------------------------------------
deny contains msg if {
	some z in input.dns.recursion_for
	not z in {"lan-a", "lan-b", "app"}
	msg := sprintf("INV-05: the resolver recurses for zone %s", [z])
}

deny contains msg if {
	some z in input.dns.local_only_for
	z in {"dmz", "db"}
	msg := sprintf("INV-05: the resolver answers zone %s, which it must refuse", [z])
}

# ---- INV-06: only each site's public prefix is advertised to the ISP --------------------------
deny contains msg if {
	some s in input.sites
	some e in s.bgp.isp.advertise
	p := split(e, " ")[0]
	net.cidr_intersects(p, private)
	msg := sprintf("INV-06: site %s advertises private %s to the ISP", [s.name, e])
}

deny contains msg if {
	some s in input.sites
	some e in s.bgp.isp.advertise
	split(e, " ")[0] != s.public_prefix
	msg := sprintf("INV-06: site %s advertises %s to the ISP, not its public prefix", [s.name, e])
}

# ---- INV-07: site-to-site private traffic never crosses the ISP in clear ----------------------
deny contains msg if {
	some s in input.sites
	some r in s.static_routes
	net.cidr_intersects(r.prefix, private)
	r.via == s.uplink.isp_address
	msg := sprintf("INV-07: site %s routes private %s to the ISP in clear", [s.name, r.prefix])
}

# ---- INV-10: the proxy's certificate covers the name it serves --------------------------------
deny contains msg if {
	certs := [c | some c in input.pki.certificates; c.host == input.proxy.host]
	not input.proxy.certificate in {n | some c in certs; some n in c.names}
	msg := sprintf("INV-10: no certificate for %s is issued to %s", [input.proxy.certificate, input.proxy.host])
}

# ---- INV-11: inside names never resolve from the outside --------------------------------------
internal_host(name) if {
	some h in input.hosts
	h.name == name
	h.zone != "outside"
}

deny contains msg if {
	some label, value in input.dns.outside
	internal_host(value)
	msg := sprintf("INV-11: outside view %s points at internal host %s", [label, value])
}

deny contains msg if {
	some label, value in input.dns.outside
	not internal_host(value)
	net.cidr_contains(private, value)
	msg := sprintf("INV-11: outside view %s publishes private address %s", [label, value])
}

# Names, not only values: `db: 198.51.100.65` in the outside view would make db.packetproof.example
# resolve from the outside with a public value (review of v1.0.0). Only these two are published.
published_outside := {"www", "ns1"}

deny contains msg if {
	some label, _ in input.dns.outside
	not label in published_outside
	msg := sprintf("INV-11: the outside view publishes the name %s; only www and ns1 are public", [label])
}

# ---- INV-12: the allowed flows are exactly these ----------------------------------------------
expected_flows := {
	"users-to-web": {"from": {"zone:lan-a", "zone:lan-b"}, "to": {"host:haproxy"}, "tcp": {443}, "udp": set()},
	"users-to-dns": {"from": {"zone:lan-a", "zone:lan-b"}, "to": {"host:resolver"}, "tcp": {53}, "udp": {53}},
	"users-to-internet": {"from": {"zone:lan-a", "zone:lan-b"}, "to": {"internet"}, "tcp": {80, 443}, "udp": set()},
	"admin-ssh": {"from": {"host:admin"}, "to": {"all"}, "tcp": {22}, "udp": set()},
	"proxy-to-app": {"from": {"host:haproxy"}, "to": {"host:app1", "host:app2"}, "tcp": {8080}, "udp": set()},
	"acme-order": {"from": {"host:haproxy"}, "to": {"host:ca"}, "tcp": {9000}, "udp": set()},
	"acme-challenge": {"from": {"host:ca"}, "to": {"host:haproxy"}, "tcp": {80}, "udp": set()},
	"app-to-db": {"from": {"zone:app"}, "to": {"host:db"}, "tcp": {5432}, "udp": set()},
	"app-to-dns": {"from": {"zone:app"}, "to": {"host:resolver"}, "tcp": {53}, "udp": {53}},
	"resolver-to-internet": {"from": {"host:resolver"}, "to": {"internet"}, "tcp": {53}, "udp": {53}},
}

actual(f) := {
	"from": {x | some x in f.from},
	"to": {x | some x in f.to},
	"tcp": {p | some p in object.get(f, "tcp", [])},
	"udp": {p | some p in object.get(f, "udp", [])},
}

deny contains msg if {
	some f in input.flows
	not expected_flows[f.name]
	msg := sprintf("INV-12: unexpected flow %q", [f.name])
}

deny contains msg if {
	some f in input.flows
	exp := expected_flows[f.name]
	actual(f) != exp
	msg := sprintf("INV-12: flow %q is %v, expected %v", [f.name, actual(f), exp])
}

deny contains msg if {
	some f in input.flows
	f.any_port
	msg := sprintf("INV-12: flow %q allows any port", [f.name])
}

deny contains msg if {
	some name, _ in expected_flows
	not name in {f.name | some f in input.flows}
	msg := sprintf("INV-12: expected flow %q is missing", [name])
}

# A zone is the set of interfaces labelled with it; a relabelled interface changes every flow.
deny contains msg if {
	some s in input.sites
	some z in s.zones
	object.get(z, "interface_zone", z.name) != z.name
	msg := sprintf("INV-12: zone %s's interface is labelled as zone %s", [z.name, z.interface_zone])
}
