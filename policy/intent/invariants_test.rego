# Unit tests for invariants.rego (`conftest verify`, run by Gate 1).
package main

intent_dns(outside) := {"hosts": [{"name": "db", "zone": "db", "address": "172.16.40.10"},
	{"name": "haproxy", "zone": "dmz", "address": "172.16.20.10"}],
	"dns": {"outside": outside}}

inv11(outside) := {m | some m in deny with input as intent_dns(outside); startswith(m, "INV-11")}

test_inv11_public_names_pass if {
	count(inv11({"www": "198.51.100.65", "ns1": "198.51.100.65"})) == 0
}

test_inv11_inside_name_with_a_public_value_fails if {
	count(inv11({"www": "198.51.100.65", "ns1": "198.51.100.65", "db": "198.51.100.65"})) > 0
}

test_inv11_internal_host_value_fails if {
	count(inv11({"www": "haproxy"})) > 0
}
