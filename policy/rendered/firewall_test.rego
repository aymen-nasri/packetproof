# Unit tests for firewall.rego (`conftest verify`, run by Gate 1): a ruleset in nft's JSON form that
# must pass, and one broken variant per hole the review of v1.0.0 found, each of which must fail.
package main

edge_chain := {"chain": {"family": "netdev", "table": "edge", "name": "uplink_in", "type": "filter", "hook": "ingress", "prio": -500, "policy": "accept", "dev": "eth1"}}

fixture_edge(field) := {"rule": {"family": "netdev", "table": "edge", "chain": "uplink_in", "expr": [
	{"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": field}}, "right": {"set": [
		{"prefix": {"addr": "10.0.0.0", "len": 8}}, {"prefix": {"addr": "172.16.0.0", "len": 12}},
		{"prefix": {"addr": "192.168.0.0", "len": 16}}, {"prefix": {"addr": "127.0.0.0", "len": 8}},
		{"prefix": {"addr": "198.51.100.64", "len": 27}},
	]}}},
	{"counter": {"packets": 0, "bytes": 0}},
	{"drop": null},
]}}

antispoof_chain := {"chain": {"family": "inet", "table": "pp", "name": "antispoof", "type": "filter", "hook": "prerouting", "prio": -150, "policy": "accept"}}

fixture_rpf(ifaces) := {"rule": {"family": "inet", "table": "pp", "chain": "antispoof", "expr": [
	{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": {"set": ifaces}}},
	{"match": {"op": "==", "left": {"fib": {"result": "oif", "flags": ["saddr", "iif"]}}, "right": false}},
	{"counter": {"packets": 0, "bytes": 0}},
	{"drop": null},
]}}

accept_eth3 := {"rule": {"family": "inet", "table": "pp", "chain": "antispoof", "expr": [
	{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "eth3"}},
	{"accept": null},
]}}

input_chain := {"chain": {"family": "inet", "table": "pp", "name": "input", "type": "filter", "hook": "input", "prio": 0, "policy": "drop"}}

forward_chain := {"chain": {"family": "inet", "table": "pp", "name": "forward", "type": "filter", "hook": "forward", "prio": 0, "policy": "drop"}}

forward_no_hook := {"chain": {"family": "inet", "table": "pp", "name": "forward"}}

established := {"rule": {"family": "inet", "table": "pp", "chain": "forward", "expr": [
	{"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": ["established", "related"]}},
	{"accept": null},
]}}

doc(items) := {"router": "rtr-a", "public_prefix": "198.51.100.64/27", "zone_ifaces": ["eth2", "eth3"], "nft": {"nftables": items}}

good := [edge_chain, fixture_edge("saddr"), antispoof_chain, fixture_rpf(["eth2", "eth3"]), input_chain, forward_chain, established]

denies_with(items, prefix) if {
	some m in deny with input as doc(items)
	startswith(m, prefix)
}

test_good_ruleset_passes if {
	count(deny) == 0 with input as doc(good)
}

test_forward_chain_without_hook_or_policy_fails if {
	denies_with([edge_chain, fixture_edge("saddr"), antispoof_chain, fixture_rpf(["eth2", "eth3"]), input_chain, forward_no_hook, established], "INV-09")
}

test_forward_policy_accept_fails if {
	accepting := {"chain": object.union(forward_chain.chain, {"policy": "accept"})}
	denies_with([edge_chain, fixture_edge("saddr"), antispoof_chain, fixture_rpf(["eth2", "eth3"]), input_chain, accepting, established], "INV-09")
}

test_edge_filter_on_destination_fails if {
	denies_with([edge_chain, fixture_edge("daddr"), antispoof_chain, fixture_rpf(["eth2", "eth3"]), input_chain, forward_chain, established], "INV-08")
}

test_edge_filter_on_another_device_fails if {
	elsewhere := {"chain": object.union(edge_chain.chain, {"dev": "eth2"})}
	denies_with([elsewhere, fixture_edge("saddr"), antispoof_chain, fixture_rpf(["eth2", "eth3"]), input_chain, forward_chain, established], "INV-08")
}

test_rpf_missing_an_interface_fails if {
	denies_with([edge_chain, fixture_edge("saddr"), antispoof_chain, fixture_rpf(["eth2"]), input_chain, forward_chain, established], "INV-13")
}

test_accept_before_the_rpf_check_fails if {
	denies_with([edge_chain, fixture_edge("saddr"), antispoof_chain, accept_eth3, fixture_rpf(["eth2", "eth3"]), input_chain, forward_chain, established], "INV-13")
}

test_established_not_first_fails if {
	denies_with([edge_chain, fixture_edge("saddr"), antispoof_chain, fixture_rpf(["eth2", "eth3"]), input_chain, forward_chain, accept_eth3_forward, established], "INV-09")
}

accept_eth3_forward := {"rule": {"family": "inet", "table": "pp", "chain": "forward", "expr": [
	{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "eth3"}},
	{"accept": null},
]}}
