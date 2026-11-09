"""What the network must look like, written by hand from docs/method.md (parts 2, 3 and 5).

Nothing here is read from network.yaml: if the intent is wrong, these values do not move with
it, and the tests fail. That independence is the point of the design.
"""

CLIENT_A = "172.16.10.10"
ADMIN = "172.16.10.20"
HAPROXY = "172.16.20.10"
NS1 = "172.16.20.53"
APP1 = "172.16.30.11"
APP2 = "172.16.30.12"
DB = "172.16.40.10"
RESOLVER = "172.16.50.53"
CA = "172.16.50.10"
CLIENT_B = "172.24.10.10"
OUTSIDE = "192.0.2.10"
PUBLIC = "198.51.100.65"      # site A's published service address
NAT_A = "198.51.100.66"       # site A's egress NAT address
NAT_B = "203.0.113.66"        # site B's egress NAT address
RTR_A_LO = "172.16.255.1"
RTR_B_LO = "172.24.255.1"
RTR_A_WG = "172.31.255.0"
RTR_B_WG = "172.31.255.1"
RTR_A_DMZ = "172.16.20.1"
RTR_A_DB = "172.16.40.1"

SITE_A_PRIVATE = ["172.16.10.0/24", "172.16.20.0/24", "172.16.30.0/24", "172.16.40.0/24",
                  "172.16.50.0/24", "172.16.255.1/32"]
SITE_B_PRIVATE = ["172.24.10.0/24", "172.24.255.1/32"]

INSIDE_VIEW = {"www": HAPROXY, "haproxy": HAPROXY, "ns1": NS1, "app1": APP1, "app2": APP2, "db": DB,
               "ca": CA, "resolver": RESOLVER, "admin": ADMIN}
OUTSIDE_VIEW = {"www": PUBLIC, "ns1": PUBLIC}
ZONE = "packetproof.example"

# INV-12: flows that must work. (source host, destination, port, what must answer)
# "open": a service answers. "reached": the firewall lets it through (open or refused).
ALLOWED = [
    ("client-a", HAPROXY, 443, "open"), ("client-b", HAPROXY, 443, "open"),
    ("client-a", RESOLVER, 53, "open"), ("client-b", RESOLVER, 53, "open"),
    ("client-a", OUTSIDE, 443, "open"), ("client-a", OUTSIDE, 80, "open"), ("client-b", OUTSIDE, 443, "open"),
    ("admin", APP1, 22, "open"), ("admin", DB, 22, "open"), ("admin", RESOLVER, 22, "open"),
    ("admin", NS1, 22, "open"), ("admin", CLIENT_B, 22, "open"), ("admin", RTR_A_LO, 22, "open"),
    ("admin", RTR_B_LO, 22, "open"),
    ("haproxy", APP1, 8080, "open"), ("haproxy", APP2, 8080, "open"), ("haproxy", CA, 9000, "open"),
    ("ca", HAPROXY, 80, "reached"),
    ("app1", DB, 5432, "open"), ("app2", DB, 5432, "open"), ("app1", RESOLVER, 53, "open"),
    ("resolver", OUTSIDE, 53, "open"),
]

# Flows that must be dropped. Each sits next to an allowed flow above that proves the path
# itself works, so a drop here is the firewall's doing, not a broken network.
DENIED = [
    ("client-a", DB, 5432), ("client-b", DB, 5432),          # INV-01: only APP reaches the DB
    ("client-a", APP1, 8080), ("client-b", APP1, 8080),      # users go through the proxy
    ("client-a", RTR_A_LO, 22), ("client-b", RTR_B_LO, 22),  # INV-02: only admin manages routers
    ("client-a", NS1, 53),                                   # inside users use the resolver
    ("app1", OUTSIDE, 443), ("db", OUTSIDE, 443), ("ca", OUTSIDE, 443),  # INV-04
    ("resolver", OUTSIDE, 443),                              # the resolver's egress is DNS only
    ("db", RESOLVER, 53),                                    # INV-05 / INV-12
    ("ns1", DB, 5432),
    ("outside", PUBLIC, 22), ("outside", PUBLIC, 5432), ("outside", PUBLIC, 8080),  # INV-03
    ("outside", "198.51.100.1", 22), ("outside", HAPROXY, 443),
]
