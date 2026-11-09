# PacketProof router: FRRouting plus the tools the design needs on the same box.
# The base image is pinned by digest, so a moved tag cannot change what is built.
FROM quay.io/frrouting/frr:10.7.1@sha256:e995beaa50fdc9edb35eadcfefa29b7f062cc06f2b812613789b68fa541554d2

# nftables: zone firewall and NAT. wireguard-tools-wg: the `wg` tool (kernel WireGuard does the
# work). tcpdump: packet evidence. iproute2: full `ip` for links, routes and wg0. dropbear: SSH,
# so management access is something the firewall must actually restrict. iputils-ping: ping with
# don't-fragment, to measure the tunnel's MTU.
RUN apk add --no-cache nftables wireguard-tools-wg tcpdump iproute2 dropbear iputils-ping
