# PacketProof node: every non-router host in the lab runs this one image, and its role comes
# from the start script rendered for it. The base image is pinned by digest.
FROM alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf

# Services: unbound (resolver), nsd (authoritative DNS), dnsmasq (the outside's DNS), haproxy,
# step-certificates and step-cli (lab CA and ACME client), prometheus, blackbox exporter and grafana,
# dropbear (SSH on every internal host). Tools for tests: curl, dig, openssl, nmap, nping,
# ncat, tcpdump, iputils ping (supports don't-fragment), python3 for the small servers in bin/.
RUN apk add --no-cache \
      unbound nsd dnsmasq haproxy step-certificates step-cli prometheus prometheus-blackbox-exporter grafana \
      dropbear curl bind-tools openssl nmap nmap-nping nmap-ncat tcpdump iputils-ping iproute2 python3

COPY bin/ /usr/local/bin/
RUN chmod 0755 /usr/local/bin/*.py
