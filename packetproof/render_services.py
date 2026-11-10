"""Per-host configs and start scripts: DNS (both views), CA, proxy, apps, decoys, monitoring.

Each host gets a directory mounted at /pp (read-only) holding start.sh and its configs. The
directory mounted at /shared carries only what a real network would distribute out of band:
the lab CA's root certificate and the test certificates used by Gate 2.
"""

from __future__ import annotations

import ipaddress
import json

from .model import Network

ZONE_TTL = 60


def _plen(net: Network, zone: str) -> str:
    return net.zones[zone]["prefix"].split("/")[1] if zone != "outside" else net.data["isp"]["outside"]["prefix"].split("/")[1]


def _gateway(net: Network, zone: str) -> str:
    return net.zones[zone]["gateway"] if zone != "outside" else net.data["isp"]["outside"]["gateway"]


def _fqdn(net: Network, label: str) -> str:
    return f"{label}.{net.data['dns']['zone']}"


def inside_records(net: Network) -> dict[str, str]:
    return {_fqdn(net, k): net.resolve_dns_target(v) for k, v in net.data["dns"]["inside"].items()}


def _prelude(net: Network, host: dict) -> list[str]:
    zone = host["zone"]
    lines = [
        "#!/bin/sh",
        f"# Rendered by packetproof for {host['name']} ({host['role']}). Do not edit by hand.",
        "exec >/tmp/pp-start.log 2>&1",
        "set -eux",
        "# containerlab attaches eth1 after the container starts; wait for it.",
        "i=0; while ! ip link show eth1 >/dev/null 2>&1; do i=$((i+1)); [ $i -gt 600 ] && exit 1; sleep 0.1; done",
        f"ip addr add {host['address']}/{_plen(net, zone)} dev eth1",
        "ip link set eth1 up",
        f"ip route replace default via {_gateway(net, zone)} dev eth1",
    ]
    if host["role"] == "outside" and net.data["isp"]["outside"].get("mtu", 1500) < 1500:
        # Like a client behind a tunnel that does not clamp its MSS: it advertises 1460 bytes on a
        # smaller line, so servers must rely on path-MTU discovery (ICMP "fragmentation needed").
        lines[-1] += " advmss 1460"
    resolver = next(h for h in net.data["hosts"] if h["role"] == "dns-resolver")
    if zone in ("dmz", "db", "outside"):
        # DMZ and DB hosts get no DNS (INV-05, INV-12): the names they need come from a static
        # hosts file rendered from the inside view.
        lines.append(": > /etc/resolv.conf")
        if zone != "outside":
            # Only the names this host's own software looks up: a compromised DMZ host should not
            # be handed a map of the network (review of v1.0.0). HAProxy's backends are addresses;
            # its ACME client needs the CA's name, and nothing else needs any.
            needed = {net.host_address(net.data["pki"]["ca"])} if host["role"] == "proxy" else set()
            for name, addr in inside_records(net).items():
                if addr in needed:
                    lines.append(f"echo '{addr} {name}' >> /etc/hosts")
    else:
        lines.append(f"echo 'nameserver {resolver['address']}' > /etc/resolv.conf")
    if host["role"] != "outside":
        lines.append("dropbear -R -p 22")
    return lines


def _wait_for(path: str, seconds: int = 180) -> str:
    return f"i=0; while [ ! -s {path} ]; do i=$((i+1)); [ $i -gt {seconds * 2} ] && exit 1; sleep 0.5; done"


STEP = 'STEP="$(command -v step || command -v step-cli)"'


def start_script(net: Network, host: dict) -> tuple[str, dict[str, str]]:
    """Return (start.sh, {extra file name: content}) for one host."""
    role = host["role"]
    lines = _prelude(net, host)
    files: dict[str, str] = {}
    dns = net.data["dns"]

    if role == "dns-resolver":
        files["unbound.conf"] = unbound_conf(net)
        lines += ["unbound -c /pp/unbound.conf"]
    elif role == "dns-authoritative":
        files["nsd.conf"] = NSD_CONF.format(zone=dns["zone"])
        files[f"{dns['zone']}.zone"] = outside_zone(net)
        lines += ["mkdir -p /var/lib/nsd /run/nsd", "nsd -c /pp/nsd.conf",
                  # A server that started without its zone answers SERVFAIL; fail readiness instead.
                  "i=0; until grep -q 'read with success' /tmp/nsd.log 2>/dev/null; do "
                  "i=$((i+1)); [ $i -gt 40 ] && exit 1; sleep 0.25; done"]
    elif role == "ca":
        lines += ca_lines(net)
    elif role == "proxy":
        files["haproxy.cfg"] = haproxy_cfg(net)
        lines += proxy_lines(net, host)
    elif role == "app":
        lines += [f"nohup python3 /usr/local/bin/pp-app.py --name {host['name']} --port 8080 >/tmp/app.log 2>&1 &"]
    elif role == "db":
        lines += ["nohup python3 /usr/local/bin/pp-decoy.py --port 5432 --banner PGDECOY >/tmp/decoy.log 2>&1 &"]
    elif role == "outside":
        lines += [
            "printf 'address=/example.net/%s\\nno-resolv\\nlog-queries\\nlog-facility=/tmp/dnsmasq.log\\n' "
            f"'{host['address']}' > /tmp/dnsmasq.conf",
            "dnsmasq -C /tmp/dnsmasq.conf",
            "nohup python3 /usr/local/bin/pp-outside.py --ports 80,443,4444 >/tmp/outside.log 2>&1 &",
        ]
    elif role == "monitor":
        files["blackbox.yml"] = BLACKBOX_YML
        files["prometheus.yml"] = prometheus_yml(net)
        files.update(grafana_files())
        lines += [
            _wait_for("/shared/pki/root_ca.crt"),
            'BB="$(command -v blackbox_exporter || command -v prometheus-blackbox-exporter)"',
            'nohup "$BB" --config.file=/pp/blackbox.yml --web.listen-address=127.0.0.1:9115 >/tmp/blackbox.log 2>&1 &',
            "nohup prometheus --config.file=/pp/prometheus.yml --storage.tsdb.path=/tmp/prom "
            "--web.listen-address=127.0.0.1:9090 >/tmp/prometheus.log 2>&1 &",
            # Grafana: no admin account, anonymous read-only, localhost only, provisioned from /pp.
            "mkdir -p /tmp/grafana/log /tmp/grafana/plugins",
            'if command -v grafana >/dev/null; then GF="grafana server"; else GF="grafana-server"; fi',
            "nohup $GF --homepath /usr/share/grafana --config /pp/grafana.ini >/tmp/grafana.log 2>&1 &",
        ]
    # Ready means the service answers, not that it was started in the background.
    lines += [_wait_for_port(p) for p in READY_PORTS.get(role, [])]
    lines += ["touch /tmp/pp-ready"]
    return "\n".join(lines) + "\n", files


# Local ports each role must answer on before the host writes /tmp/pp-ready.
READY_PORTS = {"app": [8080], "db": [5432], "outside": [80, 443, 4444], "monitor": [9115, 9090, 3000]}


def unbound_conf(net: Network) -> str:
    dns = net.data["dns"]
    acl = ["    access-control: 0.0.0.0/0 refuse", "    access-control: 127.0.0.0/8 allow"]
    acl += [f"    access-control: {net.zones[z]['prefix']} allow" for z in dns["recursion_for"]]
    acl += [f"    access-control: {net.zones[z]['prefix']} refuse_non_local" for z in dns["local_only_for"]]
    data = [f'    local-data: "{name}. {ZONE_TTL} IN A {addr}"' for name, addr in inside_records(net).items()]
    fwd = []
    for zone, addr in dns["forwarders"].items():
        fwd += [f'    local-zone: "{zone}." transparent']
    out = [
        "# Rendered by packetproof: the recursive resolver (inside view of split-horizon DNS).",
        "server:",
        "    interface: 0.0.0.0",
        "    do-ip6: no",
        '    username: ""',
        '    chroot: ""',
        '    directory: "/tmp"',
        '    pidfile: "/tmp/unbound.pid"',
        "    use-syslog: no",
        '    logfile: "/tmp/unbound.log"',
        "    log-queries: yes",
        '    module-config: "iterator"',
    ] + acl + [
        "    # Only inside data and the lab's internet zones exist; everything else is refused,",
        "    # so the resolver never goes looking for real root servers.",
        '    local-zone: "." refuse',
        f'    local-zone: "{dns["zone"]}." static',
    ] + fwd + data
    for zone, addr in dns["forwarders"].items():
        out += ["forward-zone:", f'    name: "{zone}."', f"    forward-addr: {addr}"]
    return "\n".join(out) + "\n"


NSD_CONF = """\
# Rendered by packetproof: the authoritative server for the outside view.
server:
    ip-address: 0.0.0.0
    port: 53
    username: ""
    chroot: ""
    zonesdir: "/pp"
    pidfile: "/tmp/nsd.pid"
    xfrdfile: "/tmp/nsd-xfrd.state"
    zonelistfile: "/tmp/nsd-zone.list"
    logfile: "/tmp/nsd.log"
    verbosity: 1
remote-control:
    control-enable: no
zone:
    name: "{zone}"
    zonefile: "{zone}.zone"
"""


def outside_zone(net: Network) -> str:
    dns = net.data["dns"]
    zone = dns["zone"]
    lines = [f"$ORIGIN {zone}.", f"$TTL {ZONE_TTL}",
             f"@ IN SOA ns1.{zone}. hostmaster.{zone}. 1 3600 600 86400 {ZONE_TTL}",
             f"@ IN NS ns1.{zone}."]
    for label, target in dns["outside"].items():
        lines.append(f"{label} IN A {net.resolve_dns_target(target)}")
    return "\n".join(lines) + "\n"


def ca_lines(net: Network) -> list[str]:
    ca = net.hosts[net.data["pki"]["ca"]]
    port = net.data["pki"]["port"]
    zone = net.data["dns"]["zone"]
    return [
        STEP,
        "export STEPPATH=/tmp/step",
        "umask 077",
        "head -c 32 /dev/urandom | base64 > /tmp/step-pw",
        # In prod the long-lived root comes from SOPS (mounted at /pp-secrets), so every rebuild
        # keeps the same trust anchor; a pull-request lab gets a fresh root each time.
        'ROOT=""; [ -s /pp-secrets/root_ca.key ] && ROOT="--root /pp-secrets/root_ca.crt --key /pp-secrets/root_ca.key"',
        f'"$STEP" ca init --deployment-type standalone --name "PacketProof Lab CA" --dns ca.{zone} '
        f"--dns {ca['address']} --address :{port} --provisioner admin --password-file /tmp/step-pw "
        "--provisioner-password-file /tmp/step-pw --acme $ROOT",
        "nohup step-ca /tmp/step/config/ca.json --password-file /tmp/step-pw >/tmp/step-ca.log 2>&1 &",
        "umask 022",
        "mkdir -p /shared/pki/test",
        # Test certificates for Gate 2's refusal checks: expired, and issued by a CA nobody trusts.
        f'"$STEP" certificate create www.{zone} /shared/pki/test/expired.crt /shared/pki/test/expired.key '
        "--profile leaf --ca /tmp/step/certs/intermediate_ca.crt --ca-key /tmp/step/secrets/intermediate_ca_key "
        "--ca-password-file /tmp/step-pw --not-before=-48h --not-after=-24h --no-password --insecure --bundle",
        f'"$STEP" certificate create "Untrusted Root" /tmp/untrusted-root.crt /tmp/untrusted-root.key '
        "--profile root-ca --no-password --insecure",
        f'"$STEP" certificate create www.{zone} /shared/pki/test/untrusted.crt /shared/pki/test/untrusted.key '
        "--profile leaf --ca /tmp/untrusted-root.crt --ca-key /tmp/untrusted-root.key --no-password --insecure",
        "cat /shared/pki/test/expired.crt /shared/pki/test/expired.key > /shared/pki/test/expired.pem",
        "cp /tmp/step/certs/intermediate_ca.crt /shared/pki/intermediate_ca.crt",
        "chmod 0644 /shared/pki/test/*",
        # Publishing the root last tells everyone else the CA is ready.
        _wait_for_port(port),
        "cp /tmp/step/certs/root_ca.crt /shared/pki/root_ca.crt.tmp && mv /shared/pki/root_ca.crt.tmp /shared/pki/root_ca.crt",
    ]


def _wait_for_port(port: int) -> str:
    probe = f"import socket; socket.create_connection(('127.0.0.1', {port}), 1)"
    return f'i=0; while ! python3 -c "{probe}" 2>/dev/null; do i=$((i+1)); [ $i -gt 120 ] && exit 1; sleep 0.5; done'


def proxy_lines(net: Network, host: dict) -> list[str]:
    zone = net.data["dns"]["zone"]
    port = net.data["pki"]["port"]
    names = next(c["names"] for c in net.data["pki"]["certificates"] if c["host"] == host["name"])
    sans = " ".join(f"--san {n}" for n in names)
    return [
        STEP,
        _wait_for("/shared/pki/root_ca.crt"),
        "mkdir -p /tmp/pp-certs",
        # ACME (HTTP-01) from the lab CA: step-ca connects back to port 80 here to validate.
        f'i=0; until "$STEP" ca certificate {names[0]} /tmp/pp-certs/www.crt /tmp/pp-certs/www.key {sans} '
        f"--provisioner acme --ca-url https://ca.{zone}:{port} --root /shared/pki/root_ca.crt "
        "--standalone --http-listen :80 --force; do i=$((i+1)); [ $i -gt 20 ] && exit 1; sleep 3; done",
        "cat /tmp/pp-certs/www.crt /tmp/pp-certs/www.key > /tmp/pp-certs/www.pem",
        "haproxy -D -f /pp/haproxy.cfg",
    ]


def haproxy_cfg(net: Network) -> str:
    p = net.data["proxy"]
    hc = p.get("health_check")
    out = [
        "# Rendered by packetproof: TLS terminates here; two app backends behind health checks.",
        "global",
        "    pidfile /tmp/haproxy.pid",
        "defaults",
        "    mode http",
        "    timeout connect 3s",
        "    timeout client 10s",
        "    timeout server 10s",
        "frontend fe_https",
        f"    bind :{p['listen']} ssl crt /tmp/pp-certs/www.pem",
        "    default_backend be_app",
        "backend be_app",
        "    balance roundrobin",
    ]
    if hc:
        out.append(f"    option httpchk GET {hc['path']}")
    for b in p["backends"]:
        check = f" check inter {hc['inter_ms']} fall {hc['fall']} rise {hc['rise']}" if hc else ""
        out.append(f"    server {b['host']} {net.host_address(b['host'])}:{b['port']}{check}")
    return "\n".join(out) + "\n"


BLACKBOX_YML = """\
# Rendered by packetproof: what "healthy" means to the monitor.
modules:
  https_2xx:
    prober: http
    timeout: 5s
    http:
      valid_status_codes: [200]
      fail_if_not_ssl: true
      tls_config:
        ca_file: /shared/pki/root_ca.crt
  tls_connect:
    prober: tcp
    timeout: 5s
    tcp:
      tls: true
      tls_config:
        ca_file: /shared/pki/root_ca.crt
  dns_a:
    prober: dns
    timeout: 5s
    dns:
      transport_protocol: udp
      query_name: www.packetproof.example
      query_type: A
      valid_rcodes: [NOERROR]
"""


GRAFANA_INI = """\
; Rendered by packetproof: a read-only Grafana for the lab, reachable only from the monitor host.
[paths]
data = /tmp/grafana
logs = /tmp/grafana/log
plugins = /tmp/grafana/plugins
provisioning = /pp/grafana
[server]
http_addr = 127.0.0.1
http_port = 3000
[security]
disable_initial_admin_creation = true
[auth]
disable_login_form = true
[auth.anonymous]
enabled = true
org_role = Viewer
[analytics]
reporting_enabled = false
check_for_updates = false
check_for_plugin_updates = false
[news]
news_feed_enabled = false
"""

GRAFANA_DATASOURCE = """\
apiVersion: 1
datasources:
  - name: Prometheus
    uid: prometheus
    type: prometheus
    access: proxy
    url: http://127.0.0.1:9090
    isDefault: true
"""

GRAFANA_PROVIDER = """\
apiVersion: 1
providers:
  - name: packetproof
    type: file
    disableDeletion: true
    options:
      path: /pp/grafana/dashboards/json
"""


def grafana_dashboard() -> str:
    ds = {"type": "prometheus", "uid": "prometheus"}

    def panel(kind, title, expr, x, y, w, legend="{{job}}", unit=None):
        p = {"type": kind, "title": title, "datasource": ds, "gridPos": {"x": x, "y": y, "w": w, "h": 7},
             "targets": [{"refId": "A", "datasource": ds, "expr": expr, "legendFormat": legend}]}
        if unit:
            p["fieldConfig"] = {"defaults": {"unit": unit}, "overrides": []}
        return p

    dash = {
        "uid": "packetproof-probes", "title": "PacketProof probes", "schemaVersion": 39, "version": 1,
        "refresh": "5s", "time": {"from": "now-15m", "to": "now"}, "tags": ["packetproof"],
        "panels": [
            panel("stat", "Probe success (1 = up)", "probe_success", 0, 0, 12),
            panel("stat", "Hours until the www certificate expires",
                  '(probe_ssl_earliest_cert_expiry{job="www-tls-expiry"} - time()) / 3600', 12, 0, 12, "hours", "h"),
            panel("timeseries", "Probe duration", "probe_duration_seconds", 0, 7, 24, unit="s"),
        ],
    }
    return json.dumps(dash, indent=2) + "\n"


def grafana_files() -> dict[str, str]:
    return {"grafana.ini": GRAFANA_INI,
            "grafana/datasources/prometheus.yaml": GRAFANA_DATASOURCE,
            "grafana/dashboards/packetproof.yaml": GRAFANA_PROVIDER,
            "grafana/dashboards/json/packetproof.json": grafana_dashboard()}


def prometheus_yml(net: Network) -> str:
    module = {"http": "https_2xx", "tls": "tls_connect", "dns": "dns_a"}
    jobs = ["# Rendered by packetproof: scrape the blackbox exporter for each probe.",
            "global:", "  scrape_interval: 5s", "scrape_configs:"]
    for pr in net.data["monitoring"]["probes"]:
        jobs += [
            f"  - job_name: {pr['name']}",
            "    metrics_path: /probe",
            f"    params: {{module: [{module[pr['kind']]}]}}",
            "    static_configs:",
            f"      - targets: ['{pr['target']}']",
            "    relabel_configs:",
            "      - source_labels: [__address__]",
            "        target_label: __param_target",
            "      - source_labels: [__param_target]",
            "        target_label: instance",
            "      - target_label: __address__",
            "        replacement: 127.0.0.1:9115",
        ]
    return "\n".join(jobs) + "\n"


def is_private(addr: str) -> bool:
    return ipaddress.ip_address(addr) in ipaddress.ip_network("172.16.0.0/12")
