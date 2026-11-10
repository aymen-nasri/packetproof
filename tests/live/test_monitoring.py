"""A small blackbox monitor: HTTPS, TLS expiry and DNS probes from LAN-A, as an operator sees them,
in Prometheus and through Grafana."""

import json
import time

JOBS = {"www-https", "www-tls-expiry", "dns-www"}


def _query(lab, expr: str) -> list[dict]:
    out = lab.sh("mon", f"curl -sS --max-time 5 -G http://127.0.0.1:9090/api/v1/query --data-urlencode 'query={expr}'").stdout
    try:
        return json.loads(out)["data"]["result"]
    except (ValueError, KeyError):
        return []


def test_every_probe_succeeds(lab):
    deadline = time.time() + 60
    results = {}
    while time.time() < deadline:
        results = {r["metric"].get("job"): r["value"][1] for r in _query(lab, "probe_success")}
        if JOBS <= set(results) and all(results[j] == "1" for j in JOBS):
            return
        time.sleep(5)
    raise AssertionError(f"probe_success by job: {results}")


def test_certificate_expiry_is_visible(lab):
    deadline = time.time() + 60
    res = []
    while time.time() < deadline and not res:  # no reliance on an earlier test having waited
        res = _query(lab, 'probe_ssl_earliest_cert_expiry{job="www-tls-expiry"} - time()')
        if not res:
            time.sleep(5)
    assert res, "no TLS expiry metric"
    seconds = float(res[0]["value"][1])
    assert 0 < seconds <= 25 * 3600, f"certificate expires in {seconds} s"


def _grafana(lab, path: str, body: str | None = None) -> dict:
    data = f"-H 'Content-Type: application/json' --data '{body}'" if body else ""
    out = lab.sh("mon", f"curl -sS --max-time 5 {data} http://127.0.0.1:3000{path}").stdout
    try:
        return json.loads(out)
    except ValueError:
        return {"raw": out[-300:]}


def test_grafana_serves_the_probe_dashboard(lab):
    deadline = time.time() + 90
    health = {}
    while time.time() < deadline:
        health = _grafana(lab, "/api/health")
        if health.get("database") == "ok":
            break
        time.sleep(3)
    assert health.get("database") == "ok", health
    dash = _grafana(lab, "/api/dashboards/uid/packetproof-probes")
    assert dash.get("dashboard", {}).get("title") == "PacketProof probes", dash


def test_grafana_reads_the_probes_through_prometheus(lab):
    """The whole chain: blackbox exporter -> Prometheus -> Grafana's data source, as a viewer sees it."""
    query = json.dumps({"from": "now-5m", "to": "now", "queries": [
        {"refId": "A", "datasource": {"type": "prometheus", "uid": "prometheus"}, "expr": "probe_success",
         "instant": True}]})
    deadline = time.time() + 60
    values = []
    while time.time() < deadline:
        res = _grafana(lab, "/api/ds/query", query)
        frames = res.get("results", {}).get("A", {}).get("frames", [])
        values = [v for f in frames for v in (f.get("data", {}).get("values") or [[], []])[-1]]
        if len(values) >= 3:
            break
        time.sleep(3)
    assert len(values) >= 3 and all(v == 1 for v in values), f"probe_success through Grafana: {values}"
