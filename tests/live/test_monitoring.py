"""A small blackbox monitor: HTTPS, TLS expiry and DNS probes from LAN-A, as an operator sees them."""

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
    res = _query(lab, 'probe_ssl_earliest_cert_expiry{job="www-tls-expiry"} - time()')
    assert res, "no TLS expiry metric"
    seconds = float(res[0]["value"][1])
    assert 0 < seconds <= 25 * 3600, f"certificate expires in {seconds} s"
