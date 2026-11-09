"""TLS and the private CA (INV-10): the proxy's certificate is from the lab CA, valid now, for the
right name and short-lived; and clients refuse a wrong name, an expired certificate and an
untrusted issuer."""

import re
from datetime import datetime, timedelta

from expect import HAPROXY, ZONE

ROOT = "/shared/pki/root_ca.crt"


def test_https_through_the_proxy(lab):
    res = lab.curl("client-a", f"https://www.{ZONE}/")
    assert res.returncode == 0 and re.match(r"app[12] saw " + re.escape(HAPROXY), res.stdout), res.stdout + res.stderr


def test_served_certificate(lab):
    out = lab.sh("client-a", f"echo | openssl s_client -connect {HAPROXY}:443 -servername www.{ZONE} 2>/dev/null "
                             "| openssl x509 -noout -issuer -ext subjectAltName -startdate -enddate").stdout
    assert f"DNS:www.{ZONE}" in out, out
    assert "PacketProof Lab CA" in out, out
    fmt = "%b %d %H:%M:%S %Y %Z"
    start = datetime.strptime(re.search(r"notBefore=(.+)", out).group(1).replace("  ", " "), fmt)
    end = datetime.strptime(re.search(r"notAfter=(.+)", out).group(1).replace("  ", " "), fmt)
    assert start <= datetime.utcnow() <= end, f"not valid now: {start} .. {end}"
    assert end - start <= timedelta(hours=24, minutes=5), f"not short-lived: {end - start}"


def _verify(lab, connect: str, name: str) -> str:
    return lab.sh("client-a", f"echo | openssl s_client -connect {connect} -servername {name} "
                              f"-verify_hostname {name} -CAfile {ROOT} -verify_return_error 2>&1").stdout


def test_wrong_name_refused(lab):
    out = _verify(lab, f"{HAPROXY}:443", f"wrong.{ZONE}")
    assert "hostname mismatch" in out, out[-600:]


def _serve_and_verify(lab, cert: str, port: int, chain: str = "") -> str:
    chain_opt = f"-cert_chain {chain}" if chain else ""
    lab.bg("client-a", f"timeout 15 openssl s_server -accept 127.0.0.1:{port} -cert /shared/pki/test/{cert}.crt "
                       f"-key /shared/pki/test/{cert}.key {chain_opt} -www")
    lab.sh("client-a", "sleep 2")
    return _verify(lab, f"127.0.0.1:{port}", f"www.{ZONE}")


def test_expired_certificate_refused(lab):
    # Served with the lab intermediate, so the only thing wrong is the date.
    out = _serve_and_verify(lab, "expired", 8443, chain="/shared/pki/intermediate_ca.crt")
    assert "certificate has expired" in out, out[-600:]


def test_untrusted_issuer_refused(lab):
    out = _serve_and_verify(lab, "untrusted", 8444)
    assert "unable to get local issuer certificate" in out, out[-600:]
