"""INV-12: the allow/deny matrix, tested with real connections."""

import pytest

from expect import ALLOWED, DENIED


@pytest.mark.parametrize("src,dst,port,want", ALLOWED, ids=[f"{s}->{d}:{p}" for s, d, p, _ in ALLOWED])
def test_allowed_flow(lab, src, dst, port, want):
    got = lab.tcp(src, dst, port)
    ok = got == "open" if want == "open" else got in ("open", "refused")
    assert ok, f"{src} -> {dst}:{port} should be {want}, got {got}"


@pytest.mark.parametrize("src,dst,port", DENIED, ids=[f"{s}->{d}:{p}" for s, d, p in DENIED])
def test_denied_flow(lab, src, dst, port):
    got = lab.tcp(src, dst, port, timeout=2)
    assert got in ("filtered", "unreachable"), f"{src} -> {dst}:{port} must be dropped, got {got}"
