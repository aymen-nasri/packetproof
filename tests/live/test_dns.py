"""Split-horizon DNS: the resolver's inside view, ns1's outside view, and who may recurse."""

import pytest

from expect import INSIDE_VIEW, OUTSIDE, OUTSIDE_VIEW, PUBLIC, RESOLVER, ZONE


@pytest.mark.parametrize("label", sorted(INSIDE_VIEW))
def test_inside_view_from_lan_a(lab, label):
    status, answers = lab.dig("client-a", RESOLVER, f"{label}.{ZONE}")
    assert answers == [INSIDE_VIEW[label]], f"{label}: {status} {answers}"


def test_inside_view_from_lan_b_across_tunnel(lab):
    status, answers = lab.dig("client-b", RESOLVER, f"www.{ZONE}")
    assert answers == [INSIDE_VIEW["www"]], f"{status} {answers}"


@pytest.mark.parametrize("label", sorted(OUTSIDE_VIEW))
def test_outside_view(lab, label):
    status, answers = lab.dig("outside", PUBLIC, f"{label}.{ZONE}")
    assert answers == [OUTSIDE_VIEW[label]], f"{label}: {status} {answers}"


@pytest.mark.parametrize("label", ["db", "app1", "ca", "admin", "resolver", "haproxy"])
def test_inside_names_hidden_from_outside(lab, label):
    """INV-11."""
    status, answers = lab.dig("outside", PUBLIC, f"{label}.{ZONE}")
    assert status == "NXDOMAIN" and not answers, f"{label}: {status} {answers}"


@pytest.mark.parametrize("src", ["client-a", "client-b", "app1"])
def test_resolver_recurses_for_users_and_app(lab, src):
    status, answers = lab.dig(src, RESOLVER, "www.example.net")
    assert answers == [OUTSIDE], f"{src}: {status} {answers}"


def test_svc_gets_inside_data_but_no_recursion(lab):
    """INV-05: the SVC zone is answered from inside data only."""
    status, answers = lab.dig("ca", RESOLVER, f"www.{ZONE}")
    assert answers == [INSIDE_VIEW["www"]], f"inside data: {status} {answers}"
    status, answers = lab.dig("ca", RESOLVER, "www.example.net")
    assert status == "REFUSED" and not answers, f"recursion: {status} {answers}"
