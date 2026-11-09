"""Every node finished its start script. A node that did not is reported with its log."""

import pytest

NODES = ["rtr-a", "rtr-b", "isp", "client-a", "admin", "mon", "haproxy", "ns1", "app1", "app2", "db",
         "resolver", "ca", "client-b", "outside"]


@pytest.mark.parametrize("node", NODES)
def test_node_ready(lab, node):
    ready = lab.sh(node, "test -f /tmp/pp-ready").returncode == 0
    log = "" if ready else lab.sh(node, "tail -n 25 /tmp/pp-start.log /tmp/pp-up.log 2>/dev/null").stdout
    assert ready, f"{node} did not finish starting:\n{log}"
