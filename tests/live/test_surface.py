"""What a host exposes, seen from the host itself with `ss`: the firewall would hide a stray
service from the network, but it would still be there for whoever gets past it."""


def _listeners(lab, node: str) -> set[tuple[str, int]]:
    out = lab.sh(node, "ss -Hltun").stdout
    found = set()
    for line in out.splitlines():
        cols = line.split()
        if len(cols) < 5:
            continue
        addr, _, port = cols[4].rpartition(":")
        addr = addr.split("%")[0]
        if addr.startswith("127.") or addr == "[::1]":
            continue  # loopback only (Docker's embedded DNS listens on 127.0.0.11)
        found.add((cols[0], int(port)))
    return found


def test_db_listens_only_where_the_intent_allows(lab):
    """INV-01 from the inside: the DB host listens on SSH (22, for admin, INV-02) and the database
    (5432) and on nothing else."""
    assert _listeners(lab, "db") == {("tcp", 22), ("tcp", 5432)}
