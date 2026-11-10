"""The L7 proxy: requests are spread over both backends, and a dead backend is routed around."""

import re
import time

from expect import ZONE


def _backends(lab, n: int = 10) -> list[str]:
    seen = []
    for _ in range(n):
        res = lab.curl("client-a", f"https://www.{ZONE}/", "-f", timeout=5)
        m = re.match(r"(app\d) saw", res.stdout)
        seen.append(m.group(1) if m else f"error:{res.returncode}")
    return seen


def test_round_robin_reaches_both_backends(lab):
    seen = _backends(lab)
    assert {"app1", "app2"} <= set(seen), seen


def test_one_backend_down_is_routed_around(lab):
    lab.sh("app2", "pkill -f pp-app.py")
    try:
        # Health checks run every second and two failures mark app2 down: wait for that, then
        # require ten requests in a row to land on app1.
        seen = []
        for _ in range(15):
            time.sleep(1)
            seen = _backends(lab)
            if all(s == "app1" for s in seen):
                break
        assert all(s == "app1" for s in seen), f"with app2 down: {seen}"
    finally:
        lab.bg("app2", "python3 /usr/local/bin/pp-app.py --name app2 --port 8080 >/tmp/app.log 2>&1")
    for _ in range(15):
        time.sleep(1)
        if "app2" in _backends(lab, 4):
            return
    raise AssertionError("app2 did not come back into rotation")
