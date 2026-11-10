"""Gate 3's grading (docs/method.md part 6 and amendment A2): a tool, harness or runner failure in
a fault's own job is "could not judge" (void, re-run), never a catch."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from packetproof.model import ROOT

COLLECT = ROOT / "gate3" / "collect.py"
SCORECARD = ROOT / "gate3" / "scorecard.py"

PASSING_GATE2 = '<testsuites><testsuite><testcase classname="t" name="test_ok"/></testsuite></testsuites>'


def collect(tmp: Path, *, render=None, gate1=None, gate2=None, deploy=None) -> dict:
    args = [sys.executable, str(COLLECT), "--id", "F99", "--gate1", str(tmp / "g1.json"),
            "--gate2", str(tmp / "g2.xml"), "--render-status", str(tmp / "render.json"),
            "--deploy", str(tmp / "deploy.json"), "--out", str(tmp / "out.json")]
    for name, value in (("render.json", render), ("g1.json", gate1), ("deploy.json", deploy)):
        if value is not None:
            (tmp / name).write_text(json.dumps(value))
    if gate2 is not None:
        (tmp / "g2.xml").write_text(gate2)
    subprocess.run(args, check=True, capture_output=True)
    return json.loads((tmp / "out.json").read_text())


OK = {"result": "ok"}


def gate1(*checks):
    return {"passed": all(c["ok"] for c in checks), "checks": list(checks)}


def test_batfish_crash_alone_is_not_a_catch(tmp_path):
    r = collect(tmp_path, render=OK, deploy={"deploy_rc": 0}, gate2=PASSING_GATE2,
                gate1=gate1({"name": "conftest-intent", "ok": True, "details": []},
                            {"name": "batfish", "ok": False, "tool_error": True, "details": ["error: connection refused"]}))
    assert r["gate1"]["passed"] is None and r["gate1"]["tool_errors"]


def test_real_failure_next_to_a_tool_error_is_a_catch(tmp_path):
    r = collect(tmp_path, render=OK, deploy={"deploy_rc": 0}, gate2=PASSING_GATE2,
                gate1=gate1({"name": "conftest-intent", "ok": False, "details": ["INV-01: hole"]},
                            {"name": "batfish", "ok": False, "tool_error": True, "details": ["error: x"]}))
    assert r["gate1"]["passed"] is False and r["gate1"]["failing"] == ["conftest-intent:INV-01: hole"]


def test_a_fault_that_cannot_be_planted_is_not_a_catch(tmp_path):
    r = collect(tmp_path, render={"result": "crashed", "detail": "pattern found 0 times"})
    assert r["gate1"]["passed"] is None and r["gate2"]["passed"] is None


def test_an_intent_the_generator_rejects_is_a_gate1_catch(tmp_path):
    r = collect(tmp_path, render={"result": "rejected", "detail": "'x' is not valid"})
    assert r["gate1"]["passed"] is False and r["gate2"]["passed"] is None


def test_missing_results_are_not_catches(tmp_path):
    r = collect(tmp_path, render=OK)
    assert r["gate1"]["passed"] is None and r["gate2"]["passed"] is None


def test_a_lab_that_did_not_deploy_is_not_a_gate2_catch(tmp_path):
    r = collect(tmp_path, render=OK, gate1=gate1({"name": "batfish", "ok": True, "details": []}),
                deploy={"deploy_rc": 1}, gate2=PASSING_GATE2)
    assert r["gate2"]["passed"] is None


def test_every_test_erroring_is_the_harness_not_the_network(tmp_path):
    xml = ('<testsuites><testsuite><testcase classname="t" name="a"><error message="docker gone"/></testcase>'
           '<testcase classname="t" name="b"><error message="docker gone"/></testcase></testsuite></testsuites>')
    r = collect(tmp_path, render=OK, gate1=gate1({"name": "batfish", "ok": True, "details": []}),
                deploy={"deploy_rc": 0}, gate2=xml)
    assert r["gate2"]["passed"] is None


def _write_run(tmp: Path, fault: dict, aps: int = 12) -> Path:
    res = tmp / "results"
    res.mkdir()
    base = {"id": "baseline", "gate1": {"passed": True, "failing": []}, "gate2": {"passed": True, "failing": [], "tests": 1}}
    (res / "baseline.json").write_text(json.dumps(base))
    (res / "F01.json").write_text(json.dumps(fault))
    names = ["test_ap01_scan_db_zone", "test_ap02_direct_db_connection", "test_ap03_lateral_ssh_to_app",
             "test_ap04_scan_lan_a", "test_ap05_ssh_to_router_dmz_gateway", "test_ap06_ssh_to_router_other_addresses",
             "test_ap07_ssh_to_rtr_b_across_tunnel", "test_ap08_scan_lan_b_across_tunnel", "test_ap09_outbound_to_outside",
             "test_ap10_dns_exfiltration_through_resolver", "test_ap11_dns_direct_to_outside",
             "test_ap12_spoofed_source_into_db"][:aps]
    cases = "".join(f'<testcase classname="test_attacks" name="{n}"/>' for n in names)
    (res / "baseline-gate2.xml").write_text(f"<testsuites><testsuite>{cases}</testsuite></testsuites>")
    return res


def _score(tmp: Path, res: Path) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(SCORECARD), "--results", str(res), "--out", str(tmp / "site")],
                          capture_output=True, text=True)


def test_scorecard_voids_a_fault_a_gate_could_not_judge(tmp_path):
    fault = {"id": "F01", "gate1": {"passed": None, "failing": ["not judged: a Gate 1 tool failed"], "tool_errors": ["batfish:error: x"]},
             "gate2": {"passed": True, "failing": [], "tests": 1}}
    res = _write_run(tmp_path, fault)
    assert _score(tmp_path, res).returncode == 0
    card = json.loads((tmp_path / "site" / "scorecard.json").read_text())
    f01 = next(f for f in card["faults"] if f["id"] == "F01")
    assert f01["verdict"] == "void" and card["summary"]["first_caught_by_gate1"] == 0
    assert card["summary"]["void"] == 1


def test_scorecard_refuses_to_publish_without_all_attack_paths(tmp_path):
    fault = {"id": "F01", "gate1": {"passed": False, "failing": ["batfish:x"]}, "gate2": {"passed": True, "failing": [], "tests": 1}}
    res = _write_run(tmp_path, fault, aps=11)
    out = _score(tmp_path, res)
    assert out.returncode != 0 and "11 of 12" in (out.stdout + out.stderr)


@pytest.mark.parametrize("message,verdict", [("legitimate pair failed: x", "invalid"),
                                             ("RuntimeError: probe dmz->x did not run", "not run"),
                                             ("AssertionError: open ports", "open")])
def test_attack_path_failures_are_classified(tmp_path, message, verdict):
    sys.path.insert(0, str(ROOT / "gate3"))
    import scorecard

    xml = tmp_path / "b.xml"
    xml.write_text('<testsuites><testsuite><testcase classname="test_attacks" name="test_ap02_direct_db_connection">'
                   f'<failure message="{message}"/></testcase></testsuite></testsuites>')
    with pytest.raises(SystemExit):  # one of 12: refused, but the classification is checked first
        scorecard.attack_paths(xml)
    full = tmp_path / "full.xml"
    cases = "".join(f'<testcase classname="test_attacks" name="{n}"/>' for n in scorecard.AP_NAMES if n != "test_ap02_direct_db_connection")
    full.write_text('<testsuites><testsuite>' + cases + '<testcase classname="test_attacks" name="test_ap02_direct_db_connection">'
                    f'<failure message="{message}"/></testcase></testsuite></testsuites>')
    ap02 = next(x for x in scorecard.attack_paths(full) if x["id"] == "AP-02")
    assert ap02["verdict"] == verdict and ap02["legitimate_pair"] == "app2 connects to db 5432"
