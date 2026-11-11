"""The change plan posted on every pull request: `frr version` is not a change."""

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
spec = importlib.util.spec_from_file_location("config_diff", ROOT / "scripts" / "config_diff.py")
config_diff = importlib.util.module_from_spec(spec)
spec.loader.exec_module(config_diff)


def test_a_plan_that_only_adds_the_version_header_is_no_change():
    out = "Lines To Add\n============\nfrr version 10.7.1"
    assert config_diff.clean_plan(out) == ""


def test_real_changes_are_kept_and_the_version_header_is_not():
    out = ("Lines To Delete\n===============\nrouter bgp 65001\n no neighbor 198.51.100.0 shutdown\n\n"
           "Lines To Add\n============\nfrr version 10.7.1\nip prefix-list PL-X seq 5 permit 10.0.0.0/8")
    plan = config_diff.clean_plan(out)
    assert "frr version" not in plan
    assert "Lines To Delete" in plan and "no neighbor 198.51.100.0 shutdown" in plan
    assert "Lines To Add" in plan and "ip prefix-list PL-X seq 5 permit 10.0.0.0/8" in plan


def test_an_empty_section_is_dropped():
    out = "Lines To Delete\n===============\n\nLines To Add\n============\nfrr version 10.7.1\nhostname rtr-z"
    assert config_diff.clean_plan(out) == "Lines To Add\n============\nhostname rtr-z"


def test_output_that_is_not_a_plan_is_left_alone():
    assert config_diff.clean_plan("frr-reload.py failed: something") == "frr-reload.py failed: something"
