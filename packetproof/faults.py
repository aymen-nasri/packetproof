"""Apply one planted fault from faults/faults.yaml (docs/method.md, part 4).

Two kinds of change, matching the method's "Where" column:
  intent   edits the network.yaml data before rendering (what a pull request to the intent does)
  render   edits a rendered file after rendering: the effect of a broken template or a hand-
           edited generated file. Batfish snapshots embed frr.conf, so a frr.conf patch is
           applied to the matching snapshot file too.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from .model import ROOT

FAULTS_FILE = ROOT / "faults" / "faults.yaml"


def load_faults() -> dict[str, dict]:
    return {f["id"]: f for f in yaml.safe_load(FAULTS_FILE.read_text())}


def _select(node, step):
    if isinstance(step, dict):
        (key, value), = step.items()
        for item in node:
            if item.get(key) == value:
                return item
        raise KeyError(f"no item with {key}={value}")
    return node[step]


def apply_intent(data: dict, fault: dict) -> dict:
    for op in fault.get("intent", []):
        *parents, last = op["path"]
        node = data
        for step in parents:
            node = _select(node, step)
        if op["op"] == "set":
            node[last] = op["value"]
        elif op["op"] == "append":
            _select(node, last).append(op["value"])
        elif op["op"] == "remove":
            target = node[last] if not isinstance(last, dict) else None
            if isinstance(last, dict):
                node.remove(_select(node, last))
            elif isinstance(node, dict):
                del node[last]
            else:
                node.remove(target)
        else:
            raise ValueError(op["op"])
    return data


def apply_render(render_dir: Path, fault: dict) -> None:
    for patch in fault.get("render", []):
        files = [render_dir / patch["file"]]
        if patch["file"].startswith("routers/") and patch["file"].endswith("/frr.conf"):
            router = patch["file"].split("/")[1]
            files.append(render_dir / "batfish" / "configs" / f"{router}.cfg")
        for f in files:
            text = f.read_text()
            if text.count(patch["find"]) != 1:
                raise ValueError(f"{fault['id']}: pattern found {text.count(patch['find'])} times in {f}")
            f.write_text(text.replace(patch["find"], patch["replace"]), newline="\n")
