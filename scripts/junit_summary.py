#!/usr/bin/env python3
"""Turn a pytest JUnit XML file into a short Markdown summary for the Actions job summary."""

import sys
import xml.etree.ElementTree as ET


def main() -> int:
    path, title = sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "Tests"
    root = ET.parse(path).getroot()
    cases = root.iter("testcase")
    passed, failed, skipped = [], [], []
    for c in cases:
        name = f"{c.get('classname', '').split('.')[-1]}::{c.get('name')}"
        if c.find("failure") is not None or c.find("error") is not None:
            node = c.find("failure") if c.find("failure") is not None else c.find("error")
            failed.append((name, (node.get("message") or "").splitlines()[0][:200] if node.get("message") else ""))
        elif c.find("skipped") is not None:
            skipped.append(name)
        else:
            passed.append(name)
    print(f"### {title}: {len(passed)} passed, {len(failed)} failed, {len(skipped)} skipped\n")
    if failed:
        print("| Failed test | Message |\n|---|---|")
        for name, msg in failed:
            print(f"| `{name}` | {msg.replace('|', '/')} |")
    return 0


if __name__ == "__main__":
    sys.exit(main())
