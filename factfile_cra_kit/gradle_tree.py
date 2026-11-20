#!/usr/bin/env python3
"""
Parse the output of `gradlew :app:dependencies --configuration <cfg>`.

Why this is separate from static parsing of build.gradle.kts: Gradle resolves
transitive dependencies, substitutes versions under its conflict resolution
rules, and fills in versions managed by platform BOMs. Static parsing sees
none of that and yields only the top level.

Result: instead of the "statutory minimum" you get the actual composition of
what ships in the built artefact.

Line formats that must be understood:
    +--- group:name:1.2.3                       plain
    +--- group:name:1.2.3 -> 2.0.0              version substituted on resolution
    |    \\--- group:name:1.0 -> 2.0 (*)         subtree already shown above
    +--- group:name:1.0 -> 2.0 (c)              version constraint
    +--- group:name (n)                         not resolved
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# each nesting level is exactly five characters: "|    ", "     ", "+--- ", "\--- "
_INDENT = re.compile(r"^(?P<indent>(?:[| ]    )*)(?:\+---|\\---)\s+(?P<body>.*)$")
_COORD = re.compile(
    r"^(?P<group>[A-Za-z0-9_.\-]+):(?P<name>[A-Za-z0-9_.\-]+)"
    r"(?::(?P<requested>[^\s(]+))?"
    r"(?:\s*->\s*(?P<resolved>[^\s(]+))?"
    r"(?P<flags>(?:\s*\((?:\*|c|n)\))*)\s*$"
)


def read_text(path: Path) -> str:
    """PowerShell likes UTF-16 and BOMs — read tolerantly."""
    raw = path.read_bytes()
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16")
    return raw.decode("utf-8-sig", errors="replace")


def parse(path: Path, configuration: str | None = None) -> dict:
    lines = read_text(path).splitlines()

    # locate the configuration block we need
    start = 0
    cfg_name = configuration
    for i, l in enumerate(lines):
        m = re.match(r"^(?P<cfg>\w+)\s+-\s+", l)
        if m and (configuration is None or m.group("cfg") == configuration):
            start, cfg_name = i + 1, m.group("cfg")
            break

    nodes: list[dict] = []
    stack: list[str] = []
    stats = {"omitted": 0, "constraints": 0, "unresolved": 0, "substituted": 0}

    for line in lines[start:]:
        if not line.strip():
            continue
        if re.match(r"^\w+\s+-\s+", line) or line.startswith("("):
            break  # the next configuration block has started
        m = _INDENT.match(line)
        if not m:
            continue
        depth = len(m.group("indent")) // 5
        c = _COORD.match(m.group("body").strip())
        if not c:
            continue

        flags = c.group("flags") or ""
        omitted = "(*)" in flags
        constraint = "(c)" in flags
        unresolved = "(n)" in flags
        if omitted:
            stats["omitted"] += 1
        if constraint:
            stats["constraints"] += 1
        if unresolved:
            stats["unresolved"] += 1

        group, name = c.group("group"), c.group("name")
        requested = c.group("requested")
        resolved = c.group("resolved") or requested
        if c.group("resolved") and requested and c.group("resolved") != requested:
            stats["substituted"] += 1

        ref = f"{group}:{name}"
        stack = stack[:depth]
        parent = stack[-1] if stack else None
        stack.append(ref)

        nodes.append({
            "group": group,
            "name": name,
            "requested": requested,
            "resolved": resolved,
            "depth": depth,
            "parent": parent,
            "omitted": omitted,
            "constraint": constraint,
            "unresolved": unresolved,
        })

    return {"configuration": cfg_name, "nodes": nodes, "stats": stats}


def to_components(parsed: dict) -> list[dict]:
    """Flatten the tree into a list of CycloneDX components."""
    best: dict[str, dict] = {}
    children: dict[str, set[str]] = {}

    for n in parsed["nodes"]:
        if n["unresolved"] or not n["resolved"]:
            continue
        key = f"{n['group']}:{n['name']}"
        prev = best.get(key)
        # depth is what marks a direct dependency: if the component was
        # seen at depth 0, it is direct
        if prev is None:
            best[key] = {
                "group": n["group"], "name": n["name"],
                "version": n["resolved"],
                "direct": n["depth"] == 0,
                "constraint_only": n["constraint"],
            }
        else:
            prev["direct"] = prev["direct"] or n["depth"] == 0
            prev["constraint_only"] = prev["constraint_only"] and n["constraint"]
        if n["parent"]:
            children.setdefault(n["parent"], set()).add(key)

    comps = []
    for key, v in sorted(best.items()):
        # a component seen only as a version constraint does not ship in the
        # artefact — it is a resolution rule, not a dependency
        if v["constraint_only"]:
            continue
        purl = f"pkg:maven/{v['group']}/{v['name']}@{v['version']}"
        comps.append({
            "bom-ref": purl,
            "type": "library",
            "name": key,
            "version": v["version"],
            "purl": purl,
            "scope": "required",
            "properties": [
                {"name": "cra:ecosystem", "value": "gradle"},
                {"name": "cra:direct", "value": "true" if v["direct"] else "false"},
                {"name": "cra:dev", "value": "false"},
                {"name": "cra:resolved-by", "value": "gradle"},
            ],
        })
    return comps


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Parse a Gradle dependency tree into CycloneDX components"
    )
    ap.add_argument("deps", type=Path, help="file containing the output of gradlew :app:dependencies")
    ap.add_argument("--configuration", default=None,
                    help="configuration name, e.g. prodReleaseRuntimeClasspath")
    ap.add_argument("-o", "--out", type=Path, default=None,
                    help="where to save the components as JSON")
    args = ap.parse_args()

    parsed = parse(args.deps, args.configuration)
    comps = to_components(parsed)
    st = parsed["stats"]

    direct = sum(
        1 for c in comps
        if any(p["name"] == "cra:direct" and p["value"] == "true" for p in c["properties"])
    )
    print(f"  Configuration:            {parsed['configuration']}")
    print(f"  Nodes in tree:            {len(parsed['nodes'])}")
    print(f"  Unique components:        {len(comps)}")
    print(f"    direct:                 {direct}")
    print(f"    transitive:             {len(comps) - direct}")
    print(f"  Versions substituted:     {st['substituted']}")
    print(f"  Version constraints:      {st['constraints']}")
    print(f"  Collapsed repeats:        {st['omitted']}")
    if st["unresolved"]:
        print(f"  Unresolved:               {st['unresolved']}  <- needs attention")

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(comps, indent=2, ensure_ascii=False),
                            encoding="utf-8")
        print(f"\n  Written: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
