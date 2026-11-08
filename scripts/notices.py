#!/usr/bin/env python3
"""Write THIRD_PARTY_NOTICES.md from cargo metadata.

The table lists every crate linked into the binaries, its version, its
SPDX license and its repository. `--check` compares the committed file
with a fresh generation and exits 1 when it is stale.
"""
import json
import pathlib
import subprocess
import sys


def metadata():
    out = subprocess.check_output(
        ["cargo", "metadata", "--locked", "--format-version", "1"]
    )
    return json.loads(out)


def main():
    meta = metadata()
    pkgs = {p["id"]: p for p in meta["packages"]}
    root = next(p for p in meta["packages"] if p["name"] == "pmask")
    nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}
    seen = set()
    stack = [root["id"]]
    while stack:
        pid = stack.pop()
        if pid in seen:
            continue
        seen.add(pid)
        node = nodes.get(pid)
        if not node:
            continue
        for dep in node["deps"]:
            kinds = dep.get("dep_kinds", [])
            if not kinds or any(k.get("kind") is None for k in kinds):
                stack.append(dep["pkg"])
    rows = []
    for pid in seen:
        p = pkgs.get(pid)
        if not p or p["name"] == "pmask":
            continue
        rows.append(
            (
                p["name"],
                p["version"],
                p.get("license") or "unknown",
                p.get("repository") or "",
            )
        )
    rows.sort()
    lines = [
        "# Third-party notices",
        "",
        "pmask is 0BSD. The crates below are linked into the binaries and are",
        "distributed under their own licenses. `cargo deny` enforces the",
        "allowlist in `deny.toml`.",
        "",
        "| crate | version | license | repository |",
        "| --- | --- | --- | --- |",
    ]
    for name, version, license, repo in rows:
        lines.append(f"| `{name}` | {version} | {license} | {repo} |")
    lines.append("")
    text = "\n".join(lines)
    target = pathlib.Path("THIRD_PARTY_NOTICES.md")
    if "--check" in sys.argv:
        if not target.exists() or target.read_text() != text:
            print(
                "THIRD_PARTY_NOTICES.md is stale; run python3 scripts/notices.py",
                file=sys.stderr,
            )
            return 1
        return 0
    target.write_text(text)
    print(f"wrote {target} ({len(rows)} crates)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
