#!/usr/bin/env python3
"""Refuse an unmarked `unwrap()` or `expect(` on the secret path.

The four files that carry plaintext or the store are audited: a new
`unwrap` there is a panic in a process that must not panic.  Every
accepted site carries `// unwrap-ok: <reason>` on its own line or on the
line above; the count is printed so a deleted annotation is noticed.
The `#[cfg(test)]` module at the end of each file is not scanned.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FILES = ["src/secret.rs", "src/mem.rs", "src/store.rs", "src/run.rs"]
MARKER = "// unwrap-ok:"
PATTERN = re.compile(r"\.unwrap\(\)|\.expect\(")


def scan(path: Path):
    lines = path.read_text(encoding="utf-8").splitlines()
    end = len(lines)
    for i, line in enumerate(lines):
        if line.strip().startswith("#[cfg(test)]"):
            end = i
            break
    findings = []
    accepted = 0
    for i in range(end):
        if not PATTERN.search(lines[i]):
            continue
        prev = lines[i - 1] if i > 0 else ""
        if MARKER in lines[i] or MARKER in prev:
            accepted += 1
        else:
            findings.append((i + 1, lines[i].strip()))
    return accepted, findings


def main() -> int:
    total = 0
    findings = []
    for rel in FILES:
        path = ROOT / rel
        if not path.exists():
            print(f"unwrap-audit: {rel} is missing", file=sys.stderr)
            return 2
        accepted, found = scan(path)
        total += accepted
        findings.extend((rel, line, text) for line, text in found)
    if findings:
        print(
            f"unwrap-audit: {len(findings)} unmarked site(s) on the secret path",
            file=sys.stderr,
        )
        for rel, line, text in findings:
            print(f"  {rel}:{line}: {text}", file=sys.stderr)
        print(
            "add `// unwrap-ok: <reason>` on the line or the line above, "
            "or remove the unwrap",
            file=sys.stderr,
        )
        return 1
    print(f"unwrap-audit: {total} accepted site(s), no unmarked site")
    return 0


if __name__ == "__main__":
    sys.exit(main())
