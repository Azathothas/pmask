#!/usr/bin/env python3
"""Re-run the 2025 process-concealment survey queries.

All requests go through the pkgforge services. The script writes one JSON
object per result with the query that produced it, so an empty result is
visible as a missing line rather than a zero.

Usage:
    python3 search.py repo --out repo.jsonl
    python3 search.py code --out code.jsonl
    python3 search.py web  --out web.jsonl

The full run takes about two hours at the observed rate limits. Use
--limit to try a single query first.
"""

import argparse
import json
import pathlib
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
FORGE = "https://forge.web.pkgforge.dev/github/search"
WEB = "https://search.web.pkgforge.dev/search"
SLEEP = {"repo": 2.3, "code": 7.0, "web": 1.2}


def get(url):
    req = urllib.request.Request(url, headers={"accept": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)


def repo_query(q):
    url = f"{FORGE}/repositories?" + urllib.parse.urlencode(
        {"q": q, "per_page": 100, "sort": "stars"}
    )
    d = get(url)
    for it in d.get("items", []):
        yield {
            "query": q,
            "full_name": it.get("full_name"),
            "created_at": it.get("created_at"),
            "description": it.get("description"),
            "stars": it.get("stargazers_count"),
            "html_url": it.get("html_url"),
        }


def code_query(q):
    url = f"{FORGE}/code?" + urllib.parse.urlencode({"q": q, "per_page": 100})
    d = get(url)
    for it in d.get("items", []):
        yield {
            "query": q,
            "repo": it.get("repository", {}).get("full_name"),
            "path": it.get("path"),
            "html_url": it.get("html_url"),
        }


def web_query(q):
    url = f"{WEB}?" + urllib.parse.urlencode({"q": q, "count": "10"})
    d = get(url)
    for it in d.get("results", []):
        yield {
            "query": q,
            "url": it.get("url"),
            "title": it.get("title"),
            "snippet": it.get("snippet"),
        }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("kind", choices=["repo", "code", "web"])
    ap.add_argument("--out", required=True)
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    queries = json.loads((HERE / "queries.json").read_text(encoding="utf-8"))
    key = {"repo": "repo_queries", "code": "code_queries", "web": "web_queries"}[args.kind]
    qs = queries[key]
    if args.kind == "repo":
        qs = qs + queries["manual_repo_queries"]
    if args.limit:
        qs = qs[: args.limit]

    run = {"repo": repo_query, "code": code_query, "web": web_query}[args.kind]
    with open(args.out, "a", encoding="utf-8") as f:
        for i, q in enumerate(qs, 1):
            try:
                rows = list(run(q))
            except (urllib.error.URLError, json.JSONDecodeError) as e:
                print(f"ERR {q!r}: {e}", file=sys.stderr)
                time.sleep(5)
                continue
            for row in rows:
                f.write(json.dumps(row, ensure_ascii=False) + "\n")
            f.flush()
            print(f"{i}/{len(qs)} {q!r} {len(rows)}", file=sys.stderr, flush=True)
            time.sleep(SLEEP[args.kind])


if __name__ == "__main__":
    main()
