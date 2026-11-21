#!/usr/bin/env python3
"""Official CRS nginx tags that are newer than lua/tests/live/crs-images.txt.

The monthly matrix retests the tags already in that file. This script names
the tags a new upstream release would add:

- the latest multi-arch Debian nginx build of the newest stable CRS v4 and
  of the newest stable CRS v3.3
- the latest multi-arch Debian ``-lts`` build of the newest stable release
  on each minor line the file already tracks with an ``-lts`` tag

A newer build of the current release is included. That is how a new
libmodsecurity shows up on Docker Hub before the next CRS tag. Alpine tags
and tags that are not both linux/amd64 and linux/arm64 are ignored.

Prints one tag per line. ``--json`` prints a JSON array. ``--settle`` drops
a tag whose ``crs-image: <tag>`` issue already has a ``## ✅`` comment, or
three ``## ❌`` comments. ``--self-test`` checks the selection with fixtures
and does not use the network.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import urllib.parse
from pathlib import Path

TAG = re.compile(r"^(\d+\.\d+\.\d+)-nginx-(\d{12})(-lts)?$")
RELEASE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")
ROOT = Path(__file__).resolve().parents[3]
IMAGE_LIST = ROOT / "lua" / "tests" / "live" / "crs-images.txt"
HUB = "https://hub.docker.com/v2/repositories/owasp/modsecurity-crs/tags"
MAX_FAILS = 3


def listed_tags(path: Path) -> set[str]:
    tags = set()
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            tags.add(line)
    return tags


def version_key(version: str) -> tuple[int, int, int]:
    return tuple(int(part) for part in version.split("."))


def stable_versions(tags: list[str], major: int, minor: int | None = None) -> list[str]:
    found = []
    for tag in tags:
        match = RELEASE.match(tag)
        if not match:
            continue
        numbers = tuple(int(part) for part in match.groups())
        if numbers[0] != major:
            continue
        if minor is not None and numbers[1] != minor:
            continue
        found.append(".".join(str(part) for part in numbers))
    return sorted(set(found), key=version_key)


def lts_minors(listed: set[str]) -> set[tuple[int, int]]:
    minors = set()
    for tag in listed:
        match = TAG.match(tag)
        if match and match.group(3):
            major, minor, _patch = match.group(1).split(".")
            minors.add((int(major), int(minor)))
    return minors


def newest(versions: list[str]) -> str | None:
    return versions[-1] if versions else None


def tracked_versions(release_tags: list[str], listed: set[str]) -> list[tuple[str, bool]]:
    """(crs version, lts only) pairs to resolve on Docker Hub."""
    wanted: list[tuple[str, bool]] = []
    current = newest(stable_versions(release_tags, 4))
    lts_33 = newest(stable_versions(release_tags, 3, 3))
    if current:
        wanted.append((current, False))
    if lts_33:
        wanted.append((lts_33, False))
    for major, minor in sorted(lts_minors(listed)):
        version = newest(stable_versions(release_tags, major, minor))
        if version:
            wanted.append((version, True))
    # One entry per version and lts flag.
    seen = set()
    unique = []
    for item in wanted:
        if item not in seen:
            seen.add(item)
            unique.append(item)
    return unique


def latest_build(hub_tags: list[dict], version: str, lts: bool) -> str | None:
    best = None
    for item in hub_tags:
        match = TAG.match(item.get("name") or "")
        if not match or match.group(1) != version:
            continue
        if bool(match.group(3)) != lts:
            continue
        arch = set()
        for image in item.get("images") or []:
            if image.get("os") in (None, "linux"):
                arch.add(image.get("architecture"))
        if "amd64" not in arch or "arm64" not in arch:
            continue
        stamp = match.group(2)
        if best is None or stamp > best[0]:
            best = (stamp, item["name"])
    return None if best is None else best[1]


def listed_stamp(listed: set[str], version: str, lts: bool) -> str | None:
    stamps = []
    for tag in listed:
        match = TAG.match(tag)
        if not match or match.group(1) != version:
            continue
        if bool(match.group(3)) != lts:
            continue
        stamps.append(match.group(2))
    return max(stamps) if stamps else None


def select_new(listed: set[str], release_tags: list[str], hub_by_version: dict[str, list[dict]]) -> list[str]:
    chosen = []
    for version, lts in tracked_versions(release_tags, listed):
        tag = latest_build(hub_by_version.get(version, []), version, lts)
        if tag is None or tag in listed:
            continue
        have = listed_stamp(listed, version, lts)
        stamp = TAG.match(tag).group(2)
        if have is not None and stamp <= have:
            continue
        chosen.append(tag)
    return chosen


def drop_settled(tags: list[str], records: dict[str, tuple[int, int]]) -> list[str]:
    kept = []
    for tag in tags:
        passed, failed = records.get(f"crs-image: {tag}", (0, 0))
        if passed > 0 or failed >= MAX_FAILS:
            continue
        kept.append(tag)
    return kept


def _curl_json(url: str) -> dict | list:
    command = ["curl", "-fsSL", "-A", "crs-new-images", "--max-time", "60", "--retry", "3"]
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if token and url.startswith("https://api.github.com/"):
        command += ["-H", f"Authorization: Bearer {token}", "-H", "Accept: application/vnd.github+json"]
    raw = subprocess.check_output(command + [url], text=True)
    return json.loads(raw)


def fetch_releases(repo: str) -> list[str]:
    tags = []
    page = 1
    while page <= 10:
        url = f"https://api.github.com/repos/{repo}/releases?per_page=100&page={page}"
        batch = _curl_json(url)
        if not isinstance(batch, list) or not batch:
            break
        for item in batch:
            if item.get("draft") or item.get("prerelease"):
                continue
            tag = item.get("tag_name") or ""
            if RELEASE.match(tag):
                tags.append(tag)
        if len(batch) < 100:
            break
        page += 1
    return tags


def fetch_hub(version: str) -> list[dict]:
    query = urllib.parse.urlencode({"page_size": 100, "name": f"{version}-nginx"})
    data = _curl_json(f"{HUB}?{query}")
    return list(data.get("results") or [])


def settled_records(repo: str) -> dict[str, tuple[int, int]]:
    raw = subprocess.check_output(
        [
            "gh", "issue", "list", "--repo", repo, "--state", "all", "--limit", "200",
            "--json", "number,title",
        ],
        text=True,
    )
    records: dict[str, tuple[int, int]] = {}
    for item in json.loads(raw):
        title = item.get("title") or ""
        if not title.startswith("crs-image: "):
            continue
        view = subprocess.check_output(
            ["gh", "issue", "view", str(item["number"]), "--repo", repo, "--json", "comments"],
            text=True,
        )
        comments = json.loads(view).get("comments") or []
        passed = sum(1 for comment in comments if (comment.get("body") or "").startswith("## ✅"))
        failed = sum(1 for comment in comments if (comment.get("body") or "").startswith("## ❌"))
        records[title] = (passed, failed)
    return records


def hub_tag(name: str, arch: list[str]) -> dict:
    return {"name": name, "images": [{"os": "linux", "architecture": item} for item in arch]}


def self_test() -> None:
    listed = {
        "4.30.0-nginx-202610180210",
        "3.3.10-nginx-202609230209",
        "4.25.2-nginx-202610180210-lts",
        "3.3.10-nginx-202610180210-lts",
    }
    releases = ["v4.30.0", "v4.25.2", "v3.3.10", "v4.31.0-rc1", "not-a-release"]
    both = ["amd64", "arm64"]
    hub = {
        "4.30.0": [
            hub_tag("4.30.0-nginx-alpine-202611190211", both),
            hub_tag("4.30.0-nginx-202611190211", both),
            hub_tag("4.30.0-nginx-202611160811", ["amd64"]),
            hub_tag("4.30.0-nginx-202610180210", both),
        ],
        "3.3.10": [
            hub_tag("3.3.10-nginx-202611190211", both),
            hub_tag("3.3.10-nginx-202611190211-lts", both),
            hub_tag("3.3.10-nginx-202610180210-lts", both),
        ],
        "4.25.2": [
            hub_tag("4.25.2-nginx-202611190211-lts", both),
            hub_tag("4.25.2-nginx-202610180210-lts", both),
        ],
    }
    got = select_new(listed, releases, hub)
    want = [
        "4.30.0-nginx-202611190211",
        "3.3.10-nginx-202611190211",
        "3.3.10-nginx-202611190211-lts",
        "4.25.2-nginx-202611190211-lts",
    ]
    if got != want:
        raise SystemExit(f"select_new: {got} != {want}")
    settled = drop_settled(got, {"crs-image: 4.30.0-nginx-202611190211": (1, 0), "crs-image: 3.3.10-nginx-202611190211": (0, 3)})
    if settled != ["3.3.10-nginx-202611190211-lts", "4.25.2-nginx-202611190211-lts"]:
        raise SystemExit(f"drop_settled: {settled}")
    # A brand-new CRS release with no listed tag is kept.
    fresh = select_new(listed, ["v4.31.0", "v4.30.0", "v4.25.2", "v3.3.10"], {
        "4.31.0": [hub_tag("4.31.0-nginx-202612010101", both)],
        "4.30.0": [hub_tag("4.30.0-nginx-202610180210", both)],
        "3.3.10": [hub_tag("3.3.10-nginx-202609230209", both), hub_tag("3.3.10-nginx-202610180210-lts", both)],
        "4.25.2": [hub_tag("4.25.2-nginx-202610180210-lts", both)],
    })
    if fresh != ["4.31.0-nginx-202612010101"]:
        raise SystemExit(f"new release: {fresh}")
    print("new_images.py self-test ok")


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        self_test()
        return 0
    listed = listed_tags(IMAGE_LIST)
    releases = fetch_releases("coreruleset/coreruleset")
    versions = sorted({version for version, _lts in tracked_versions(releases, listed)})
    hub = {version: fetch_hub(version) for version in versions}
    tags = select_new(listed, releases, hub)
    if "--settle" in argv:
        repo = None
        for arg in argv:
            if arg.startswith("--repo="):
                repo = arg.split("=", 1)[1]
        if not repo:
            raise SystemExit("--settle needs --repo=owner/name")
        tags = drop_settled(tags, settled_records(repo))
    if "--json" in argv:
        print(json.dumps(tags))
    else:
        for tag in tags:
            print(tag)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
