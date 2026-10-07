#!/usr/bin/env python3
"""Verify the curated repository.

Offline checks (default):
  - checksums.json matches every mirrored file and index
  - no untracked files inside managed output dirs
  - index schema + trust policy re-applied to every entry
  - every URL that points at this repository maps to a file that exists locally

Online checks (--online):
  - every external URL (allowlisted upstream repos/CDNs) returns HTTP 200

Exit code 0 = clean, 1 = problems found.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common as C  # noqa: E402

MANAGED_DIRS = ["icon", "apk", "mangayomi", "sora", "cloudstream"]
MANAGED_FILES = ["index.min.json", "checksums.json", "build-report.json"]

errors: list[str] = []
warnings: list[str] = []


def err(msg: str):
    errors.append(msg)


def warn(msg: str):
    warnings.append(msg)


def load(path: str):
    return C.load_json(C.ROOT / path)


# ---------------------------------------------------------------------------

def verify_checksums(checksums: dict, raw_base: str):
    files = checksums.get("files", {})
    if not files:
        err("checksums.json has no files")
        return
    for rel, want in sorted(files.items()):
        p = C.ROOT / rel
        if not p.exists():
            err(f"checksummed file missing: {rel}")
            continue
        got = C.sha256_file(p)
        if got != want:
            err(f"checksum mismatch (tampered or rebuilt without policy?): {rel}")
    # untracked files in managed dirs
    tracked = set(files)
    for d in MANAGED_DIRS:
        base = C.ROOT / d
        if not base.exists():
            continue
        for p in sorted(base.rglob("*")):
            if p.is_file():
                rel = str(p.relative_to(C.ROOT))
                if rel not in tracked:
                    err(f"file present but not in checksums.json: {rel}")


def self_rel(url: str, raw_base: str) -> str | None:
    if raw_base and url.startswith(raw_base + "/"):
        return urllib.parse.unquote(url[len(raw_base) + 1:])
    return None


def check_self_url(url: str, ctx: dict, label: str):
    rel = self_rel(url, ctx["raw_base"])
    if rel is None:
        err(f"{label}: URL not on this repo's raw base and not an approved upstream: {url}")
        return
    if not (C.ROOT / rel).exists():
        err(f"{label}: points at missing local file: {rel}")


def check_reference_url(url: str, domains: dict, label: str, *, executable: bool):
    """External (upstream) URL: must pass the allowlist."""
    ok, reason = C.check_url_allowed(url, domains, executable=executable)
    if not ok:
        err(f"{label}: URL policy violation: {url} ({reason})")
    if C.suspicious_reason(url, domains):
        err(f"{label}: suspicious URL: {url}")


def verify_aniyomi(ctx: dict, domains: dict, report: dict):
    idx = load("index.min.json")
    if not isinstance(idx, list) or not idx:
        err("index.min.json: missing or not a list")
        return
    seen_pkg, seen_apk = set(), set()
    for i, e in enumerate(idx):
        label = f"index.min.json[{i}] {e.get('name', '?')}"
        name = e.get("name", "")
        if not (name.startswith("Aniyomi: ") or name.startswith("Tachiyomi: ")):
            err(f"{label}: missing Aniyomi:/Tachiyomi: prefix")
        pkg = e.get("pkg", "")
        apk = e.get("apk", "")
        if not re.fullmatch(r"[A-Za-z0-9_.]+", pkg or ""):
            err(f"{label}: bad pkg {pkg!r}")
        if not re.fullmatch(r"[A-Za-z0-9._-]+\.apk", apk or ""):
            err(f"{label}: bad apk {apk!r}")
        if pkg in seen_pkg:
            err(f"{label}: duplicate pkg")
        if apk in seen_apk:
            err(f"{label}: duplicate apk filename")
        seen_pkg.add(pkg)
        seen_apk.add(apk)
        if e.get("nsfw") not in (0, False):
            err(f"{label}: nsfw flag set")
        if not isinstance(e.get("sources"), list) or not e["sources"]:
            err(f"{label}: empty sources")
        for s in e.get("sources", []):
            bu = s.get("baseUrl", "")
            if bu and not bu.startswith("https://"):
                err(f"{label}: non-https source baseUrl {bu}")
            if C.suspicious_reason(str(bu), domains):
                err(f"{label}: suspicious source baseUrl {bu}")
        icon = f"{ctx['raw_base']}/icon/{pkg}.png"
        rel = self_rel(icon, ctx["raw_base"])
        if not rel or not (C.ROOT / rel).exists():
            err(f"{label}: mirrored icon missing for {pkg}")
        rel = self_rel(f"{ctx['raw_base']}/apk/{apk}", ctx["raw_base"])
        if not rel or not (C.ROOT / rel).exists():
            err(f"{label}: mirrored apk missing for {apk}")
    r = (report.get("aniyomi") or {})
    got = len(idx)
    expect = (r.get("anime", {}).get("kept", 0) + r.get("manga", {}).get("kept", 0))
    if got != expect:
        err(f"index.min.json has {got} entries but report says {expect} kept")


MANGAYOMI_FILES = {"manga": ("index.json", 0), "anime": ("anime_index.json", 1), "novel": ("novel_index.json", 2)}


def verify_mangayomi(ctx: dict, domains: dict, report: dict):
    for type_key, (fname, itemtype) in MANGAYOMI_FILES.items():
        idx = load(f"mangayomi/{fname}")
        if not isinstance(idx, list):
            err(f"mangayomi/{fname}: not a list")
            continue
        seen_ids = set()
        for i, e in enumerate(idx):
            label = f"mangayomi/{fname}[{i}] {e.get('name', '?')}"
            if e.get("itemType") != itemtype:
                err(f"{label}: itemType {e.get('itemType')} != {itemtype}")
            if e.get("isNsfw"):
                err(f"{label}: nsfw flagged")
            sid = e.get("id")
            if sid in seen_ids:
                err(f"{label}: duplicate id")
            seen_ids.add(sid)
            check_reference_url(str(e.get("sourceCodeUrl", "")), domains, label, executable=True)
            # icons are not executable: any public https host that is not
            # suspicious/private is acceptable (same rule the builder applies)
            icon_url = str(e.get("iconUrl", ""))
            ok_icon, icon_reason = C.is_safe_fetch_target(icon_url, domains)
            if not ok_icon:
                err(f"{label}: iconUrl policy violation: {icon_url} ({icon_reason})")
            if not str(e.get("baseUrl", "")).startswith("http"):
                err(f"{label}: bad baseUrl")
            if C.adult_blocked(str(e.get("name", "")), domains):
                err(f"{label}: adult-name pattern")


def verify_sora(ctx: dict, domains: dict, report: dict):
    idx = load("sora/index.json")
    if not isinstance(idx, list):
        err("sora/index.json: not a list")
        return
    names = set()
    for i, e in enumerate(idx):
        label = f"sora/index.json[{i}] {e.get('sourceName', '?')}"
        if not e.get("sourceName"):
            err(f"{label}: missing sourceName")
            continue
        if e["sourceName"] in names:
            err(f"{label}: duplicate sourceName")
        names.add(e["sourceName"])
        mtype = str(e.get("type", "")).lower()
        if mtype not in {"anime", "movie", "mangas"}:
            err(f"{label}: type {mtype!r} invisible to Dartotsu")
        if e.get("nsfw") is True:
            err(f"{label}: nsfw flag set")
        if not str(e.get("baseUrl", "")).startswith("https://"):
            err(f"{label}: bad baseUrl")
        check_self_url(str(e.get("scriptUrl", "")), ctx, label)
        if e.get("iconUrl"):
            check_self_url(str(e["iconUrl"]), ctx, label)
        auth = e.get("author")
        if isinstance(auth, dict) and auth.get("icon"):
            check_self_url(str(auth["icon"]), ctx, label)
        for field in ("baseUrl", "searchBaseUrl"):
            u = e.get(field)
            if u and C.suspicious_reason(str(u), domains):
                err(f"{label}: suspicious {field}: {u}")


def verify_cloudstream(ctx: dict, domains: dict, report: dict):
    idx = load("cloudstream/repo.json")
    if not isinstance(idx, list):
        err("cloudstream/repo.json: not a list")
        return
    seen = set()
    for i, e in enumerate(idx):
        label = f"cloudstream/repo.json[{i}] {e.get('name', '?')}"
        internal = str(e.get("internalName", "")).lower()
        if not internal:
            err(f"{label}: missing internalName")
            continue
        if internal in seen:
            err(f"{label}: duplicate internalName")
        seen.add(internal)
        if e.get("status") == 0:
            err(f"{label}: status 0 (down)")
        if e.get("price") not in (None, 0, "0"):
            err(f"{label}: paid entry")
        if not e.get("language") and e.get("language") is not None:
            warn(f"{label}: empty language")
        rel = self_rel(str(e.get("url", "")), ctx["raw_base"])
        if not rel:
            err(f"{label}: plugin url not on raw base: {e.get('url')}")
        else:
            p = C.ROOT / rel
            if not p.exists():
                err(f"{label}: mirrored plugin missing: {rel}")
            else:
                ok, why, _ = C.validate_cs3(p.read_bytes())
                if not ok:
                    err(f"{label}: mirrored .cs3 invalid: {why}")
                declared = str(e.get("fileHash") or "")
                if declared.startswith("sha256-"):
                    if C.sha256_file(p) != declared[7:]:
                        err(f"{label}: mirrored .cs3 does not match declared fileHash")
        if e.get("iconUrl"):
            check_self_url(str(e["iconUrl"]), ctx, label)
        for banned in ("jarUrl", "jarFileSize", "jarHash", "updateURL", "pluginUrl"):
            if banned in e:
                err(f"{label}: field {banned} should have been stripped")
        if e.get("repositoryUrl"):
            check_reference_url(str(e["repositoryUrl"]), domains, label, executable=False)
        if C.adult_blocked(" ".join(str(x) for x in [e.get("name"), e.get("description"),
                                                     " ".join(e.get("tvTypes") or [])]), domains):
            err(f"{label}: adult-name pattern")


def collect_external_urls(domains: dict) -> set[str]:
    urls: set[str] = set()
    idx = load("mangayomi/index.json") + load("mangayomi/anime_index.json") + load("mangayomi/novel_index.json")
    for e in idx:
        urls.add(str(e.get("sourceCodeUrl")))
        urls.add(str(e.get("iconUrl")))
    return {u for u in urls if u.startswith("https://")}


def verify_online(domains: dict, jobs: int = 12):
    urls = sorted(collect_external_urls(domains))
    print(f"  checking {len(urls)} external URLs ...")

    def head(u):
        try:
            status, _ = C.fetch(u, binary=True, use_cache=False, timeout=30, retries=1)
            return u, status
        except C.FetchError as e:
            return u, str(e)

    with ThreadPoolExecutor(max_workers=jobs) as ex:
        for u, status in ex.map(head, urls):
            if status == 200:
                continue
            m = re.search(r"HTTP (\d{3})", str(status))
            code = int(m.group(1)) if m else None
            if code in (404, 410):
                # definitive: the file itself is gone
                err(f"external URL dead ({status}): {u}")
            else:
                # environment-dependent (bot-blocks, DNS/geo filtering, TLS,
                # timeouts) - the app or another network may still reach it
                warn(f"external URL not reachable ({status}): {u}")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--online", action="store_true", help="also check external URL liveness")
    ap.add_argument("--jobs", type=int, default=12)
    args = ap.parse_args()

    policy = C.load_policy()
    domains = policy["domains"]
    report = load("build-report.json")
    checksums = load("checksums.json")
    raw_base = report.get("raw_base", "")
    if not raw_base:
        err("build-report.json missing raw_base")
        raw_base = ""
    ctx = {"raw_base": raw_base}

    # build must have been clean
    crit = report.get("critical") or []
    for c in crit:
        err(f"build-report critical: {c}")

    # policy drift since last build
    if report.get("policy_sha256") and report["policy_sha256"] != C.policy_sha256():
        warn("policy files changed since last build - run scripts/build.py to regenerate")

    print("  checksums ...")
    verify_checksums(checksums, raw_base)
    print("  aniyomi index ...")
    verify_aniyomi(ctx, domains, report)
    print("  mangayomi indexes ...")
    verify_mangayomi(ctx, domains, report)
    print("  sora index ...")
    verify_sora(ctx, domains, report)
    print("  cloudstream index ...")
    verify_cloudstream(ctx, domains, report)

    if args.online:
        print("  online liveness ...")
        verify_online(domains, args.jobs)

    for w in warnings:
        print(f"  WARN: {w}")
    for e in errors:
        print(f"  FAIL: {e}")
    print(f"\nverify: {len(errors)} failure(s), {len(warnings)} warning(s)")
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
