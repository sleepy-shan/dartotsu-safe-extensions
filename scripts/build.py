#!/usr/bin/env python3
"""Build the curated Dartotsu extension repository.

Pipeline:
  1. Load trust policy (policy/*.json).
  2. For each ecosystem: fetch vetted upstream indexes, filter (NSFW, blocklist,
     adult heuristics, allowlists), mirror binaries (Aniyomi APKs/icons,
     Sora JS/icons, CloudStream .cs3/icons) into this repo, run content checks
     (zip validity, dex host scan, hash pinning).
  3. Emit index files Dartotsu understands, checksums.json, build-report.json.

Stdlib only. Network required. Use --no-cache to refetch.
"""
from __future__ import annotations

import argparse
import io
import json
import os
import re
import shutil
import sys
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common as C  # noqa: E402

SELF_REPO = "sagalang02/dartotsu-safe-extensions"

MANAGED_PATHS = [
    "index.min.json",
    "icon",
    "apk",
    "mangayomi",
    "sora",
    "cloudstream",
    "checksums.json",
    "build-report.json",
]

DEFAULT_MIN_ENTRIES = {
    "aniyomi_anime": 20,
    "aniyomi_manga": 20,
    "mangayomi_manga": 100,
    "mangayomi_anime": 30,
    "mangayomi_novel": 4,
    "sora": 8,
    "cloudstream": 25,
}

KNOWN_FINAL_HOSTS_RAW = {"raw.githubusercontent.com", "cdn.jsdelivr.net", "jsdelivr.net"}
KNOWN_FINAL_HOSTS_RELEASE = {
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
}
KNOWN_FINAL_HOSTS_FAVICON = {"www.google.com", "gstatic.com", "www.gstatic.com", "t1.gstatic.com", "t2.gstatic.com", "t3.gstatic.com", "t4.gstatic.com", "t5.gstatic.com", "t6.gstatic.com"}


class Critical(Exception):
    pass


class Ctx:
    def __init__(self, policy, raw_base, use_cache, jobs):
        self.policy = policy
        self.domains = policy["domains"]
        self.blocklist = policy["blocklist"]
        self.raw_base = raw_base.rstrip("/")
        self.use_cache = use_cache
        self.jobs = jobs
        self.report: dict = {}
        self.critical: list[str] = []
        self.checksums: dict[str, str] = {}

    # ---- fetch wrappers -------------------------------------------------
    def get_json(self, url: str, *, strict=True):
        if strict:
            ok, reason = C.check_url_allowed(url, self.domains, executable=True)
            if not ok:
                raise C.PolicyError(f"index url rejected: {url} ({reason})")
        data = self.fetch_strict(url, lambda u: (True, "ok"),
                                 final_hosts=(KNOWN_FINAL_HOSTS_RAW | {"cdn.jsdelivr.net", "api.github.com"})
                                 if strict else None)
        try:
            return json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            raise C.FetchError(f"invalid JSON from {url}: {e}") from e

    def fetch_strict(self, url: str, policy_cb, *, final_hosts=None, timeout=60):
        """Download with validation of the *final* (post-redirect) URL."""
        cached = C._cache_path(url)
        if self.use_cache and cached.exists():
            data = cached.read_bytes()
            status = int(data[:3])
            payload = data[3:]
            if status != 200:
                raise C.FetchError(f"HTTP {status} for {url} (cached)")
            return payload

        headers = {"User-Agent": C.DEFAULT_USER_AGENT}
        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        if token and ("api.github.com" in url or "raw.githubusercontent.com" in url):
            headers["Authorization"] = f"Bearer {token}"

        import ssl as _ssl
        import time as _time
        import urllib.error as _uerror
        import urllib.request as _ureq

        last_err = None
        for attempt in range(3):
            try:
                req = _ureq.Request(url, headers=headers)
                with _ureq.urlopen(req, timeout=timeout, context=_ssl.create_default_context()) as resp:
                    payload = resp.read()
                    final = resp.geturl()
                if final != url:
                    ok, reason = policy_cb(final)
                    if not ok:
                        raise C.PolicyError(
                            f"redirect target rejected for {url} -> {final}: {reason}"
                        )
                if final_hosts is not None:
                    fh = (urllib.parse.urlsplit(final).hostname or "").lower()
                    if not any(fh == h or fh.endswith("." + h) for h in final_hosts):
                        raise C.PolicyError(
                            f"redirect to unexpected host for {url} -> {final}"
                        )
                if self.use_cache:
                    cached.parent.mkdir(parents=True, exist_ok=True)
                    tmp = cached.with_suffix(f".tmp{os.getpid()}")
                    tmp.write_bytes(b"200" + payload)
                    os.replace(tmp, cached)
                return payload
            except _uerror.HTTPError as e:
                if e.code in (429, 500, 502, 503) and attempt < 2:
                    _time.sleep(1.5 * (attempt + 1))
                    continue
                body = e.read() if e.fp else b""
                if self.use_cache:
                    cached.parent.mkdir(parents=True, exist_ok=True)
                    tmp = cached.with_suffix(f".tmp{os.getpid()}")
                    tmp.write_bytes(f"{e.code:03d}".encode() + body)
                    os.replace(tmp, cached)
                raise C.FetchError(f"HTTP {e.code} for {url}") from None
            except (C.PolicyError,):
                raise
            except Exception as e:  # noqa: BLE001
                last_err = e
                if attempt < 2:
                    _time.sleep(1.5 * (attempt + 1))
        raise C.FetchError(f"network error fetching {url}: {last_err}")

    def get_ok(self, url: str, **kw) -> bytes:
        data = self.fetch_strict(url, lambda u: (True, "ok"), **kw)
        return data

    # ---- policy checks --------------------------------------------------
    def blocked_name(self, name: str) -> str | None:
        bl = self.blocklist
        if name in set(bl.get("names", [])):
            return "blocklisted name"
        for pat in bl.get("name_patterns", []):
            if re.search(pat, name, flags=re.I):
                return f"blocklisted pattern: {pat}"
        return None

    def adult_name(self, *texts: str | None) -> str | None:
        joined = " | ".join(t for t in texts if t)
        return C._matches(joined, self.domains.get("adult_patterns", []))

    def store(self, rel: str, data: bytes, *, minified=False, obj=None):
        path = C.ROOT / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if obj is not None:
            C.write_json(path, obj, minified=minified)
            data = path.read_bytes()
        else:
            path.write_bytes(data)
        self.checksums[rel] = C.sha256_bytes(data)


# ---------------------------------------------------------------------------
# Aniyomi (anime + manga) — mirrors APKs, emits root index.min.json
# ---------------------------------------------------------------------------

def build_aniyomi(ctx: Ctx):
    pol = ctx.policy["upstreams"]["aniyomi"]
    entries_out: list[dict] = []
    rep: dict = {}

    for item_type in ("anime", "manga"):
        cfg = pol.get(item_type, {})
        trep: dict = {"upstream": cfg.get("index_url"), "enabled": cfg.get("enabled", False)}
        if not cfg.get("enabled"):
            rep[item_type] = trep
            continue
        include = set(cfg.get("include", []))
        include_mixed = set(cfg.get("include_mixed", []))
        allowed_cw = set(cfg.get("allowed_content_warnings", ["CONTENT_WARNING_SAFE"]))

        idx = ctx.get_json(cfg["index_url"])
        if cfg["format"] == "legacy":
            raw_entries = idx if isinstance(idx, list) else []
        else:
            ext_list = (idx or {}).get("extensionList", {}).get("extensions", [])
            raw_entries = ext_list if isinstance(ext_list, list) else []
        trep["upstream_entries"] = len(raw_entries)
        signing_key = (idx or {}).get("signingKey") if isinstance(idx, dict) else None
        if signing_key:
            trep["upstream_signing_key"] = signing_key

        drops: dict[str, int] = {}
        warnings: list[str] = []
        kept: list[dict] = []
        seen_pkg: set[str] = set()
        seen_apk: set[str] = set()

        def drop(reason: str):
            drops[reason] = drops.get(reason, 0) + 1

        for raw in raw_entries:
            if not isinstance(raw, dict):
                drop("not_a_dict")
                continue
            if cfg["format"] == "legacy":
                disp = re.sub(r"^(Aniyomi|Tachiyomi):\s*", "", str(raw.get("name", "")))
                prefix = "Aniyomi: " if item_type == "anime" else "Tachiyomi: "
                name_for_policy = disp
            else:
                disp = str(raw.get("name", ""))
                prefix = "Tachiyomi: " if item_type == "manga" else "Aniyomi: "
                name_for_policy = disp

            if not disp:
                drop("no_name")
                continue
            r = ctx.blocked_name(disp)
            if r:
                drop(f"blocklist ({r})")
                continue
            a = ctx.adult_name(disp)
            if a:
                drop(f"adult_pattern ({a})")
                continue

            # NSFW / content warning
            if cfg["format"] == "legacy":
                nsfw = raw.get("nsfw", raw.get("isNsfw", 0)) or 0
                if nsfw not in (0, False, "0"):
                    drop("nsfw_flag")
                    continue
                cw = "CONTENT_WARNING_SAFE"
            else:
                cw = str(raw.get("contentWarning", ""))
                if cw not in allowed_cw and disp not in include_mixed:
                    drop(f"content_warning ({cw or 'missing'})")
                    continue
                if cw not in allowed_cw:
                    # in include_mixed but not allowlisted entry -> still require allowlist
                    pass

            # allowlist mode
            mode = cfg.get("mode", "all_sfw")
            if mode == "allowlist" and disp not in include:
                drop("not_in_allowlist")
                continue

            if cfg["format"] == "legacy":
                pkg = str(raw.get("pkg", ""))
                apk = str(raw.get("apk", ""))
                lang = str(raw.get("lang", "all"))
                version = str(raw.get("version", "0"))
                code = raw.get("code")
                sources = raw.get("sources") or []
            else:
                pkg = str(raw.get("packageName", ""))
                apk_url = str(((raw.get("resources") or {}).get("apkUrl")) or "")
                apk = urllib.parse.unquote(urllib.parse.urlsplit(apk_url).path.rsplit("/", 1)[-1])
                lang_s = {str(s.get("language", "all")) for s in raw.get("sources") or [] if isinstance(s, dict)}
                lang = next(iter(lang_s)) if len(lang_s) == 1 else "all"
                version = str(raw.get("versionName", "0"))
                try:
                    code = int(raw.get("versionCode", 0))
                except (TypeError, ValueError):
                    code = 0
                sources = [
                    {
                        "name": str(s.get("name", "")),
                        "lang": str(s.get("language", "all")),
                        "id": str(s.get("id", "")),
                        "baseUrl": str(s.get("homeUrl", "")),
                    }
                    for s in raw.get("sources") or []
                    if isinstance(s, dict)
                ]

            if not re.fullmatch(r"[A-Za-z0-9_.]+", pkg or ""):
                drop("bad_pkg")
                continue
            if not re.fullmatch(r"[A-Za-z0-9._-]+\.apk", apk or ""):
                drop("bad_apk_name")
                continue
            if pkg in seen_pkg:
                drop("duplicate_pkg")
                continue
            if apk in seen_apk:
                drop("duplicate_apk")
                continue
            if not sources:
                drop("no_sources")
                continue

            bad_src = None
            for s in sources:
                bu = s.get("baseUrl", "")
                if not bu:
                    # user-configured sources (Jellyfin, GoogleDriveIndex...) ship
                    # an empty baseUrl by design; nothing to validate yet
                    continue
                if not bu.startswith("https://"):
                    bad_src = f"non-https baseUrl ({bu[:60]})"
                    break
                rs = C.suspicious_reason(bu, ctx.domains)
                if rs:
                    bad_src = rs
                    break
            if bad_src:
                drop(f"source_url ({bad_src})")
                continue
            if any(not s.get("baseUrl") for s in sources):
                warnings.append(f"{disp}: source with empty (user-configured) baseUrl")

            # --- mirror icon + apk ---------------------------------------
            base = re.sub(r"/index\.(min\.)?json$", "", cfg["index_url"])
            if cfg["format"] == "legacy":
                icon_url = f"{base}/icon/{pkg}.png"
                apk_url = f"{base}/apk/{apk}"
            else:
                icon_url = ((raw.get("resources") or {}).get("iconUrl")) or f"{base}/icon/{pkg}.png"

            ok, reason = C.check_url_allowed(icon_url, ctx.domains, executable=False)
            ok_icon_fetch = True
            if not ok:
                # icons may come from image-safe hosts (jsdelivr/raw allowlist preferred)
                ok_icon_fetch, reason = C.is_safe_fetch_target(icon_url, ctx.domains)
            if not (ok or ok_icon_fetch):
                drop(f"icon_url ({reason})")
                continue

            ok, reason = C.check_url_allowed(apk_url, ctx.domains, executable=True)
            if not ok:
                drop(f"apk_url ({reason})")
                continue

            try:
                # icon: no fixed final-host set; original URL passed
                # is_safe_fetch_target above, redirects are re-checked by the
                # policy callback, and bytes are verified to be an image below
                icon_data = ctx.fetch_strict(
                    icon_url,
                    lambda u: C.is_safe_fetch_target(u, ctx.domains),
                )
            except (C.FetchError, C.PolicyError) as e:
                drop(f"icon_fetch ({type(e).__name__})")
                continue
            if C.image_kind(icon_data) is None:
                drop("icon_not_image")
                continue

            try:
                apk_data = ctx.fetch_strict(
                    apk_url,
                    lambda u: C.is_safe_fetch_target(u, ctx.domains),
                    final_hosts=KNOWN_FINAL_HOSTS_RELEASE | KNOWN_FINAL_HOSTS_RAW,
                )
            except (C.FetchError, C.PolicyError) as e:
                drop(f"apk_fetch ({type(e).__name__})")
                continue
            ok, why, info = C.validate_apk(apk_data)
            if not ok:
                drop(f"apk_invalid ({why})")
                continue

            dex = C.dex_artifact_report(apk_data, ctx.domains)
            if dex.get("suspicious"):
                ctx.critical.append(f"{pkg}: suspicious URLs in dex: {dex['suspicious'][:5]}")
                drop("dex_suspicious")
                continue

            # signing key best-effort check
            if signing_key:
                got = C.v1_cert_sha256(apk_data)
                if got is None:
                    warnings.append(f"{pkg}: no v1 signature block (v2/v3 only) - cert check skipped")
                elif got != signing_key:
                    warnings.append(
                        f"{pkg}: v1 cert sha256 {got[:16]}... != index signingKey {signing_key[:16]}... (may use different key format)"
                    )

            ctx.store(f"icon/{pkg}.png", icon_data)
            ctx.store(f"apk/{apk}", apk_data)
            seen_pkg.add(pkg)
            seen_apk.add(apk)

            if cfg["format"] == "legacy":
                entry = {
                    "name": prefix + disp,
                    "pkg": pkg,
                    "apk": apk,
                    "lang": lang,
                    "version": version,
                    "nsfw": 0,
                    "sources": sources,
                }
                if code is not None:
                    entry["code"] = code
            else:
                entry = {
                    "name": prefix + disp,
                    "pkg": pkg,
                    "apk": apk,
                    "lang": lang,
                    "code": code,
                    "version": version,
                    "nsfw": 0,
                    "sources": sources,
                }
            kept.append(entry)

        missing_in_upstream = sorted(include - set(
            (re.sub(r"^(Aniyomi|Tachiyomi):\s*", "", str(r.get("name", "")))) if cfg["format"] == "legacy"
            else str(r.get("name", ""))
            for r in raw_entries if isinstance(r, dict)
        ))
        trep.update({
            "kept": len(kept),
            "drops": drops,
            "warnings": warnings[:60],
            "warning_count": len(warnings),
            "allowlist_names_not_in_upstream": missing_in_upstream,
        })
        rep[item_type] = trep
        entries_out.extend(kept)

    entries_out.sort(key=lambda e: (e["name"].lower(), e["pkg"]))
    dup = [p for p in {e["pkg"] for e in entries_out} if sum(1 for x in entries_out if x["pkg"] == p) > 1]
    if dup:
        ctx.critical.append(f"duplicate pkg across types: {dup}")
    dup_apk = [a for a in {e["apk"] for e in entries_out} if sum(1 for x in entries_out if x["apk"] == a) > 1]
    if dup_apk:
        ctx.critical.append(f"duplicate apk filename across types: {dup_apk}")
    ctx.store("index.min.json", b"", obj=entries_out, minified=True)
    ctx.report["aniyomi"] = rep


# ---------------------------------------------------------------------------
# Mangayomi — passes upstream entries through (SFW only), 3 index files
# ---------------------------------------------------------------------------

MANGAYOMI_FILES = {"manga": "index.json", "anime": "anime_index.json", "novel": "novel_index.json"}
MANGAYOMI_ITEMTYPE = {"manga": 0, "anime": 1, "novel": 2}


def build_mangayomi(ctx: Ctx):
    pol = ctx.policy["upstreams"]["mangayomi"]
    rep: dict = {"upstream": pol.get("upstream"), "enabled": pol.get("enabled", False)}
    if not pol.get("enabled"):
        ctx.report["mangayomi"] = rep
        return
    for type_key, file_name in MANGAYOMI_FILES.items():
        url = pol["indexes"][type_key]
        idx = ctx.get_json(url)
        if not isinstance(idx, list):
            ctx.critical.append(f"mangayomi {type_key}: index is not a list")
            continue
        drops: dict[str, int] = {}
        kept = []
        warnings = []
        seen_ids: set = set()

        # repairs for broken upstream asset URLs; every override carries a
        # written reason and must name an existing entry id
        overrides_by_id: dict = {}
        for ov in pol.get("overrides", []):
            if ov.get("field") in ("iconUrl", "sourceCodeUrl") and "value" in ov and "id" in ov:
                overrides_by_id.setdefault(ov["id"], []).append(ov)
        applied_overrides: list[str] = []
        exclude_ids = {e["id"]: e.get("reason", "") for e in pol.get("exclude_ids", []) if "id" in e}

        def drop(reason):
            drops[reason] = drops.get(reason, 0) + 1

        for raw in idx:
            if not isinstance(raw, dict):
                drop("not_a_dict")
                continue
            # upstream ships occasional trailing whitespace in URL fields
            for f in ("name", "baseUrl", "iconUrl", "sourceCodeUrl"):
                v = raw.get(f)
                if isinstance(v, str):
                    raw[f] = v.strip()
            for ov in overrides_by_id.get(raw.get("id"), ()):
                raw[ov["field"]] = ov["value"]
                applied_overrides.append(
                    f"{raw.get('name')} (id {raw.get('id')}): {ov['field']} overridden - {ov['reason']}"
                )
            if raw.get("id") in exclude_ids:
                drop("policy_exclusion")
                warnings.append(f"id {raw.get('id')}: {exclude_ids[raw['id']]}")
                continue
            name = str(raw.get("name", ""))
            if not name:
                drop("no_name")
                continue
            r = ctx.blocked_name(name)
            if r:
                drop(f"blocklist ({r})")
                continue
            a = ctx.adult_name(name)
            if a:
                drop(f"adult_pattern ({a})")
                continue
            if raw.get("isNsfw"):
                drop("nsfw_flag")
                continue
            if raw.get("itemType") != MANGAYOMI_ITEMTYPE[type_key]:
                drop("wrong_item_type")
                continue
            for field, executable in (("sourceCodeUrl", True),):
                u = raw.get(field)
                if not u:
                    drop(f"missing_{field}")
                    break
                if str(u).endswith("/"):
                    drop(f"{field} (directory URL, not a source file)")
                    break
                ok, reason = C.check_url_allowed(u, ctx.domains, executable=executable)
                if not ok:
                    drop(f"{field} ({reason})")
                    break
            else:
                # icons are fetched by the app at runtime from upstream; they are
                # not executable, so any public https host is allowed as long as
                # it is not suspicious/private (source code stays strict-allowlist)
                iu = str(raw.get("iconUrl") or "")
                ok, reason = C.is_safe_fetch_target(iu, ctx.domains)
                if not ok:
                    drop(f"iconUrl ({reason})")
                    continue
                if not str(raw.get("baseUrl", "")).startswith("http"):
                    drop("bad_base_url")
                    continue
                # upstream occasionally ships the exact same source twice;
                # name+baseUrl repeats are legitimate (per-language instances)
                eid = raw.get("id")
                if eid is not None and eid in seen_ids:
                    drop("duplicate_entry")
                    continue
                if eid is not None:
                    seen_ids.add(eid)
                kept.append(raw)
        rep[type_key] = {
            "upstream": url,
            "upstream_entries": len(idx),
            "kept": len(kept),
            "drops": drops,
            "warnings": warnings,
            "overrides": applied_overrides,
        }
        ctx.store(f"mangayomi/{file_name}", b"", obj=kept, minified=True)
    ctx.report["mangayomi"] = rep


# ---------------------------------------------------------------------------
# Sora — aggregates JS modules, mirrors script + icons
# ---------------------------------------------------------------------------

# Type values seen in the wild -> the three type strings Dartotsu displays.
def _normalize_sora_type(t: str) -> str | None:
    if not t:
        return None
    if t == "anime":
        return "anime"
    if t == "movie":
        return "movie"
    if "manga" in t:
        return "mangas"
    if any(k in t for k in ("anime", "movie", "show")):
        # "shows", "movies/shows", "anime/shows/movies" ... all video content;
        # Dartotsu maps both 'anime' and 'movie' to the same section
        return "movie"
    return None  # novels, audio, missing -> not displayable, drop


def build_sora(ctx: Ctx):
    pol = ctx.policy["upstreams"]["sora"]
    rep: dict = {"upstream": pol.get("upstream"), "enabled": pol.get("enabled", False)}
    if not pol.get("enabled"):
        ctx.report["sora"] = rep
        return
    raw_base = pol["raw_base"].rstrip("/")
    exclude = [p.lower() for p in pol.get("exclude_path_patterns", [])]
    include_types = {t.lower() for t in pol.get("include_types", ["anime", "movie", "mangas"])}
    ea = pol.get("extra_allowed_hosts", {})
    if isinstance(ea, dict):
        extra_hosts = {h.lower() for h in ea if not h.startswith("$")}
    else:
        extra_hosts = {h.lower() for h in ea}
    type_normalized: dict[str, str] = {}

    # the tree URL is build infrastructure declared in the trusted policy file
    tree = ctx.get_json(pol["tree_url"], strict=False)
    paths = [t["path"] for t in tree.get("tree", []) if t.get("type") == "blob" and t["path"].endswith(".json")]
    paths = [p for p in paths if not any(x in p.lower() for x in exclude)]

    drops: dict[str, int] = {}
    warnings: list[str] = []
    kept: list[dict] = []
    js_hosts: dict[str, list[str]] = {}

    def drop(reason):
        drops[reason] = drops.get(reason, 0) + 1

    def remap(url: str) -> list[str]:
        """Candidate URLs for a module asset (dead 50n50 URLs -> mirror repo)."""
        cands = []
        if "raw.githubusercontent.com/50n50/sources/" in url:
            m = re.search(r"/(?:refs/heads/)?(?:main|master)/(.+)$", url)
            if m:
                cands.append(f"{raw_base}/{m.group(1)}")
        cands.append(url)
        return cands

    def fetch_asset(url: str, *, executable: bool):
        last = None
        for cand in remap(url):
            if executable:
                ok, reason = C.check_url_allowed(cand, ctx.domains, executable=True)
            else:
                ok, reason = C.is_safe_fetch_target(cand, ctx.domains)
            if not ok:
                last = f"url policy: {reason}"
                continue
            try:
                if executable:
                    data = ctx.fetch_strict(cand, lambda u: C.is_safe_fetch_target(u, ctx.domains),
                                            final_hosts=KNOWN_FINAL_HOSTS_RAW | {"cdn.jsdelivr.net"})
                else:
                    data = ctx.fetch_strict(cand, lambda u: C.is_safe_fetch_target(u, ctx.domains))
                return cand, data, None
            except (C.FetchError, C.PolicyError) as e:
                last = f"{type(e).__name__}: {e}"
        return None, None, last or "unreachable"

    for path in sorted(paths):
        url = f"{raw_base}/{urllib.parse.quote(path)}"
        try:
            mod = ctx.get_json(url, strict=True)
        except (C.FetchError, C.PolicyError, json.JSONDecodeError) as e:
            drop(f"module_fetch ({type(e).__name__})")
            continue
        if not isinstance(mod, dict) or "sourceName" not in mod:
            drop("bad_module_shape")
            continue
        sname = str(mod["sourceName"])
        r = ctx.blocked_name(sname)
        if r:
            drop(f"blocklist ({r})")
            continue
        a = ctx.adult_name(sname, str(mod.get("description", "")))
        if a:
            drop(f"adult_pattern ({a})")
            continue
        if mod.get("nsfw") is True:
            drop("nsfw_flag")
            continue
        mtype_raw = str(mod.get("type", "")).strip().lower()
        mtype = _normalize_sora_type(mtype_raw)
        if mtype is None or mtype not in include_types:
            drop(f"type_{mtype_raw or 'missing'}")
            continue
        if mtype != mtype_raw:
            type_normalized[sname] = f"{mtype_raw} -> {mtype}"
        for req in ("baseUrl", "language", "version"):
            if req not in mod:
                drop(f"missing_{req}")
                break
        else:
            bu = str(mod.get("baseUrl", ""))
            if not bu.startswith("https://"):
                drop("bad_base_url")
                continue

            # --- script (executable) ---
            script_url = str(mod.get("scriptUrl") or mod.get("scriptURL") or "")
            if not script_url:
                drop("missing_script")
                continue
            _, js, err = fetch_asset(script_url, executable=True)
            if js is None:
                drop(f"script_fetch ({err})")
                continue
            if len(js) < 200:
                drop("script_too_small")
                continue
            try:
                js_text = js.decode("utf-8")
            except UnicodeDecodeError:
                js_text = js.decode("latin1")

            # hosts referenced anywhere in the module definition are trusted
            # for this module's JS (its own baseUrl/api/cdn), plus global extras
            _, mod_urls = C.hosts_from_text(json.dumps(mod))
            allowed_js_hosts = set(extra_hosts) | {
                "raw.githubusercontent.com", "cdn.jsdelivr.net", "github.io",
                "github.com", "google.com", "gstatic.com",
            }
            for mu in mod_urls:
                try:
                    h = urllib.parse.urlsplit(mu).hostname
                    if h:
                        allowed_js_hosts.add(h.lower())
                except ValueError:
                    pass

            def _host_approved(h: str) -> bool:
                return any(h == a or h.endswith("." + a) for a in allowed_js_hosts)

            js_hosts_set, js_urls = C.hosts_from_text(js_text)
            unapproved = sorted(h for h in js_hosts_set if not _host_approved(h))
            susp = [u for u in js_urls if C.suspicious_reason(u, ctx.domains)]
            if susp:
                drop("js_suspicious_url")
                warnings.append(f"{sname}: suspicious JS urls: {susp[:3]}")
                continue
            if unapproved:
                drop("js_unapproved_hosts")
                warnings.append(f"{sname}: JS references unapproved hosts: {unapproved}")
                continue
            js_hosts[sname] = sorted(js_hosts_set)

            # --- icon ---
            icon_url = str(mod.get("iconUrl") or mod.get("iconURL") or "")
            new_icon = None
            if icon_url:
                _, icon_data, err = fetch_asset(icon_url, executable=False)
                if icon_data and C.image_kind(icon_data):
                    kind = C.image_kind(icon_data)
                    rel = f"sora/icon/{C.slugify(sname)}.{kind}"
                    ctx.store(rel, icon_data)
                    new_icon = f"{ctx.raw_base}/{rel}"
                else:
                    warnings.append(f"{sname}: icon mirror failed ({err}); icon omitted")

            # --- author icon ---
            author = mod.get("author")
            new_author = None
            if isinstance(author, dict):
                new_author = {"name": author.get("name")}
                aicon = str(author.get("icon") or "")
                if aicon:
                    _, adata, err = fetch_asset(aicon, executable=False)
                    if adata and C.image_kind(adata):
                        kind = C.image_kind(adata)
                        rel = f"sora/author/{C.slugify(str(author.get('name') or 'anon'))}.{kind}"
                        if rel not in ctx.checksums:
                            ctx.store(rel, adata)
                        new_author["icon"] = f"{ctx.raw_base}/{rel}"
                    else:
                        warnings.append(f"{sname}: author icon mirror failed ({err})")

            out = dict(mod)
            out["type"] = mtype  # normalized for Dartotsu display
            out["scriptUrl"] = f"{ctx.raw_base}/sora/js/{C.slugify(sname)}.js"
            if new_icon:
                out["iconUrl"] = new_icon
            else:
                out.pop("iconUrl", None)
                out.pop("iconURL", None)
            if new_author is not None:
                out["author"] = new_author
            rel = f"sora/js/{C.slugify(sname)}.js"
            ctx.store(rel, js)
            kept.append(out)

    names = [k["sourceName"] for k in kept]
    dupes = sorted({n for n in names if names.count(n) > 1})
    if dupes:
        ctx.critical.append(f"duplicate sora sourceName: {dupes}")
    kept.sort(key=lambda m: str(m.get("sourceName", "")).lower())
    rep.update({
        "upstream_entries": len(paths),
        "kept": len(kept),
        "drops": drops,
        "warnings": warnings[:80],
        "warning_count": len(warnings),
        "type_normalized": type_normalized,
        "js_hosts": js_hosts,
    })
    ctx.store("sora/index.json", b"", obj=kept, minified=True)
    ctx.report["sora"] = rep


# ---------------------------------------------------------------------------
# CloudStream — aggregates plugin repos, mirrors .cs3 + icons
# ---------------------------------------------------------------------------

def build_cloudstream(ctx: Ctx):
    pol = ctx.policy["upstreams"]["cloudstream"]
    rep: dict = {"enabled": pol.get("enabled", False), "repos": []}
    if not pol.get("enabled"):
        ctx.report["cloudstream"] = rep
        return
    exclude_status = set(pol.get("exclude_status", [0]))
    exclude_paid = pol.get("exclude_paid", True)

    plugins: dict[str, dict] = {}
    drop_counts: dict[str, int] = {}
    warnings: list[str] = []
    dex_hosts: dict[str, list[str]] = {}
    hash_verified = 0
    hash_mismatches: list[str] = []
    kept_here = 0

    def drop(reason):
        drop_counts[reason] = drop_counts.get(reason, 0) + 1

    for repo_cfg in pol["repos"]:
        rrep = {"name": repo_cfg["name"], "tier": repo_cfg["tier"], "index": repo_cfg["index"]}
        try:
            idx = ctx.get_json(repo_cfg["index"], strict=True)
        except (C.FetchError, C.PolicyError) as e:
            rrep["error"] = str(e)
            rep["repos"].append(rrep)
            ctx.critical.append(f"cs repo {repo_cfg['name']}: index fetch failed: {e}")
            continue

        if isinstance(idx, dict) and "pluginLists" in idx:
            entries = []
            for sub in idx["pluginLists"]:
                ok, reason = C.check_url_allowed(sub, ctx.domains, executable=True)
                if not ok:
                    drop_counts[f"subrepo_not_allowed ({reason})"] = drop_counts.get(f"subrepo_not_allowed ({reason})", 0) + 1
                    continue
                try:
                    sub_idx = ctx.get_json(sub, strict=True)
                except (C.FetchError, C.PolicyError) as e:
                    warnings.append(f"{repo_cfg['name']}: subrepo failed: {e}")
                    continue
                if isinstance(sub_idx, list):
                    entries.extend(sub_idx)
                elif isinstance(sub_idx, dict) and "pluginLists" in sub_idx:
                    pass  # nested meta not followed (depth limit)
        elif isinstance(idx, list):
            entries = idx
        else:
            rrep["error"] = "unsupported index shape"
            rep["repos"].append(rrep)
            ctx.critical.append(f"cs repo {repo_cfg['name']}: unsupported index shape")
            continue

        rrep["upstream_entries"] = len(entries)
        for e in entries:
            if not isinstance(e, dict):
                drop("not_a_dict")
                continue
            name = str(e.get("name", ""))
            internal = str(e.get("internalName") or name)
            if not name or not internal:
                drop("no_name")
                continue
            r = ctx.blocked_name(name)
            if r:
                drop(f"blocklist ({r})")
                continue
            tv = e.get("tvTypes") or []
            tvs = " ".join(str(x) for x in tv) if isinstance(tv, list) else str(tv)
            a = ctx.adult_name(name, tvs, str(e.get("description", "")))
            if a:
                drop(f"adult_pattern ({a})")
                continue
            status = e.get("status")
            if status is not None and status in exclude_status:
                drop(f"status_{status}")
                continue
            price = e.get("price")
            if exclude_paid and price not in (None, 0, "0"):
                drop("paid")
                continue
            key = internal.lower()
            if key in plugins:
                drop("duplicate_internal_name")
                continue
            url = str(e.get("url", ""))
            ok, reason = C.check_url_allowed(url, ctx.domains, executable=True)
            if not ok:
                drop(f"plugin_url [{internal}] ({reason})")
                continue

            # mirror .cs3
            try:
                blob = ctx.fetch_strict(url, lambda u: C.is_safe_fetch_target(u, ctx.domains),
                                        final_hosts=KNOWN_FINAL_HOSTS_RAW)
            except (C.FetchError, C.PolicyError) as ex:
                drop(f"plugin_fetch [{internal}] ({type(ex).__name__}: {ex})")
                continue
            ok, why, info = C.validate_cs3(blob)
            if not ok:
                drop(f"plugin_invalid [{internal}] ({why})")
                continue
            declared = str(e.get("fileHash") or "")
            if declared.startswith("sha256-"):
                got = C.sha256_bytes(blob)
                if got != declared[len("sha256-"):]:
                    hash_mismatches.append(
                        f"{repo_cfg['name']}/{internal}: declared {declared[7:24]}... actual {got[:17]}..."
                    )
                    drop("hash_mismatch")
                    continue
                hash_verified += 1
            dex = C.dex_artifact_report(blob, ctx.domains)
            if dex.get("suspicious"):
                ctx.critical.append(
                    f"{repo_cfg['name']}/{internal}: suspicious URLs in dex: {dex['suspicious'][:5]}"
                )
                drop("dex_suspicious")
                continue
            dex_hosts[internal] = dex.get("hosts", [])

            repo_slug = C.slugify(repo_cfg["name"])
            base_name = urllib.parse.unquote(url.rsplit("/", 1)[-1])
            rel = f"cloudstream/plugins/{repo_slug}/{C.slugify(base_name)}.cs3"
            ctx.store(rel, blob)

            # mirror icon (optional)
            new_icon = None
            icon_url = str(e.get("iconUrl") or "")
            if icon_url:
                if "%size%" in icon_url:
                    icon_url = icon_url.replace("%size%", "128")
                ok, reason = C.check_url_allowed(icon_url, ctx.domains, executable=False)
                ok_safe, reason2 = C.is_safe_fetch_target(icon_url, ctx.domains)
                if ok or ok_safe:
                    try:
                        # icons: no fixed final-host set — a redirect (if any) is
                        # still validated by the policy callback, and the bytes
                        # are verified to be a real image afterwards
                        icon_data = ctx.fetch_strict(icon_url, lambda u: C.is_safe_fetch_target(u, ctx.domains))
                        kind = C.image_kind(icon_data)
                        if kind:
                            rel_i = f"cloudstream/icon/{C.slugify(internal)}.{kind}"
                            ctx.store(rel_i, icon_data)
                            new_icon = f"{ctx.raw_base}/{rel_i}"
                        else:
                            warnings.append(f"{internal}: icon not an image, omitted")
                    except (C.FetchError, C.PolicyError) as ex:
                        warnings.append(f"{internal}: icon fetch failed ({ex}), omitted")
                else:
                    warnings.append(f"{internal}: icon url rejected ({reason or reason2}), omitted")

            out = {
                "name": name,
                "internalName": internal,
                "url": f"{ctx.raw_base}/{rel}",
                "language": e.get("language"),
                "version": e.get("version", 1),
                "tvTypes": tv if isinstance(tv, list) else None,
                "authors": e.get("authors"),
                "description": e.get("description"),
                "status": status if status is not None else 1,
            }
            if new_icon:
                out["iconUrl"] = new_icon
            if e.get("fileHash"):
                out["fileHash"] = e["fileHash"]
            if e.get("repositoryUrl"):
                ok, _ = C.check_url_allowed(str(e["repositoryUrl"]), ctx.domains, executable=False)
                if ok:
                    out["repositoryUrl"] = e["repositoryUrl"]
            out = {k: v for k, v in out.items() if v is not None}
            plugins[key] = out
            kept_here += 1
        rrep["kept"] = kept_here
        kept_here = 0
        rep["repos"].append(rrep)

    final = sorted(plugins.values(), key=lambda p: p["name"].lower())
    rep.update({
        "kept": len(final),
        "drops": drop_counts,
        "hash_verified": hash_verified,
        "hash_mismatches": hash_mismatches,
        "warnings": warnings[:80],
        "warning_count": len(warnings),
        "dex_hosts": dex_hosts,
    })
    if hash_mismatches:
        ctx.critical.append(f"{len(hash_mismatches)} .cs3 fileHash mismatches (upstream artifact changed): {hash_mismatches[:5]}")
    ctx.store("cloudstream/repo.json", b"", obj=final, minified=True)
    ctx.report["cloudstream"] = rep


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def wipe_managed(paths=None):
    for rel in (paths or MANAGED_PATHS):
        p = C.ROOT / rel
        if p.is_dir():
            shutil.rmtree(p)
        elif p.exists():
            p.unlink()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--only", choices=["aniyomi", "mangayomi", "sora", "cloudstream"],
                    help="rebuild a single ecosystem (others left as-is)")
    ap.add_argument("--no-cache", action="store_true", help="ignore .cache and refetch")
    ap.add_argument("--repo-base", default=os.environ.get("REPO_RAW_BASE"),
                    help="raw base URL of this repo, e.g. https://raw.githubusercontent.com/USER/REPO/main")
    ap.add_argument("--jobs", type=int, default=8)
    args = ap.parse_args()

    policy = C.load_policy()
    raw_base = (args.repo_base or f"https://raw.githubusercontent.com/{SELF_REPO}/main").rstrip("/")
    ctx = Ctx(policy, raw_base, use_cache=not args.no_cache, jobs=args.jobs)

    if args.only:
        wipe = {"aniyomi": ["index.min.json", "icon", "apk"],
                "mangayomi": ["mangayomi"],
                "sora": ["sora"],
                "cloudstream": ["cloudstream"]}[args.only]
        # preserve checksums for files we are not rebuilding
        cs_path = C.ROOT / "checksums.json"
        if cs_path.exists():
            old = C.load_json(cs_path).get("files", {})
            prefixes = tuple(w.rstrip("/") + "/" for w in wipe if not w.endswith(".json")) + tuple(
                w for w in wipe if w.endswith(".json")
            )
            ctx.checksums = {k: v for k, v in old.items() if not k.startswith(prefixes)}
        wipe_managed(wipe)
        report_path = C.ROOT / "build-report.json"
        if report_path.exists():
            ctx.report = C.load_json(report_path)
    else:
        wipe_managed()

    builders = {
        "aniyomi": build_aniyomi,
        "mangayomi": build_mangayomi,
        "sora": build_sora,
        "cloudstream": build_cloudstream,
    }
    order = [args.only] if args.only else ["aniyomi", "mangayomi", "sora", "cloudstream"]
    for name in order:
        print(f"==> building {name} ...", flush=True)
        try:
            builders[name](ctx)
        except C.PolicyError as e:
            ctx.critical.append(f"{name}: policy violation: {e}")
        except C.FetchError as e:
            ctx.critical.append(f"{name}: fetch failed: {e}")

    # checksums over all managed outputs
    for rel in ["index.min.json", "mangayomi/index.json", "mangayomi/anime_index.json",
                "mangayomi/novel_index.json", "sora/index.json", "cloudstream/repo.json"]:
        p = C.ROOT / rel
        if p.exists():
            ctx.checksums[rel] = C.sha256_file(p)

    # minimum entries guard
    mins = DEFAULT_MIN_ENTRIES
    checks = [
        ("aniyomi_anime", (ctx.report.get("aniyomi") or {}).get("anime", {}).get("kept")),
        ("aniyomi_manga", (ctx.report.get("aniyomi") or {}).get("manga", {}).get("kept")),
        ("mangayomi_manga", (ctx.report.get("mangayomi") or {}).get("manga", {}).get("kept")),
        ("mangayomi_anime", (ctx.report.get("mangayomi") or {}).get("anime", {}).get("kept")),
        ("mangayomi_novel", (ctx.report.get("mangayomi") or {}).get("novel", {}).get("kept")),
        ("sora", (ctx.report.get("sora") or {}).get("kept")),
        ("cloudstream", (ctx.report.get("cloudstream") or {}).get("kept")),
    ]
    for key, got in checks:
        if got is None:
            continue
        if got < mins[key]:
            ctx.critical.append(f"min entries failed for {key}: {got} < {mins[key]}")

    ctx.report["built_at"] = __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat()
    ctx.report["policy_sha256"] = C.policy_sha256()
    ctx.report["raw_base"] = ctx.raw_base
    ctx.report["totals"] = {
        "mirrored_files": len(ctx.checksums),
        "mirrored_bytes": sum(
            (C.ROOT / r).stat().st_size for r in ctx.checksums if (C.ROOT / r).exists()
        ),
    }
    ctx.report["critical"] = ctx.critical
    C.write_json(C.ROOT / "checksums.json", {"algorithm": "sha256",
                                             "files": dict(sorted(ctx.checksums.items()))})
    C.write_json(C.ROOT / "build-report.json", ctx.report)

    # summary
    def line(k, v):
        print(f"    {k}: {v}")
    for eco in ("aniyomi", "mangayomi", "sora", "cloudstream"):
        r = ctx.report.get(eco)
        if not r:
            continue
        print(f"  {eco}:")
        if eco == "aniyomi":
            for t in ("anime", "manga"):
                line(t, f"{r.get(t, {}).get('kept', 0)} kept / {r.get(t, {}).get('upstream_entries', 0)} upstream")
        elif eco == "mangayomi":
            for t in ("manga", "anime", "novel"):
                if t in r:
                    line(t, f"{r[t].get('kept', 0)} kept / {r[t].get('upstream_entries', 0)} upstream")
        else:
            line("kept", f"{r.get('kept', 0)}")
    print(f"  mirrored files: {len(ctx.checksums)}, "
          f"bytes: {ctx.report['totals']['mirrored_bytes'] / 1e6:.1f} MB")
    if ctx.critical:
        print("\nCRITICAL ISSUES:", file=sys.stderr)
        for c in ctx.critical:
            print(f"  ! {c}", file=sys.stderr)
        sys.exit(2)
    print("build OK")


if __name__ == "__main__":
    main()
