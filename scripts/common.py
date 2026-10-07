#!/usr/bin/env python3
"""Shared helpers for building and verifying the curated Dartotsu extension repo.

Stdlib-only. Used by scripts/build.py and scripts/verify.py.
"""
from __future__ import annotations

import hashlib
import io
import ipaddress
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
POLICY_DIR = ROOT / "policy"
CACHE_DIR = ROOT / ".cache"

DEFAULT_USER_AGENT = (
    "dartotsu-safe-extensions/1.0 "
    "(+https://github.com/sleepy-shan/dartotsu-safe-extensions)"
)

IMAGE_MAGICS = [
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"\xff\xd8\xff", "jpg"),
    (b"GIF87a", "gif"),
    (b"GIF89a", "gif"),
]


class FetchError(Exception):
    pass


class PolicyError(Exception):
    pass


# --------------------------------------------------------------------------
# Policy loading
# --------------------------------------------------------------------------

def load_json(path: Path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_policy() -> dict:
    return {
        "upstreams": load_json(POLICY_DIR / "upstreams.json"),
        "domains": load_json(POLICY_DIR / "domains.json"),
        "blocklist": load_json(POLICY_DIR / "blocklist.json"),
    }


def policy_sha256() -> dict:
    out = {}
    for name in ("upstreams.json", "domains.json", "blocklist.json"):
        out[name] = sha256_bytes((POLICY_DIR / name).read_bytes())
    return out


# --------------------------------------------------------------------------
# Fetching (with disk cache)
# --------------------------------------------------------------------------

def _cache_path(url: str) -> Path:
    return CACHE_DIR / (hashlib.sha1(url.encode("utf-8")).hexdigest() + ".bin")


def fetch(url: str, *, binary: bool = True, use_cache: bool = True,
          timeout: int = 45, retries: int = 2) -> tuple[int, bytes]:
    """Fetch a URL. Returns (status, data). data is bytes for binary mode.

    HTTP error statuses are returned, not raised. Network failures retry.
    """
    cached = _cache_path(url)
    if use_cache and cached.exists():
        data = cached.read_bytes()
        # cached entries are stored as (status_bytes) with a 3-byte prefix
        status = int(data[:3])
        payload = data[3:]
        return status, payload

    headers = {"User-Agent": DEFAULT_USER_AGENT}
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token and ("api.github.com" in url or "raw.githubusercontent.com" in url):
        headers["Authorization"] = f"Bearer {token}"

    last_err: Exception | None = None
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, headers=headers)
            ctx = ssl.create_default_context()
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                payload = resp.read()
                status = resp.status
            if use_cache:
                cached.parent.mkdir(parents=True, exist_ok=True)
                tmp = cached.with_suffix(f".tmp{os.getpid()}")
                tmp.write_bytes(f"{status:03d}".encode() + payload)
                os.replace(tmp, cached)
            return status, payload
        except urllib.error.HTTPError as e:
            payload = e.read() if e.fp else b""
            status = e.code
            if status in (429, 500, 502, 503) and attempt < retries:
                time.sleep(1.5 * (attempt + 1))
                continue
            if use_cache:
                cached.parent.mkdir(parents=True, exist_ok=True)
                tmp = cached.with_suffix(f".tmp{os.getpid()}")
                tmp.write_bytes(f"{status:03d}".encode() + payload)
                os.replace(tmp, cached)
            return status, payload
        except Exception as e:  # noqa: BLE001 - network layer
            last_err = e
            if attempt < retries:
                time.sleep(1.5 * (attempt + 1))
    raise FetchError(f"network error fetching {url}: {last_err}")


def fetch_ok(url: str, **kw) -> bytes:
    status, data = fetch(url, **kw)
    if status != 200:
        raise FetchError(f"HTTP {status} for {url}")
    return data


def fetch_json(url: str, **kw):
    data = fetch_ok(url, **kw)
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise FetchError(f"invalid JSON from {url}: {e}") from e


# --------------------------------------------------------------------------
# URL policy
# --------------------------------------------------------------------------

def _matches(text: str, patterns: list[str]) -> str | None:
    low = text.lower()
    for p in patterns:
        if re.search(p.lower(), low):
            return p
    return None


def suspicious_reason(url: str, domains: dict) -> str | None:
    p = _matches(url, domains.get("suspicious_url_patterns", []))
    return f"suspicious pattern: {p}" if p else None


def public_ip_host(url: str) -> str | None:
    """If `url`'s host is a literal *public* IP address, return it, else None.

    Raw public-IP endpoints are a hallmark phishing signature and destabilize
    extensions, so index `baseUrl`/`url` fields must be DNS names. Loopback and
    private/ULA addresses are allowed so self-hosted server extensions (e.g.
    Komga defaulting to 127.0.0.1:25600) still build.
    """
    try:
        h = (urllib.parse.urlsplit(url).hostname or "").strip("[]")
    except ValueError:
        return None
    if not h:
        return None
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return None  # not an IP literal -> fine
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        return None
    if ip.is_reserved or ip.is_multicast or ip.is_unspecified:
        return None
    return h


def blocked_host_reason(host: str, domains: dict) -> str | None:
    p = _matches(host, domains.get("blocked_host_patterns", []))
    return f"blocked host pattern: {p}" if p else None


def adult_blocked(text: str, domains: dict) -> str | None:
    """Return the matching adult-content pattern, or None."""
    return _matches(text or "", domains.get("adult_patterns", []))


def check_url_allowed(url: str, domains: dict, *, executable: bool = False) -> tuple[bool, str]:
    """Check that a URL referenced by an index entry is on the trust list.

    executable=True additionally requires it to be an allowlisted repo artifact
    (raw.githubusercontent.com/<allowlisted repo>/... or jsdelivr gh/allowlisted).
    Returns (ok, reason).
    """
    if not isinstance(url, str) or not url:
        return False, "empty url"
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return False, "unparseable url"
    if parts.scheme != "https":
        return False, f"scheme not https: {parts.scheme!r}"
    host = (parts.hostname or "").lower()
    if not host:
        return False, "no host"
    r = suspicious_reason(url, domains)
    if r:
        return False, r
    r = blocked_host_reason(host, domains)
    if r:
        return False, r

    gh_repos = set(domains.get("github_repos", []))

    if host == "raw.githubusercontent.com":
        segs = parts.path.lstrip("/").split("/")
        if len(segs) < 2:
            return False, "malformed raw.githubusercontent path"
        repo = f"{segs[0]}/{segs[1]}"
        if repo not in gh_repos:
            return False, f"repo not allowlisted: {repo}"
        if executable and len(segs) < 4:
            return False, "missing ref/path in raw url"
        return True, "ok"

    if host == "cdn.jsdelivr.net":
        m = re.match(r"^/gh/([^/@]+/[^/@]+)@", parts.path)
        if not m:
            return False, "jsdelivr url not a /gh/ repo url"
        if m.group(1) not in gh_repos:
            return False, f"jsdelivr repo not allowlisted: {m.group(1)}"
        return True, "ok"

    if host == "github.com":
        m = re.match(r"^/([^/]+/[^/]+)/", parts.path)
        if not m or m.group(1) not in gh_repos:
            return False, f"github repo not allowlisted: {m.group(1) if m else parts.path}"
        if executable:
            # executables only from release assets of allowlisted repos
            if re.match(r"^/[^/]+/[^/]+/releases/download/", parts.path):
                return True, "ok"
            return False, "executable artifact must be a raw url or release asset"
        return True, "ok"

    if executable:
        return False, f"executable url host not allowlisted: {host}"

    spec = domains.get("hosts", {}).get(host)
    if spec is None:
        return False, f"host not allowlisted: {host}"
    prefixes = spec.get("path_prefixes")
    if prefixes and not any(parts.path.startswith(p) for p in prefixes):
        return False, f"path not under allowed prefix on {host}"
    if spec.get("require_jsdelivr_repo"):
        return False, "host requires jsdelivr repo check (use full gh url)"
    return True, "ok"


def is_safe_fetch_target(url: str, domains: dict) -> tuple[bool, str]:
    """Looser policy used only for downloading icons/images that are then
    re-hosted in this repository (never executed): https only, no suspicious
    patterns, no private/localhost hosts. Bytes must still pass image magic.
    """
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return False, "unparseable url"
    if parts.scheme != "https":
        return False, "scheme not https"
    host = (parts.hostname or "").lower()
    if not host:
        return False, "no host"
    r = suspicious_reason(url, domains)
    if r:
        return False, r
    r = blocked_host_reason(host, domains)
    if r:
        return False, r
    ok, reason = check_url_allowed(url, domains, executable=False)
    if ok:
        return True, "allowlisted"
    # allowed as a plain image fetch if it is not on any deny list above
    if "not allowlisted" in reason:
        return True, "arbitrary https image host (will be re-hosted)"
    return False, reason


def rewrite_our_url(url: str, raw_base: str, rel_path: str) -> str:
    return f"{raw_base}/{rel_path}"


def local_path_for_self_url(url: str, raw_base: str, root: Path) -> Path | None:
    """Map a raw.githubusercontent URL of this very repo to a local path."""
    if raw_base and url.startswith(raw_base + "/"):
        rel = url[len(raw_base) + 1:]
        return root / urllib.parse.unquote(rel)
    return None


# --------------------------------------------------------------------------
# Image / zip / dex helpers
# --------------------------------------------------------------------------

def image_kind(data: bytes) -> str | None:
    for magic, kind in IMAGE_MAGICS:
        if data.startswith(magic):
            return kind
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    return None


def validate_apk(data: bytes) -> tuple[bool, str, dict]:
    info: dict = {}
    if len(data) < 10 * 1024:
        return False, f"too small ({len(data)} bytes)", info
    if len(data) > 150 * 1024 * 1024:
        return False, f"too large ({len(data)} bytes)", info
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return False, "not a valid zip/apk", info
    names = zf.namelist()
    info["entries"] = len(names)
    if "AndroidManifest.xml" not in names:
        return False, "missing AndroidManifest.xml", info
    if not any(re.match(r"classes\d*\.dex$", n) for n in names):
        return False, "missing classes.dex", info
    top = sorted({n.split("/")[0] for n in names})
    info["top_level"] = top
    bad = [n for n in names if "\x00" in n or n.startswith("/") or ".." in n]
    if bad:
        return False, f"suspicious zip entry names: {bad[:3]}", info
    return True, "ok", info


def validate_cs3(data: bytes) -> tuple[bool, str, dict]:
    info: dict = {}
    if len(data) < 1024:
        return False, f"too small ({len(data)} bytes)", info
    if len(data) > 100 * 1024 * 1024:
        return False, f"too large ({len(data)} bytes)", info
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return False, "not a valid zip/.cs3", info
    names = zf.namelist()
    info["entries"] = len(names)
    dex = [n for n in names if re.match(r"classes\d*\.dex$", n)]
    if not dex:
        return False, "missing classes.dex", info
    bad = [n for n in names if "\x00" in n or n.startswith("/") or ".." in n]
    if bad:
        return False, f"suspicious zip entry names: {bad[:3]}", info
    info["dex"] = dex
    return True, "ok", info


_URL_IN_BYTES = re.compile(rb"https?://[\x21-\x7e]{4,300}")
_URL_IN_TEXT = re.compile(r"https?://[\x21-\x7e]{4,300}")
_TRAILING = "\"'`<>)].,;:}]\\|"


def _clean_url(u: str) -> str:
    return u.rstrip(_TRAILING)


# IANA reserved TLDs used as placeholders in code (filemoon.example, default.example)
_RESERVED_TLDS = {"example", "invalid", "test", "localhost", "local", "internal"}


def hosts_from_text(text: str) -> tuple[set[str], list[str]]:
    """Extract hosts from URLs appearing in text (JS source, dex strings...).

    Template-literal interpolations are cut at `${` and reserved-TLD
    placeholders (foo.example) are skipped so they don't pollute host review.
    """
    urls = [_clean_url(m) for m in _URL_IN_TEXT.findall(text)]
    hosts: set[str] = set()
    for u in urls:
        if "${" in u:
            u = u.split("${", 1)[0]  # https://${domain}/path -> https://
        if len(u) < 10:
            continue
        try:
            h = urllib.parse.urlsplit(u).hostname
        except ValueError:
            continue
        if not h:
            continue
        h = h.lower().rstrip(".")
        if h.rsplit(".", 1)[-1] in _RESERVED_TLDS:
            continue
        hosts.add(h)
    return hosts, urls


def dex_artifact_report(data: bytes, domains: dict) -> dict:
    """Extract http(s) hosts referenced inside classes*.dex of an apk/.cs3 zip.

    Returns {'hosts': [...], 'urls': [...], 'suspicious': [...]}.
    """
    hosts: set[str] = set()
    urls: list[str] = []
    suspicious: list[str] = []
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return {"error": "not a zip"}
    for name in zf.namelist():
        if not re.match(r"classes\d*\.dex$", name):
            continue
        blob = zf.read(name)
        for raw in _URL_IN_BYTES.findall(blob):
            u = _clean_url(raw.decode("latin1"))
            urls.append(u)
            r = suspicious_reason(u, domains)
            if r:
                suspicious.append(f"{u} ({r})")
                continue
            try:
                h = urllib.parse.urlsplit(u).hostname
            except ValueError:
                continue
            if h:
                hosts.add(h.lower())
    return {
        "hosts": sorted(hosts),
        "urls": sorted(set(urls)),
        "suspicious": sorted(set(suspicious)),
    }


def v1_cert_sha256(apk: bytes) -> str | None:
    """Best-effort: SHA-256 of the first X.509 certificate found in a v1
    signature block (META-INF/*.RSA|DSA|EC). Returns None when absent."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(apk))
    except zipfile.BadZipFile:
        return None
    for name in zf.namelist():
        if not name.upper().startswith("META-INF/") or not name.upper().endswith((".RSA", ".DSA", ".EC")):
            continue
        blob = zf.read(name)
        spki_oid = b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01"  # rsaEncryption
        # scan for DER SEQUENCE starts (0x30 0x82) whose declared length fits
        candidates = []
        for m in re.finditer(b"\x30\x82", blob):
            i = m.start()
            if i + 4 > len(blob):
                continue
            total = int.from_bytes(blob[i + 2:i + 4], "big") + 4
            if total <= 4 or i + total > len(blob):
                continue
            seg = blob[i:i + total]
            if spki_oid in seg and b"\x06\x03\x55\x04\x03" in seg:  # subject CN
                candidates.append(seg)
        if candidates:
            cert = max(candidates, key=len)
            return hashlib.sha256(cert).hexdigest()
    return None


# --------------------------------------------------------------------------
# Output helpers
# --------------------------------------------------------------------------

def write_json(path: Path, obj, *, minified: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if minified:
        text = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    else:
        text = json.dumps(obj, ensure_ascii=False, indent=2) + "\n"
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def slugify(name: str) -> str:
    s = re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-")
    return s or "unnamed"


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)
