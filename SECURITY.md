# Security & Vetting Policy

## Why this repo exists

Extension repositories for Dartotsu are plain JSON files served from arbitrary URLs. The app
trusts them completely: an index decides which APK/JS/.cs3 gets downloaded and executed with no
further verification. A hostile or compromised index can:

1. Point `url`/`apk`/`scriptUrl` at **phishing or malware hosting** on any domain.
2. **Swap binaries in place** — same URL, new contents (supply-chain tampering).
3. Ship **compiled plugins** (CloudStream `.cs3`, Aniyomi APKs) whose code phones home to
   attacker infrastructure.
4. Slip **NSFW or scam entries** (fake "update required" extensions, paid-walls) into an
   otherwise legitimate list.

This repository defends against all four with a build-time vetting pipeline plus CI re-checks.

## Threat model

| Threat | Mitigation |
|---|---|
| Index entry references attacker-controlled host | Every URL must pass the domain/repo allowlist in `policy/domains.json`; executable artifacts only from allowlisted repositories (`raw.githubusercontent.com/<repo>`, jsDelivr `/gh/<repo>`, GitHub release assets of allowlisted repos) |
| Binary swapped upstream after we mirror it | Binaries are re-hosted **in this repo** and pinned by SHA-256 in `checksums.json`; CI fails on any drift. CloudStream plugins are additionally checked against the publisher's declared `fileHash` (`sha256-...`) at build time |
| Malicious compiled code exfiltrating data | `classes.dex` string scan at build time — any URL inside the compiled artifact is extracted; URL patterns for paste sites, webhook endpoints, URL shorteners, tunneling/probe services and login/credential-lure wording cause a hard build failure; all extracted hosts are recorded per-artifact in `build-report.json` for review |
| Malicious Sora module script | JS is mirrored and scanned: every referenced host must belong to the module's own declared hosts (baseUrl/searchBaseUrl etc.), an allowlisted CDN, or `sora.extra_allowed_hosts` — an explicit list where **every entry carries a written review note** (source-inspected before allowlisting, template-literal placeholders are stripped first); otherwise the module is dropped and listed in the build report for manual review |
| Upstream ships dead/broken asset URLs | Repaired via `mangayomi.overrides` (written reason + re-verified URL), sources whose sites no longer resolve are excluded via `mangayomi.exclude_ids`; both are recorded in `build-report.json` and re-verified by CI (`--online` fails only on definitive 404/410) |
| NSFW / adult content | Three layers: upstream flags (`nsfw`, `CONTENT_WARNING_*`), name/description/tvType heuristics (`adult_patterns`), and explicit allowlists for the Aniyomi catalogs |
| Stale/compromised policy | `policy/*.json` hashes recorded in `build-report.json`; `verify.py` warns when policy drifted without a rebuild; CI runs on every push + weekly |

## Trust tiers

Every included CloudStream upstream is tagged in `policy/upstreams.json`:

- **verified** — official project organizations (e.g. `recloudstream/extensions`). Their
  `.cs3` files publish `fileHash`, which we verify byte-for-byte.
- **community** — established third-party repos that are listed in the official
  [`recloudstream/cs-repos`](https://github.com/recloudstream/cs-repos) database, serve all
  artifacts from their own allowlisted GitHub repo, publish hashes, and pass every automated
  content check (dex scan, adult filter, liveness).

> **Note on `phisher98/cloudstream-extensions-phisher`**: despite the handle, this is one of
> the most widely used community CloudStream repos (510★), is listed in the official CloudStream
> repo database, serves every plugin from its own GitHub repo with declared SHA-256 hashes, and
> passed the full content audit during the initial build (dex string scan showed only scraping
> target sites — no webhooks, paste sites, IP literals or credential-lure URLs). It is included
> at `community` tier. To exclude it, set `"enabled": false` for that entry in
> `policy/upstreams.json` and rebuild.

## What is checked at build time

**Schema & structure**
- Aniyomi: `Aniyomi:`/`Tachiyomi:` name prefix, `pkg`/`apk` filename sanity, non-empty
  `sources[]`, https `baseUrl` per source, unique pkg/apk.
- Mangayomi: correct `itemType` per file, allowlisted `sourceCodeUrl` (executable) and
  `iconUrl`, non-nsfw flag, unique ids.
- Sora: required fields (`sourceName`, `baseUrl`, `language`, `version`, `scriptUrl`), type
  limited to `anime`/`movie`/`mangas` (the only values Dartotsu displays), unique names,
  https DNS-name `baseUrl` (public-IP hosts dropped).
- CloudStream: unique `internalName`, no `status: 0` (down), no paid entries, required
  `language`/`version`, `.cs3` must be a valid zip containing `classes.dex`.

**Binary content**
- APK/`.cs3`: valid zip, must contain `AndroidManifest.xml` + `classes.dex`, size bounds,
  no path-traversal/NUL entry names.
- SHA-256 of every mirrored file recorded in `checksums.json`.
- Best-effort APK signer certificate extraction (v1 blocks) compared against the index's
  declared `signingKey` — mismatches are recorded as warnings in `build-report.json`.

**URL hygiene**
- Suspicious-URL pattern list (shorteners, paste sites, webhooks, tunnelers, credential-lure
  wording) applied to every referenced URL — including URLs found *inside* compiled code.
- Private/localhost/IPv4/IPv6 hosts blocked for all fetches.
- Index `baseUrl`/`url` fields must be DNS names: public-IP endpoints are dropped at build
  (`public_ip_host` drop reason) as a phishing-red-flag and stability heuristic. Loopback
  (`127.0.0.1`, e.g. Komga's self-hosted default) and private/LAN ranges are kept because
  local-server extensions legitimately default to them.
- Post-redirect final URL is validated too (no redirecting allowlisted URLs to foreign hosts).

**NSFW**
- `nsfw != 0`, `CONTENT_WARNING_NSFW`, and `adult_patterns` name/description matches are
  dropped and counted per reason in `build-report.json`.
- Aniyomi catalogs use an explicit allowlist of source names; `include_mixed` additionally
  approves individually-vetted `CONTENT_WARNING_MIXED` sources (e.g. MangaDex) whose mixed
  status comes from having some mature-tagged titles, not from being adult extensions.

## What CI verifies

`.github/workflows/verify.yml` runs on every push/PR and weekly:

1. `scripts/verify.py` — recomputes every SHA-256, re-validates every index entry against the
   current policy, confirms every self-referencing URL maps to a file that exists, rejects
   untracked files inside managed output dirs.
2. `scripts/verify.py --online` — every external URL (Mangayomi source/icon URLs) must still
   return HTTP 200.

A red CI means either the repository was tampered with or an upstream rotted; both need
attention before anything is published from it.

## Known limitations (be aware)

- **Compiled code is scanned, not audited.** The dex string scan catches obvious exfil
  endpoints but cannot prove a plugin is benign. Prefer `verified`-tier repos where possible.
- **Dartotsu does not verify hashes at install time.** `checksums.json` protects the
  repository contents, not the client-side install path. The safety property comes from *this*
  repo being the thing you install from and being CI-verified.
- **Upstream sites themselves are untrusted.** Extension `baseUrl`s are streaming/scraping
  targets; this repo vets the *extension*, not the sites they scrape.
- **Signing cert check is best-effort** (v1 signature blocks only; many modern APKs are
  v2/v3-only). Mismatches are warnings, not failures, because index `signingKey` formats vary.
- **Mangayomi extensions are not mirrored** — their Dart source is fetched from the vetted
  upstream at install time. The URLs are allowlist-checked at every build, but the upstream
  can still change contents (they are an established, SFW-filtered catalog with pinned
  source-code URLs).

## Reporting a problem

If you find an extension, host or entry in this repo that looks malicious:

1. Open an issue with the entry name, the index file, and the suspicious URL/behaviour.
2. For an immediate fix, add the repo/package/name to `policy/blocklist.json` (with a reason)
   or disable the upstream in `policy/upstreams.json`, then run `scripts/build.py` and
   `scripts/verify.py`.
3. Pin the malicious URL pattern into `suspicious_url_patterns` in `policy/domains.json` so
   it can never be published again.

Rebuild, verify, commit, and open a PR.
