# Dartotsu Safe Extensions

A **curated, security-vetted extension repository** for [Dartotsu](https://github.com/RyanYuuki/Dartotsu),
covering all four extension ecosystems: **Aniyomi, Mangayomi, Sora and CloudStream**.

Third-party extension repos are a known attack vector — indexes have been spotted pointing at
phishing hosts, serving tampered APKs, or quietly swapping download URLs. This repository exists
because of exactly that: every upstream is allowlisted, every entry is filtered, every binary is
mirrored, content-checked and pinned by SHA-256, and a CI job re-verifies everything on every push.

## Add to Dartotsu

Replace `USER/REPO` with where you forked this repository (defaults below assume
`sleepy-shan/dartotsu-safe-extensions` on branch `main`).

Raw base URL:

```
https://raw.githubusercontent.com/sleepy-shan/dartotsu-safe-extensions/main
```

| Ecosystem | Index URL | Where to add it |
|---|---|---|
| **Aniyomi** (anime + manga) | `<RAW_BASE>/index.min.json` | Settings → Extensions → **Anime** repos *and* **Manga** repos (the same URL works for both — entries are split by their `Aniyomi:`/`Tachiyomi:` name prefix) |
| **Mangayomi** – manga | `<RAW_BASE>/mangayomi/index.json` | Manga extension repo |
| **Mangayomi** – anime | `<RAW_BASE>/mangayomi/anime_index.json` | Anime extension repo |
| **Mangayomi** – novel | `<RAW_BASE>/mangayomi/novel_index.json` | Novel extension repo |
| **Sora** | `<RAW_BASE>/sora/index.json` | Anime extension repo (type `mangas` modules also show under Manga) |
| **CloudStream** | `<RAW_BASE>/cloudstream/repo.json` | Anime/extension repo (CloudStream has a single repo list) |

One-tap deep links (Dartotsu handles these schemes):

```
aniyomi://add-repo?url=<encoded index.min.json URL>          (anime)
tachiyomi://add-repo?url=<encoded index.min.json URL>        (manga)
sora://add-repo?url=<encoded sora/index.json URL>
cloudstreamrepo://raw.githubusercontent.com/sleepy-shan/dartotsu-safe-extensions/main/cloudstream/repo.json
dar://add-repo?repo_url=<anime_index>&manga_url=<index>&novel_url=<novel_index>
```

## What's inside

```
index.min.json              Aniyomi-format index (anime + manga entries, split by name prefix)
icon/<pkg>.png              Mirrored extension icons
apk/<name>.apk              Mirrored Aniyomi APKs (the app derives APK URLs from the index location,
                            so binaries MUST be hosted in-repo)
mangayomi/index.json        Mangayomi manga catalog (passes upstream through, SFW-filtered)
mangayomi/anime_index.json  Mangayomi anime catalog
mangayomi/novel_index.json  Mangayomi novel catalog
sora/index.json             Aggregated Sora modules (scripts/icons re-hosted in sora/)
sora/js/<name>.js           Mirrored Sora module scripts
cloudstream/repo.json       Aggregated CloudStream plugins (.cs3 mirrored under cloudstream/plugins/)
checksums.json              SHA-256 of every generated file and mirrored binary
build-report.json           Full vetting report of the last build (drops per reason, warnings, host scans)
policy/                     The trust policy: upstream allowlist, domain allowlist, blocklist
scripts/build.py            Rebuilds everything from policy
scripts/verify.py           Verifies checksums, schema and URL policy (+ --online liveness)
```

## What gets filtered out

- **NSFW extensions** (`nsfw` flags, `CONTENT_WARNING_NSFW`, adult-name heuristics)
- Entries whose URLs leave the **domain/repo allowlist** (`policy/domains.json`)
- Anything matching the **blocklist** (`policy/blocklist.json`)
- CloudStream plugins with `status: 0` (down), paid plugins, adult-typed plugins
- Sora modules Dartotsu cannot display (missing type, novels/audio); `shows`/`movies`
  type variants are normalized to `movie` so they appear in the video section
- Binaries that fail content checks: malformed zips, missing `classes.dex`, suspicious URLs
  extracted from compiled code, JavaScript modules referencing hosts outside the module's own
  allowlist, `.cs3` files whose SHA-256 doesn't match the publisher's declared `fileHash`
- **Broken upstream data is repaired or excluded, never shipped broken**: dead icon paths and
  directory-URLs are repaired via `mangayomi.overrides` (each with a written reason and re-verified
  URL), and sources whose sites are dead are excluded via `mangayomi.exclude_ids`
  (see `policy/upstreams.json`)

## Rebuild

```bash
python3 scripts/build.py            # full rebuild from policy/
python3 scripts/build.py --only sora
python3 scripts/verify.py           # offline verification (checksums, schema, URL policy)
python3 scripts/verify.py --online  # + upstream URL liveness
```

`--online` fails only on **definitive dead URLs** (HTTP 404/410). Failures caused by the
checking environment — bot-blocks (403), DNS/geo filtering, TLS quirks, timeouts — are reported
as warnings, because the app or another network may still reach them.

Requires Python 3.10+ (stdlib only) and network access. Downloads are cached in `.cache/`.
Set `GITHUB_TOKEN` to avoid GitHub API rate limits (used for the Sora file tree).

To change what gets published, edit `policy/*.json` and re-run `build.py`, then commit the
regenerated indexes, binaries, `checksums.json` and `build-report.json`.

## Trust model (short version)

See [SECURITY.md](SECURITY.md) for the full write-up.

1. **Only allowlisted upstream repos** are ever fetched from (`policy/domains.json`).
2. **Everything executable is re-hosted here** (Aniyomi APKs, Sora JS, CloudStream `.cs3`,
   icons) so what you install is exactly what was vetted — pinned by SHA-256 in `checksums.json`.
3. **Content checks run at build time**: zip structure, dex string scans for exfil/phishing
   URLs, publisher-declared hash verification, JS host scans, name/URL heuristics.
4. **CI re-verifies on every push and weekly**; any drift fails the build.
5. Upstream repos are tiered (`verified` = official project orgs, `community` = established
   third parties whose content passed every automated check). Tiers are recorded in
   `build-report.json`.

## Publishing this repo

This project is built for you to host on your own GitHub account — everything unsafe about
third-party extension repos is mitigated because **you** own the mirror.

```bash
# 1. create the repo on github.com (e.g. dartotsu-safe-extensions)
# 2. then:
git init
git add .
git commit -m "vetted Dartotsu extension repo: aniyomi + mangayomi + sora + cloudstream"

git remote add origin https://github.com/YOUR_USERNAME/dartotsu-safe-extensions.git
git branch -M main
git push -u origin main
```

If your repo name/branch differs from `sleepy-shan/dartotsu-safe-extensions@main`, all mirror URLs
inside the built files embed the raw base. Regenerate before pushing so every URL points at *your* repo:

```bash
python3 scripts/build.py --repo-base https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/YOUR_BRANCH
python3 scripts/verify.py          # then re-run verify (offline + --online)
git add -A && git commit -m "point URLs at own repo" && git push
```

After pushing, the GitHub Actions workflow runs offline + online verification automatically.

## Notes

- Mangayomi entries reference the vetted upstream's source code/icons directly (the app
  downloads Dart source per extension; those URLs are allowlist-checked at every build).
- Aniyomi APKs are mirrored because Dartotsu derives APK/icon URLs from the *index location*.
- This project is not affiliated with Dartotsu, Aniyomi, Mangayomi, Sora or CloudStream.
