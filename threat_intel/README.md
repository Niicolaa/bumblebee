# Threat Intelligence Exposure Catalogs

Maintained exposure catalogs for recent supply-chain campaigns, built from
public threat-intelligence reporting with
[Perplexity Computer](https://www.perplexity.ai/computer) and updated via
PRs as fresh campaigns are reported.

Pass a catalog to a scan with `--exposure-catalog <path>`. Review
the entries against current advisories before production use.

## Auto-generated catalogs (`auto-*.json`)

Files named `auto-*.json` are produced by the `threatintel-fetch` tool
(`cmd/threatintel-fetch`) and refreshed daily by the
[`threat-intel-sync`](../.github/workflows/threat-intel-sync.yml) GitHub
Actions workflow. Do not hand-edit them — your changes will be
overwritten on the next run. To fix a false positive, open an issue
upstream against the source feed.

Upstream license and attribution notices for each source are collected
in [`NOTICES.md`](NOTICES.md) — preserve that file when redistributing
this directory.

Sources:

| File pattern | Upstream | Ecosystem |
|---|---|---|
| `auto-malext-sentry-browser-extensions.json` | [toborrm9/malicious_extension_sentry](https://github.com/toborrm9/malicious_extension_sentry) | `browser-extension` (Chrome/Chromium IDs) |
| `auto-extsentry-browser-extensions.json` | [ExtSentry/ExtSentry.github.io](https://github.com/ExtSentry/ExtSentry.github.io) (rebuilt hourly from [mthcht/awesome-lists](https://github.com/mthcht/awesome-lists)) | `browser-extension` (Chrome/Chromium IDs; carries CRX SHA256 and per-row severity/category) |
| `auto-vsxsentry-editor-extensions.json` | [mthcht/awesome-lists VSCODE Extensions](https://github.com/mthcht/awesome-lists/tree/main/Lists/VSCODE%20Extensions) | `editor-extension` (VS Code `publisher.name`) |
| `auto-osv-malicious-npm-NN.json` (×4 shards) and `auto-osv-malicious-{pypi,go,rubygems,packagist,nuget,crates.io,maven}.json` | [ossf/malicious-packages](https://github.com/ossf/malicious-packages) (mirrored via [osv.dev](https://osv.dev)) | one file per ecosystem; npm is sharded by `FNV32(package) % 4` so each shard stays under ~25 MB |
| `auto-datadog-malicious-{npm,pypi}.json` | [DataDog/malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset) | flagged by Datadog's [GuardDog](https://github.com/DataDog/guarddog) static-analysis pipeline — independent detector relative to OSV |

Auto-generated entries use `versions: ["*"]` when the upstream feed
treats package presence (extension ID, package name) as the IOC and
does not enumerate affected versions — see the schema note in
`internal/exposure/exposure.go`.

## Fetching the catalogs

The [`threat-intel-sync`](../.github/workflows/threat-intel-sync.yml)
workflow publishes a GitHub Release named `threat-intel-YYYY-MM-DD` on
every day the feeds change. Assets are CDN-cached and need no auth or
API token:

```
# Whole set (fixed name — always the newest snapshot):
curl -fsSLO https://github.com/<owner>/<repo>/releases/latest/download/threat-intel-latest.tar.gz
tar -xzf threat-intel-latest.tar.gz

# One file:
curl -fsSLO https://github.com/<owner>/<repo>/releases/latest/download/auto-osv-malicious-npm-00.json

# Integrity check:
curl -fsSLO https://github.com/<owner>/<repo>/releases/latest/download/SHA256SUMS
sha256sum -c SHA256SUMS
```

The tarball is the whole directory including `NOTICES.md`, so a daily
`curl | tar` is the entire update procedure — the snapshot is atomic by
construction and there is nothing to reconcile against local state.

Every daily release is retained as a point-in-time snapshot; pin to a
dated tag (`releases/download/threat-intel-2026-08-04/…`) instead of
`latest` when reproducibility matters.

Cloning the repo works too — `threat_intel/` on `main` is the same
content the release is cut from.

### How the daily sync stays safe without a PR review

The workflow commits straight to `main` — no PR gate. What makes that
safe is the shrink guard in
[`cmd/threatintel-fetch/guard.go`](../cmd/threatintel-fetch/guard.go):
before anything is committed, each catalog's new entry count is compared
against its previous count, and the run fails if any catalog drops below
50% (or disappears entirely). That's the failure mode that actually
matters here — an upstream renaming a CSV column or serving an error
page yields a catalog that parses cleanly but is empty, which no human
skimming a 200k-line diff would reliably catch either. Override with
`--min-ratio=0` (or the `min_ratio` workflow-dispatch input) when a
large drop is legitimate.

## Catalogs

| File | Campaign | Source |
|---|---|---|
| [`mastra-2026-06-17.json`](mastra-2026-06-17.json) | Mastra npm supply-chain compromise (141 packages / 141 versions across `@mastra/*` plus `create-mastra` and the `easy-day-js@1.11.22` typosquat dependency that delivered a cross-platform infostealer via postinstall) | [Socket, 2026-06-17](https://socket.dev/blog/mastra-npm-packages-compromised) |
| [`mini-shai-hulud-leoplatform-2026-06-24.json`](mini-shai-hulud-leoplatform-2026-06-24.json) | Mini Shai-Hulud / Miasma (Hades variant) LeoPlatform/RStreams wave (compromised `czirker` npm account; 26 npm packages + 1 Go module / 27 versions; "Phantom Gyp" `binding.gyp` install hook, Bun-staged infostealer, "Alright Lets See If This Works" dead-drop marker) | [Socket, 2026-06-24](https://socket.dev/blog/miasma-mini-shai-hulud-hits-leoplatform-npm-packages-go-ecosystem); [OX Security, 2026-06-24](https://www.ox.security/blog/alright-lets-see-if-this-works-shai-hulud-miasma-hades-variant-spreads-on-npm/) |
| [`mini-shai-hulud.json`](mini-shai-hulud.json) | Mini/Shai-Hulud May 2026 npm and PyPI compromise (OX Security affected-package table) | Cross-checked against Fleet, Socket, Snyk, Mistral, TanStack, The Hacker News |
| [`mini-shai-hulud-redhat-cloud-services.json`](mini-shai-hulud-redhat-cloud-services.json) | Mini Shai-Hulud compromise of Red Hat Cloud Services (`@redhat-cloud-services`) npm packages (32 packages / 95 versions; "Miasma: The Spreading Blight" worm marker) | [Socket, 2026-06-01](https://socket.dev/blog/mini-shai-hulud-campaign-hits-red-hat-cloud-services-npm-packages) |
| [`laravel-lang-2026-05-23.json`](laravel-lang-2026-05-23.json) | Laravel Lang Composer/Packagist supply-chain compromise across `laravel-lang/lang`, `laravel-lang/http-statuses`, `laravel-lang/attributes`, and `laravel-lang/actions` | [Socket, 2026-05-23](https://socket.dev/blog/laravel-lang-compromise) |
| [`nx-console-vscode-2026-05-18.json`](nx-console-vscode-2026-05-18.json) | Nx Console VS Code extension (`nrwl.angular-console` 18.95.0) compromise published to the VS Code Marketplace on 2026-05-18 (OpenVSX unaffected; remediated in 18.100.0+) | [StepSecurity, 2026-05-18](https://www.stepsecurity.io/blog/nx-console-vs-code-extension-compromised) |
| [`antv-mini-shai-hulud.json`](antv-mini-shai-hulud.json) | AntV / Mini Shai-Hulud May 2026 npm worm wave (324 packages / 643 versions across npm and PyPI; scoped to artifacts detected on or after 2026-05-13) | [Socket, 2026-05-19](https://socket.dev/blog/antv-packages-compromised) |
| [`node-ipc-credential-stealer.json`](node-ipc-credential-stealer.json) | `node-ipc` npm 2026-05 credential-stealer compromise (7 malicious versions) | [Socket, 2026-05-14](https://socket.dev/blog/node-ipc-package-compromised) |
| [`shopsprint-decimal-typosquat.json`](shopsprint-decimal-typosquat.json) | Go `github.com/shopsprint/decimal` v1.3.3 typosquat with DNS TXT backdoor | [Socket, 2026-05-19](https://socket.dev/blog/popular-go-decimal-library-typosquat-dns-backdoor) |
| [`gemstuffer.json`](gemstuffer.json) | GemStuffer RubyGems exfiltration campaign (123 gems / 155 versions) targeting UK local government | [Socket, 2026-05-13](https://socket.dev/blog/gemstuffer) |
| [`glassworm.json`](glassworm.json) | GlassWorm self-propagating IDE-extension worm on Open VSX / VS Code (invisible-Unicode loader, transitive extensionPack/Dependencies delivery, Solana memo C2, credential/wallet theft); 243 `editor-extension` packages / 381 versions + 2 npm packages / 2 versions (245 entries / 383 versions) | [Socket GlassWorm v2 campaign CSV](https://socket.dev/supply-chain-attacks/glassworm-v2) and [Socket transitive report, 2026-03-13](https://socket.dev/blog/open-vsx-transitive-glassworm-campaign); supplemented by [Koi Security, 2025-10-18](https://www.koi.ai/blog/glassworm-first-self-propagating-worm-using-invisible-code-hits-openvsx-marketplace), [Checkmarx, 2026-03](https://checkmarx.com/zero-post/glassworm-targets-developer-ides-again-hiding-staged-malware-behind-runtime-rebuilt-loaders/), and [Sonatype, 2026-03-17](https://www.sonatype.com/blog/hijacked-npm-packages-deliver-malware-via-solana-linked-to-glassworm) |
| [`trapdoor-crypto-stealer.json`](trapdoor-crypto-stealer.json) | TrapDoor Crypto Stealer cross-ecosystem credential/wallet stealer across npm, PyPI, and Cargo/Crates.io (34 entries: 28 npm/PyPI / 378 versions, plus 6 `crates.io` packages promoted from the former `_cargo_packages` block now that Cargo is inventoried) | [Socket, 2026-05-24](https://socket.dev/blog/trapdoor-crypto-stealer-npm-pypi-crates) |

## Generating catalogs from OSV

`tools/osvcatalog` converts a local [OSV](https://osv.dev) snapshot into
a catalog offline. Bumblebee never queries osv.dev at scan time. Only
malicious-package records (`MAL-` ids, or records aliased to one) are
emitted, with `severity: "critical"`.

Two input shapes are supported. Pick one based on coverage.

**OSSF malicious-packages repo** (recommended, all ecosystems in one
tree):

```sh
git clone --filter=blob:none --sparse --depth=1 \
  https://github.com/ossf/malicious-packages.git mp
git -C mp sparse-checkout set osv/malicious
go run ./tools/osvcatalog \
  -source "https://github.com/ossf/malicious-packages@$(git -C mp rev-parse HEAD)" \
  -o threat_intel/osv-malicious.json mp/osv/malicious/
```

**OSV per-ecosystem dump** (single ecosystem, zip archive):

```sh
curl -fsSLO https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip
go run ./tools/osvcatalog -o threat_intel/osv-npm-malicious.json npm/all.zip
```

Each input path can be a directory tree, an OSV `all.zip` archive, or a
single `.json` record. Supported OSV ecosystems map to Bumblebee as:
`npm`, `PyPI` → `pypi`, `Go` → `go`, `RubyGems` → `rubygems`,
`Packagist` → `packagist`, `VSCode` → `editor-extension`,
`NuGet` → `nuget`, `crates.io` → `crates.io`, `Maven` → `maven`,
`Pub` → `pub`, `Hex` → `hex`, `SwiftURL` → `swift`, `Julia` → `julia`.
Of those, only npm, PyPI, Go, RubyGems, Packagist, NuGet, crates.io and
Maven currently carry any `MAL-*` advisories upstream, so only those are
fetched by `threatintel-fetch`; the rest are mapped so they flow through
the converter the day upstream publishes one. Records whose
ranges declare all versions affected (a single `introduced: "0"` event)
are emitted with `"versions": ["*"]`; records with only bounded ranges
and no enumerated `affected[].versions` are skipped. Output is
deterministic, validates against the schema, and should be reviewed
before use. The generated `_comment` records scope, per-ecosystem
counts, skip-reason breakdown, and the optional `-source` provenance
label.
