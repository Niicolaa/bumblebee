# CLAUDE.md

Guidance for Claude Code when working in this repository.

## What this is

`bumblebee` is a read-only inventory collector for package, extension,
and developer-tool metadata on macOS, Linux, and Windows developer
endpoints. It emits NDJSON component records and, given an exposure
catalog, flags exact `(ecosystem, name, version)` matches.

Module path: `github.com/perplexityai/bumblebee`. Go 1.25+.

## Hard constraints

These are the project's defining properties. Do not break them.

- **Zero non-stdlib dependencies.** `go.mod` has no `require` block and
  must stay that way. Never add a third-party library; write it against
  the stdlib or don't do it.
- **Read-only.** The scanner never executes a package manager
  (`npm ls`, `pip show`, `go list`, ...), never writes to scanned
  directories, and never makes network calls except the explicit
  `--output=http` sink. `cmd/threatintel-fetch` is the one component
  that fetches from the network, and it is separate from the scanner.
- **Metadata files only.** Parsers read lockfiles, package-manager
  install metadata, extension manifests, and the MCP JSON configs listed
  in `docs/inventory-sources.md`. No source-file reads.
- **No secret emission.** MCP host configs carry credentials in their
  `env` blocks. Parse them for the server inventory, never emit those
  values into records.
- **Cross-platform.** CI runs on ubuntu, macos, and windows. Use
  `filepath` (not string joins) for native paths; if a parser normalizes
  with `filepath.ToSlash`, convert back with `filepath.FromSlash` before
  putting a path in a record. Tests must not assert on `/`-separated
  path literals.

## Build and test

```sh
go build ./cmd/bumblebee
go test ./...
go test -race ./...
go vet ./...
gofmt -l .        # must print nothing
./bumblebee selftest
```

CI (`.github/workflows/ci.yml`) runs gofmt, vet, `go test -race`, build,
and `selftest` on all three OSes, plus `govulncheck`. `.gitattributes`
pins LF for Go sources so the Windows runner's gofmt check stays
meaningful.

## Layout

| Path | Role |
|---|---|
| `cmd/bumblebee` | CLI: `scan`, `roots`, `selftest`, `version`. Flag registration lives in `registerScanFlags` in `main.go`; root resolution per profile/OS in `roots.go`. |
| `cmd/threatintel-fetch` | Daily job building `threat_intel/auto-*.json` from public feeds (one file per source). |
| `tools/osvcatalog` | Offline OSV-to-catalog generator. |
| `internal/ecosystem/<name>` | One package per ecosystem parser (npm, pnpm, yarn, bun, pypi, pylock, gomod, rubygems, composer, nuget, cargo, maven, swiftpkg, dartelixir, mcp, skills, editorext, browserext, homebrew). |
| `internal/toml` | Restricted TOML reader for lockfiles (Cargo, poetry, uv, PEP 751). Structural damage is fatal; unmodelled values are recorded as unsupported, never dropped. |
| `internal/scanner/dispatch.go` | Typed `jobKind` constants and the walker→parser handler table. |
| `internal/walk` | Filesystem walker, exclude handling, per-OS dir-identity helpers. |
| `internal/scanner` | Orchestration: walk → parse → emit, plus finding generation. |
| `internal/exposure` | Catalog loading and matching. |
| `internal/model` | Record types, `SchemaVersion`, profile/ecosystem constants. |
| `internal/output` | stdout/file/HTTP sinks. |
| `internal/normalize`, `internal/endpoint` | Name normalization; endpoint metadata. |
| `docs/schema/v*/` | Published JSON Schemas. |
| `threat_intel/` | Shipped and auto-generated exposure catalogs. |

## Conventions

- Conventional-commit subjects: `feat(scope): ...`, `fix(scope): ...`,
  `docs: ...`, `ci: ...`, `test(scope): ...`. Keep changes small and
  separate refactors from behaviour changes.
- Tests prefer ephemeral fixtures (`t.TempDir()` + inline strings) over
  committed `testdata/`, unless a fixture is shared by several tests.
- Update `README.md` when adding or changing a user-facing flag,
  profile, ecosystem, or output field. Update
  `docs/inventory-sources.md` when changing which files a parser reads.
- Never edit a published schema under `docs/schema/<version>/` in place.
  A breaking wire-format change lands as a new version directory with a
  matching `model.SchemaVersion` bump.
- New exposure catalogs need a root `_comment` with methodology, a
  `source` on each entry pointing at public reporting, and validation
  against the current schema. See `CONTRIBUTING.md` and
  `threat_intel/README.md`.

## Adding an ecosystem parser

1. New package under `internal/ecosystem/<name>/`.
2. Add the emitted `ecosystem` value to `internal/model` — the constant
   plus `supportedEcosystemOrder` (the lookup set is derived from it).
3. Add a `jobKind` constant, an `allJobKinds` entry, and a handler in
   `internal/scanner/dispatch.go`, then a walker case in `scanner.go`.
   `TestEveryJobKindHasHandler` catches a missed handler.
4. Set `confidence` honestly: `high` only for exact identity+version
   from canonical metadata, `medium` for partial version/source, `low`
   for config or path references that are not proof of an install.
5. Document the exact files read in `docs/inventory-sources.md` and add
   a row to the README coverage table.
