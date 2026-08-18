# Contributing to bumblebee

Thanks for your interest. This project favours small, focused changes
with tests.

## Local development

Requires Go 1.25+. One runtime dependency, `pelletier/go-toml/v2`.

New dependencies are close to never accepted. This binary runs as root or
SYSTEM on every endpoint in a fleet, so its own supply chain is part of the
threat model, and a small `go.mod` is what keeps that auditable. The TOML
parser earned its place by evidence: a hand-rolled reader silently rejected
2 of 40 real lockfiles, and in a scanner a rejected file reads as "this
machine is clean". If you want to add one, bring that kind of evidence, and
prefer libraries with no transitive dependencies.

```sh
go build ./cmd/bumblebee
go test ./...
go test -race ./...
go vet ./...
gofmt -l .   # should print nothing
./bumblebee selftest
```

## Pull requests

- Keep PRs small and focused. Separate refactors from behaviour changes.
- Match the existing conventional-commits style for commit subjects:
  `fix(scope): ...`, `feat(scope): ...`, `docs: ...`, `ci: ...`.
- Add or update tests for behaviour changes. Prefer ephemeral fixtures
  (`t.TempDir()` + inline strings) over committed `testdata/` files
  unless a fixture is needed by multiple tests.
- Update `README.md` when adding or changing a user-facing flag, profile,
  ecosystem, or output field.

## Adding an exposure catalog

New catalogs land under `threat_intel/`. Before submitting:

- Validate against the published schema. A quick check, using the
  Python `jsonschema` package (`pip install jsonschema`):

  ```sh
  python3 -c "import json, jsonschema; \
    jsonschema.validate(json.load(open('threat_intel/your-catalog.json')), \
      json.load(open('docs/schema/v0.2.0/exposure-catalog.schema.json')))"
  ```

- Include a `_comment` field at the catalog root with the methodology
  and source for the entries. Keep this on existing catalogs when
  editing.
- Use a documented severity value (`critical` is the only one used by
  shipped catalogs today; if you introduce a new value, justify it in
  the PR description).
- Include `source` on each entry pointing at the public advisory or
  research writeup that backs it.

Catalogs can also be generated offline from OSV data with
`tools/osvcatalog`; see [`threat_intel/README.md`](threat_intel/README.md).

## Schema changes

Any change to a published `docs/schema/<version>/*.json` or the wire
format that breaks existing consumers is a breaking change. Land it as a
new version directory (e.g. `docs/schema/v0.3.0/`) and bump
`model.SchemaVersion` together; do not edit a published schema in place.

One deliberate exception: **adding a value to the `ecosystem` enum is
widening, not breaking**, and is done in place on the current schema
version. A new ecosystem adds records a consumer has never seen, which is
the same situation as a consumer meeting a package manager it does not
handle — it does not change the meaning or shape of any existing field.
Forcing a version bump per ecosystem would either stall coverage behind a
schema release or leave the tool emitting values its own published schema
rejects, which is what happened when `agent-skill` shipped without a
schema update. Everything else about a published schema stays frozen.

Older version directories are historical and are never widened: a record
stamped `schema_version: 0.1.0` came from a binary that could not emit
the newer ecosystems anyway. Use the current version for new catalogs.

When adding an ecosystem, update the enum in all three of
`package-record.schema.json`, `finding-record.schema.json`, and
`exposure-catalog.schema.json` under the current version directory. They
must agree with `supportedEcosystemOrder` in
[`internal/model/model.go`](internal/model/model.go).

## Security issues

Do not file public issues for vulnerabilities. See `SECURITY.md`.
