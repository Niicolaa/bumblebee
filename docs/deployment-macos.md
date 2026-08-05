# Deploying bumblebee on macOS

`bumblebee` is a one-shot binary with no built-in scheduler. On macOS
the typical pattern is to schedule it from `launchd`. The examples below
assume the plist is delivered by MDM, but the `launchd` mechanics are the
same regardless of how the file is installed.

Cadence is the runner's choice (cron, launchd, MDM, ...); the
profile only determines what gets walked. Typical deployment
shapes:

- `baseline` — bounded global/user package-manager and toolchain
  roots. Recurring, typically every 6 hours plus `RunAtLoad`.
- `project`  — configured developer/project roots. Recurring,
  typically daily or every 12 hours.
- `deep`     — exposure scan over operator-supplied roots. Typically
  on demand during a campaign; recurring is fine too (pair with
  `--findings-only` for a low-cost finding-only stream).

For backend data-modeling considerations see
[state-model.md](state-model.md).

## LaunchDaemon vs LaunchAgent

Pick one, not both.

- **LaunchDaemon** (`/Library/LaunchDaemons/`, runs as root). Useful when
  one pass should scan every user on the machine. Pass `--all-users` so
  `bumblebee` expands the profile's per-user default roots
  (`~/.nvm/versions`, `~/.vscode/extensions`, `~/Library/Application
  Support/Claude`, browser-extension profile dirs, etc.) across every
  real `/Users/<name>/` home automatically; system Python and Homebrew
  lib locations are still included exactly once. Records will carry the
  root user's identity in `endpoint.username` because the scanner
  process runs as root — `source_file` and `project_path` remain the
  source of truth for which user a given record belongs to.
- **LaunchAgent** (`/Library/LaunchAgents/`, runs per logged-in user under
  that user's UID). Each developer reports their own inventory under their
  own user identity. TCC prompts are owned by the user being scanned.

LaunchAgent is the safer default: per-user scope is what package
inventory actually represents.

## Root-owned runs with `--all-users`

A root-owned LaunchDaemon starts with `HOME=/var/root`. The profile
defaults would otherwise resolve to `/var/root/.nvm/...`,
`/var/root/.vscode/...`, etc., which captures system/Homebrew inventory
but misses per-user developer tools. Passing `--all-users` expands the
per-user default roots across every real `/Users/<name>/` home:

```sh
sudo bumblebee scan \
  --profile baseline \
  --all-users \
  --max-duration 5m \
  --output http \
  --http-url https://inventory.example.com/v1/ingest \
  --http-auth bearer \
  --http-token-env BUMBLEBEE_TOKEN \
  --device-id-env BUMBLEBEE_DEVICE_ID
```

What `--all-users` does (and does not) do:

- Adds the **same known subdirectories** under each `/Users/<name>/` that
  it would add under the current `$HOME` (toolchains, editor extensions,
  MCP config dirs, browser-extension profile dirs). It does **not** add
  `/Users/<name>/` itself as a recursive root — bare-home crawling is
  still only available via `--profile deep`.
- Includes system/Homebrew roots (`/opt/homebrew/lib`, `/usr/local/lib`,
  `/Library/Python`) exactly once, just like the single-user run.
- Skips well-known service entries (`Shared`, `Guest`, `root`, `Deleted
  Users`) and any hidden entry under `/Users` (`.localized`, `.DS_Store`).
- Cannot be combined with `--root` (explicit roots disable the
  expansion) or `--profile=deep`. `baseline` and `project` have a
  bounded set of known per-user subdirectories to fan out across
  (toolchains, editor extensions, MCP config dirs, browser profiles);
  `deep` walks operator-supplied roots and has no such known set, so
  fanning out across users on `deep` means passing `--root /Users/<name>`
  explicitly per user.
- Works on macOS and Windows. On Windows the parent is
  `%SystemDrive%\Users`, and the Windows template/service profiles
  (`Public`, `Default`, `Default User`, `All Users`, the `*ServiceProfile`
  entries) are filtered out the same way the macOS ones are. This matters
  most for agent-run scans: an EDR or Velociraptor client runs as SYSTEM,
  whose profile is `C:\Windows\system32\config\systemprofile` and holds
  no developer trees, so without `--all-users` a baseline or project scan
  exits with "found no default roots on this host".
- On Linux, `--all-users` is accepted but
  resolves to the current user's home only — multi-user fanout under a
  single root-owned scan is currently a macOS-only convenience.

`endpoint.username` and `endpoint.uid` reflect the scanner process
identity — `root` / `0` for a LaunchDaemon. This is correct: the
endpoint identity is "who ran the scan," not "whose home this record
came from." For attribution, downstream consumers should key on
`project_path` and `source_file`, both of which carry the
`/Users/<name>/...` prefix that identifies the user. The trailing
`scan_summary.roots` list also enumerates every expanded path.

## Cadence by profile

| Profile     | Typical interval                                                  | launchd shape                              |
|-------------|-------------------------------------------------------------------|--------------------------------------------|
| `baseline` | `StartInterval 21600` (every 6 h) plus `RunAtLoad` for a login run | one LaunchAgent / LaunchDaemon per host    |
| `project`   | `StartInterval 86400` (daily) or `43200` (12 h)                    | one LaunchAgent / LaunchDaemon per host    |
| `deep`      | Usually on demand; recurring works with `--findings-only`          | run from your remote-execution tool on demand, or via launchd |

Set `--max-duration` comfortably above each baseline job's observed P99.
`--concurrency 4` (default) is right for most laptops.

`deep` walks operator-supplied roots — typically a developer's home
during a campaign — and pairs naturally with `--exposure-catalog` to
emit findings. Most deployments invoke it on demand, but recurring
runs work too; `--findings-only` keeps the per-run output small.

## Output choice

- **You already run a log shipper** (Vector, Fluent Bit, Filebeat, etc.):
  use `--output file --output-file /var/log/bumblebee/inventory.ndjson`
  with `--append` and let the shipper own forwarding, batching, and
  retry. Most resilient on flaky networks.
- **No log shipper**: use `--output http --http-url https://...`. The
  HTTPS sink reads bearer or HMAC-SHA256 secrets from environment
  variables; provision them via the launchd plist's `EnvironmentVariables`
  block or via the MDM profile. HTTPS is required for non-loopback hosts.

There is no built-in S3/GCS uploader. See [transport.md](transport.md).

## Example LaunchAgent plist — baseline profile

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
 "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.example.bumblebee.baseline</string>

  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/bumblebee</string>
    <string>scan</string>
    <string>--profile</string>
    <string>baseline</string>
    <string>--max-duration</string>
    <string>5m</string>
    <string>--output</string>
    <string>http</string>
    <string>--http-url</string>
    <string>https://inventory.example.com/v1/ingest</string>
    <string>--http-auth</string>
    <string>bearer</string>
    <string>--http-token-env</string>
    <string>BUMBLEBEE_TOKEN</string>
    <string>--http-gzip</string>
    <string>--device-id-env</string>
    <string>BUMBLEBEE_DEVICE_ID</string>
  </array>

  <key>EnvironmentVariables</key>
  <dict>
    <key>BUMBLEBEE_TOKEN</key>
    <string>__TOKEN__</string>
    <key>BUMBLEBEE_DEVICE_ID</key>
    <string>__DEVICE_ID__</string>
  </dict>

  <key>StartInterval</key>
  <integer>21600</integer>
  <key>RunAtLoad</key>
  <true/>

  <key>StandardOutPath</key>
  <string>/tmp/bumblebee.baseline.out</string>
  <key>StandardErrorPath</key>
  <string>/var/log/bumblebee/bumblebee.baseline.err</string>
</dict>
</plist>
```

## Example LaunchAgent plist — project profile

Same shape, plus `--root` per project tree and a daily interval:

```xml
<key>Label</key>
<string>com.example.bumblebee.project</string>
...
<key>ProgramArguments</key>
<array>
  <string>/usr/local/bin/bumblebee</string>
  <string>scan</string>
  <string>--profile</string><string>project</string>
  <string>--root</string><string>/Users/__USERNAME__/code</string>
  <string>--root</string><string>/Users/__USERNAME__/Developer</string>
  <string>--max-duration</string><string>10m</string>
  <string>--output</string><string>http</string>
  <string>--http-url</string><string>https://inventory.example.com/v1/ingest</string>
  <string>--http-auth</string><string>bearer</string>
  <string>--http-token-env</string><string>BUMBLEBEE_TOKEN</string>
  <string>--http-gzip</string>
  <string>--device-id-env</string><string>BUMBLEBEE_DEVICE_ID</string>
</array>
...
<key>StartInterval</key><integer>86400</integer>
```

## Triggering the deep profile on demand

`deep` is not in a plist. Operators invoke it as a one-off, typically
via the remote-execution path the fleet already uses:

```sh
bumblebee scan \
  --profile deep \
  --root "$HOME" \
  --exposure-catalog /path/to/campaign-catalog.json \
  --max-duration 10m \
  --output http \
  --http-url https://inventory.example.com/v1/ingest \
  --http-auth bearer \
  --http-token-env BUMBLEBEE_TOKEN \
  --device-id-env BUMBLEBEE_DEVICE_ID
```

Findings (`record_type=finding`) land in the same NDJSON stream as the
package records and the trailing `scan_summary`.

### One-off deep run from a root-context script

If the runner executes as root, `$HOME` usually points at `/var/root`,
not the developer's home. `deep` needs at least one explicit `--root`,
so the script has to pick one deliberately. Two patterns:

**1. Target the logged-in console user.** Derive the username (and
home directory) from `/dev/console` ownership rather than trusting any
tool-supplied variable. This works on every macOS release and does not
assume the runner injects a `$USER`-equivalent:

```sh
#!/bin/sh
set -eu

CONSOLE_USER=$(stat -f '%Su' /dev/console)
if [ -z "$CONSOLE_USER" ] || [ "$CONSOLE_USER" = "root" ] || [ "$CONSOLE_USER" = "loginwindow" ]; then
  echo "no console user; skipping" >&2
  exit 0
fi
CONSOLE_HOME=$(dscl . -read "/Users/$CONSOLE_USER" NFSHomeDirectory | awk '{print $2}')

/usr/local/bin/bumblebee scan \
  --profile deep \
  --root "$CONSOLE_HOME" \
  --exposure-catalog /var/db/bumblebee/campaign-catalog.json \
  --max-duration 10m \
  --output http \
  --http-url https://inventory.example.com/v1/ingest \
  --http-auth bearer \
  --http-token-env BUMBLEBEE_TOKEN \
  --device-id-env BUMBLEBEE_DEVICE_ID
```

**2. Sweep every local user home.** When a campaign needs coverage
across all developers on a multi-user box, loop over `/Users` and
invoke `deep` once per real home. There is no `--all-users` for `deep`
(see [LaunchDaemon vs LaunchAgent](#launchdaemon-vs-launchagent)); the
loop is explicit on purpose:

```sh
#!/bin/sh
set -eu
for u in /Users/*; do
  name=$(basename "$u")
  case "$name" in
    Shared|Guest|Deleted\ Users|.localized|.*) continue ;;
  esac
  [ -d "$u" ] || continue
  /usr/local/bin/bumblebee scan \
    --profile deep \
    --root "$u" \
    --exposure-catalog /var/db/bumblebee/campaign-catalog.json \
    --max-duration 10m \
    --output http \
    --http-url https://inventory.example.com/v1/ingest \
    --http-auth bearer \
    --http-token-env BUMBLEBEE_TOKEN \
    --device-id-env BUMBLEBEE_DEVICE_ID
done
```

Each invocation is its own `run_id`; the receiver dedupes per
`(endpoint, ecosystem, normalized_name, version, source_file)`.

Management tools differ in how they expose the logged-in username to a
script. Treat those variables as advisory and prefer `/dev/console` or
an explicit `/Users` loop.

## Default roots per profile

`bumblebee roots --profile <p>` previews the resolved roots on the
current host (one `<root_kind>\t<path>` line per root). The defaults are:

- `baseline`: language toolchains and version managers (`~/.cargo`,
  `~/go`, `~/.pyenv/versions`, `~/.nvm/versions`, `~/.rbenv`,
  `~/.asdf/installs`), editor-extension trees (`~/.vscode/extensions`,
  `~/.cursor/extensions`, `~/.windsurf/extensions`, server variants,
  VSCodium), MCP config locations (`~/.cursor`, `~/.codeium/windsurf`,
  `~/.claude`, `~/.codex`, `~/.gemini`,
  `~/Library/Application Support/Claude`), plus Homebrew lib prefixes
  (`/opt/homebrew/lib`, `/usr/local/lib`) and `/Library/Python`.
  Under `~/.gemini/`, `settings.json` is parsed path-aware (Gemini CLI /
  Gemini Code Assist); generic `settings.json` elsewhere is not parsed,
  and non-JSON MCP host configs (e.g. Codex `config.toml`, Continue YAML)
  are not parsed in v0.1.
- `project`: `~/code`, `~/src`, `~/Developer`, `~/Projects`, `~/workspace`.
  Override with `--root` if your trees live elsewhere.
- `deep`: no defaults. Requires at least one explicit `--root`.

If a profile's defaults pick up nothing on this host the scan exits with
a helpful error rather than silently walking the whole home directory.

Pass `--all-users` to expand the baseline or project per-user candidate
set across every real `/Users/<name>/` home. `bumblebee roots --profile
baseline --all-users` previews exactly what a root-owned scan
would walk.

## Stable endpoint identity (`--device-id-env`)

Hostnames change. Usernames change. UIDs are stable on a given install
but reset on reinstall. For receiver-side current-state keying, a
stable externally-supplied identifier is preferable — see
[state-model.md](state-model.md).

`bumblebee` reads the device id from an environment variable rather
than a CLI argument so it does not appear in `ps`. Configure the
launchd plist's `EnvironmentVariables` block (or whichever delivery
mechanism is in use) to populate the env var from whatever attribute
is authoritative in your environment (hardware serial, asset tag, MDM
device UUID, etc.).

If the env var is missing or empty at scan time the scan still runs;
records simply omit `endpoint.device_id` and a `warn` diagnostic is
written to stderr.

## TCC / Full Disk Access

The walker is read-only and skips credential directories by default
(`.ssh`, `.aws`, `.azure`, `.config/gcloud`, `.kube`, `.docker`, `.gnupg`)
and `.env` / `.envrc` files. Some locations under `~/Library/`,
`~/Documents/`, `~/Desktop/`, and `~/Downloads/` are gated by TCC on
recent macOS releases. If your inventory must reach those (typically
only relevant for `deep`):

- Grant the `bumblebee` binary Full Disk Access via MDM (Privacy
  Preferences Policy Control payload). A LaunchDaemon running as root
  still needs FDA for TCC-protected paths.
- Or restrict `--root` to development trees only and accept that
  TCC-protected paths are out of scope.

The walker emits a `debug`-level diagnostic for unreadable paths; it does
not abort the scan.

## Verifying a deployment

1. Load the plist: `launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.example.bumblebee.baseline.plist`
   (LaunchAgent) or `sudo launchctl bootstrap system /Library/LaunchDaemons/...plist`.
2. Trigger one run: `launchctl kickstart -k gui/$(id -u)/com.example.bumblebee.baseline`.
3. Check the stderr log for the final `scan complete:` info diagnostic.
4. Confirm the receiver saw a `record_type=scan_summary` line with
   `status=complete` for the new `run_id`. That marker is what your
   pipeline should key on to promote the run to current state — see
   [state-model.md](state-model.md).
