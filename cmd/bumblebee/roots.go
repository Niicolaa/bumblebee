// Profile-aware scan root resolution.
//
// Each profile selects a different population of roots:
//
//   - baseline  — bounded known package/tool roots only. Global/user
//     package-manager install locations, Homebrew lib prefixes, language
//     toolchains, editor-extension trees, MCP config directories.
//     No project-tree crawling. Suitable for frequent (6h / login)
//     fleet inventory.
//   - project   — configured developer/project roots. ~/code, ~/src,
//     ~/Developer, ~/Projects, ~/workspace, plus any explicit --root
//     entries. Daily or twice-daily cadence is typical.
//   - deep      — incident-response exposure scan. The only profile that
//     accepts a user-home or filesystem root. Pair with
//     --exposure-catalog to emit findings. Run on demand via MDM or
//     remote execution during a campaign; not for baseline use.
//
// baseline and project refuse bare-home roots (`$HOME`, `/Users/<name>`,
// `/home/<name>`, `/`) outright. deep accepts them.
//
// --all-users expansion (baseline, project) lets an agent-owned run
// enumerate per-user known subdirectories under every real user home
// (macOS /Users/<name>, Windows <drive>:\Users\<name>) without ever
// passing a bare home root. The set of per-user subdirectories expanded
// is the same one a logged-in user would resolve; only the home prefix
// is varied. System/Homebrew roots are still included.
//
// This is what makes an agent-run scan useful at all: a fleet agent runs
// as root or SYSTEM, and SYSTEM's profile
// (C:\Windows\system32\config\systemprofile) contains no developer
// trees, so without expansion baseline and project resolve to nothing
// and the run exits with "found no default roots on this host".
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/perplexityai/bumblebee/internal/model"
	"github.com/perplexityai/bumblebee/internal/scanner"
)

// rootsOpts groups the scoping inputs to resolveRoots. Adding a new
// option here is preferred over growing resolveRoots' positional
// arguments.
type rootsOpts struct {
	// AllUsers, when true on macOS or Windows, expands the
	// baseline/project profile defaults across every real user home under
	// the platform's users directory instead of only the current process
	// owner's home. System/Homebrew roots are still included exactly
	// once. Has no effect on Linux, which has no single canonical home
	// parent to enumerate.
	AllUsers bool
}

// resolveRoots picks the scan roots for the given profile. When the caller
// supplied explicit --root entries, those are honored (and tagged with a
// best-guess kind for the profile); otherwise the profile's curated
// defaults are returned.
//
// notes is human-readable status worth surfacing as diagnostic info (e.g.
// "default roots: 4 present, 11 candidate paths absent"). err is non-nil
// only on a configuration failure the operator must address before the
// scan can run.
func resolveRoots(profile string, explicit []string, opts rootsOpts) (roots []scanner.Root, notes []string, err error) {
	switch profile {
	case model.ProfileBaseline, model.ProfileProject, model.ProfileDeep:
	case "":
		return nil, nil, fmt.Errorf("--profile is required (one of: baseline, project, deep)")
	default:
		return nil, nil, fmt.Errorf("unknown --profile %q (want: baseline, project, deep)", profile)
	}

	if opts.AllUsers && profile == model.ProfileDeep {
		return nil, nil, fmt.Errorf(
			"--all-users is not valid with --profile deep.\n" +
				"deep is the incident-response profile and intentionally requires explicit --root paths.\n" +
				"To fan out a deep sweep across users, pass --root /Users/<name> per user.")
	}

	if len(explicit) > 0 {
		if opts.AllUsers {
			return nil, nil, fmt.Errorf(
				"--all-users cannot be combined with explicit --root entries.\n" +
					"--all-users expands the profile's curated defaults across every user home.\n" +
					"Either drop --all-users and enumerate roots manually, or drop --root and let --all-users expand the defaults.")
		}
		roots = make([]scanner.Root, 0, len(explicit))
		for _, p := range explicit {
			kind := classifyRoot(p, profile)
			if isBroadHomeRoot(p) && profile != model.ProfileDeep {
				return nil, nil, fmt.Errorf(
					"profile=%s refuses broad home/filesystem root %q.\n"+
						"baseline and project profiles are source/root-allowlist inventories — they do not walk bare home directories.\n"+
						"For an incident-response exposure scan that does walk home roots, re-run with --profile deep.",
					profile, p)
			}
			roots = append(roots, scanner.Root{Path: p, Kind: kind})
		}
		return roots, notes, nil
	}

	switch profile {
	case model.ProfileBaseline:
		roots, notes = baselineDefaultRoots(opts)
	case model.ProfileProject:
		roots, notes = projectDefaultRoots(opts)
	case model.ProfileDeep:
		return nil, nil, fmt.Errorf(
			"profile=deep requires at least one explicit --root.\n" +
				"deep is the incident-response profile and is intentionally not auto-configured.\n" +
				"Pass the home root(s) you want to scan, e.g. --root \"$HOME\" or --root /Users/<name>.")
	}

	if len(roots) == 0 {
		return nil, nil, fmt.Errorf(
			"profile=%s found no default roots on this host. Pass --root explicitly.", profile)
	}
	return roots, notes, nil
}

// classifyRoot infers a RootKind for an operator-supplied --root path.
// The classifier is heuristic: it looks at trailing path segments only,
// which is enough to tag the common cases (Homebrew lib prefixes, editor
// extensions, MCP config trees, etc.). Unknown paths default to a
// profile-appropriate kind so the receiver can still split inventory by
// scan profile even when the path shape is unfamiliar.
func classifyRoot(path, profile string) string {
	p := filepath.ToSlash(filepath.Clean(path))
	switch {
	case strings.HasSuffix(p, "/extensions") && containsAny(p, ".vscode", ".cursor", ".windsurf", ".vscodium"):
		return model.RootKindEditorExtension
	case (strings.HasSuffix(p, "/Extensions") || strings.HasSuffix(p, "/extensions")) &&
		containsAny(p, "Chrome", "Chromium", "Firefox", "BraveSoftware", "Microsoft Edge", "Vivaldi", "Arc", "Comet", "LibreWolf", "Waterfox", ".mozilla"):
		return model.RootKindBrowserExtension
	case strings.HasSuffix(p, "/Profiles") && containsAny(p, "Firefox", "LibreWolf", "Waterfox"):
		return model.RootKindBrowserExtension
	case strings.Contains(p, "Library/Application Support/Claude") ||
		strings.Contains(p, "AppData/Roaming/Claude") ||
		strings.HasSuffix(p, "/.cursor") ||
		strings.HasSuffix(p, "/.codeium/windsurf") ||
		strings.HasSuffix(p, "/.claude") ||
		strings.HasSuffix(p, "/.codex") ||
		strings.HasSuffix(p, "/.gemini") ||
		strings.HasSuffix(p, "/.config/Claude") ||
		strings.HasSuffix(p, "/.config/Claude Code") ||
		strings.HasSuffix(p, "/.continue"):
		return model.RootKindMCPConfig
	case strings.HasSuffix(p, "/.agents") || strings.HasSuffix(p, "/.local/state/skills"):
		return model.RootKindAgentSkill
	case p == "/opt/homebrew/lib" ||
		p == "/usr/local/lib" ||
		strings.HasSuffix(p, "/Cellar") ||
		strings.HasSuffix(p, "/Caskroom") ||
		strings.HasSuffix(p, "/Library/Python"):
		return model.RootKindHomebrew
	case isBroadHomeRoot(path):
		return model.RootKindDeepHome
	}
	if profile == model.ProfileBaseline {
		return model.RootKindUserPackage
	}
	if profile == model.ProfileProject {
		return model.RootKindProject
	}
	return model.RootKindUnknown
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// isBroadHomeRoot reports whether path resolves to a bare user home or
// filesystem root (e.g. $HOME, /Users/<name>, /home/<name>, /, or the
// shared /Users or /home parents). baseline and project refuse such
// roots; deep accepts them.
func isBroadHomeRoot(path string) bool {
	if path == "" {
		return false
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	abs = filepath.Clean(abs)
	if abs == "/" {
		return true
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		if abs == filepath.Clean(home) {
			return true
		}
	}
	switch abs {
	case "/Users", "/home", "/root":
		return true
	}
	if dir, _ := filepath.Split(abs); dir == "/Users/" || dir == "/home/" {
		return true
	}
	if runtime.GOOS == "windows" && isWindowsBroadHome(abs) {
		return true
	}
	return false
}

// isWindowsBroadHome recognises Windows bare-home and drive-root paths:
// `<drive>:\`, `<drive>:\Users`, and `<drive>:\Users\<single-name>`.
// The drive letter is arbitrary; comparisons are case-insensitive
// because Windows filesystems are.
func isWindowsBroadHome(abs string) bool {
	vol := filepath.VolumeName(abs)
	if vol == "" {
		return false
	}
	if abs == vol || abs == vol+`\` {
		return true
	}
	rel := strings.Trim(filepath.ToSlash(strings.TrimPrefix(abs, vol)), "/")
	if rel == "" {
		return true
	}
	parts := strings.Split(rel, "/")
	if len(parts) <= 2 && strings.EqualFold(parts[0], "Users") {
		return true
	}
	return false
}

// baselineHomeCandidates returns the per-home set of curated baseline
// root candidates for one home directory (toolchains, editor extension
// trees, MCP config locations, browser extension per-profile dirs).
// It is the same set baselineDefaultRoots used to inline for the
// current user; factoring it out lets --all-users expand it across
// /Users/*.
func baselineHomeCandidates(home string) []scanner.Root {
	if home == "" {
		return nil
	}
	var out []scanner.Root
	add := func(p, kind string) { out = append(out, scanner.Root{Path: p, Kind: kind}) }

	// Language toolchain / version manager install roots — installed
	// packages live under these, but a developer's source tree does not.
	add(filepath.Join(home, "go"), model.RootKindUserPackage)
	add(filepath.Join(home, ".cargo"), model.RootKindUserPackage)
	// The NuGet global package cache is the .NET analogue of
	// node_modules or site-packages: every restored package is extracted
	// under <id>/<version>/. On Windows endpoints this is usually the
	// largest real inventory on the machine.
	add(filepath.Join(home, ".nuget", "packages"), model.RootKindUserPackage)
	// Maven's local repository, laid out as <group>/<artifact>/<version>/.
	add(filepath.Join(home, ".m2", "repository"), model.RootKindUserPackage)
	add(filepath.Join(home, ".rbenv"), model.RootKindUserPackage)
	add(filepath.Join(home, ".rvm"), model.RootKindUserPackage)
	add(filepath.Join(home, ".pyenv", "versions"), model.RootKindUserPackage)
	add(filepath.Join(home, ".asdf", "installs"), model.RootKindUserPackage)
	add(filepath.Join(home, ".nvm", "versions"), model.RootKindUserPackage)
	for _, p := range globExisting(filepath.Join(home, ".local", "lib", "python*")) {
		add(p, model.RootKindUserPackage)
	}
	add(filepath.Join(home, ".local", "share", "pipx", "venvs"), model.RootKindUserPackage)
	// uv's tool installs (`uv tool install ruff`) — the uv analogue of
	// pipx, and increasingly the default way Python CLIs land on a
	// developer machine.
	add(filepath.Join(home, ".local", "share", "uv", "tools"), model.RootKindUserPackage)

	// Global npm-family package prefixes. These are the "npm install -g"
	// targets, which is exactly the shape a compromised CLI package
	// takes — and none of them lives under a toolchain root above.
	//
	// ~/.npm-global is the prefix the standard "don't sudo npm" advice
	// tells people to configure, so it is common on exactly the machines
	// whose owners are security-conscious enough to have followed it.
	for _, seg := range [][]string{
		{".npm-global", "lib", "node_modules"},
		{".npm-packages", "lib", "node_modules"},
		{".node_modules", "lib", "node_modules"},
		{".config", "yarn", "global", "node_modules"},
		{".yarn", "global", "node_modules"},
		{".bun", "install", "global", "node_modules"},
		{".deno"},
	} {
		add(filepath.Join(append([]string{home}, seg...)...), model.RootKindUserPackage)
	}
	// pnpm's global store/tool dir moves per platform and per install
	// method, so all the documented locations are listed; absent ones
	// are dropped by filterExistingRoots.
	for _, p := range []string{
		filepath.Join(home, ".local", "share", "pnpm"),
		filepath.Join(home, "Library", "pnpm"),
		filepath.Join(home, ".pnpm-global"),
	} {
		add(p, model.RootKindUserPackage)
	}
	// Volta and fnm keep their own package images outside the toolchain
	// roots above.
	add(filepath.Join(home, ".volta", "tools", "image", "packages"), model.RootKindUserPackage)

	// Per-user conda environments. site-packages under each env holds
	// dist-info the PyPI scanner reads.
	for _, seg := range []string{"miniconda3", "anaconda3", "miniforge3", ".conda"} {
		add(filepath.Join(home, seg, "envs"), model.RootKindUserPackage)
		add(filepath.Join(home, seg, "lib"), model.RootKindUserPackage)
	}

	// Per-user RubyGems installs (`gem install --user-install`).
	add(filepath.Join(home, ".gem"), model.RootKindUserPackage)
	// macOS ships its own Ruby, whose --user-install lands here.
	add(filepath.Join(home, ".local", "share", "gem"), model.RootKindUserPackage)

	// Composer's global package tree (`composer global require`). The
	// location moved from ~/.composer to XDG, so both are listed.
	add(filepath.Join(home, ".composer", "vendor"), model.RootKindUserPackage)
	add(filepath.Join(home, ".config", "composer", "vendor"), model.RootKindUserPackage)

	// Dart/Flutter's global package cache (`dart pub global activate`).
	add(filepath.Join(home, ".pub-cache"), model.RootKindUserPackage)

	// Elixir's Hex cache and Mix archives.
	add(filepath.Join(home, ".hex", "packages"), model.RootKindUserPackage)
	add(filepath.Join(home, ".mix", "archives"), model.RootKindUserPackage)

	// Gradle's module cache. The wrapper/daemon state around it is
	// excluded by the walker (.gradle is in DefaultExcludes), so the
	// cache is named explicitly rather than by adding all of ~/.gradle.
	add(filepath.Join(home, ".gradle", "caches", "modules-2", "files-2.1"), model.RootKindUserPackage)

	// Editor extension trees. Each editor has a local tree and a
	// remote/SSH counterpart installed by its server build; a remote
	// install is just as much an installed extension as a local one.
	// VS Code Insiders has shipped its server dir under both spellings
	// depending on version, so both are listed — a home that has
	// neither simply contributes no root.
	for _, seg := range []string{
		".vscode/extensions",
		".vscode-insiders/extensions",
		".vscode-server/extensions",
		".vscode-server-insiders/extensions",
		".vscode-insiders-server/extensions",
		".cursor/extensions",
		".cursor-server/extensions",
		".windsurf/extensions",
		".windsurf-server/extensions",
		".vscodium/extensions",
		".vscodium-server/extensions",
	} {
		add(filepath.Join(home, filepath.FromSlash(seg)), model.RootKindEditorExtension)
	}

	// MCP config locations. The cross-platform dotfile homes
	// (`~/.claude`, `~/.codex`, `~/.gemini`) cover Claude Code, Codex,
	// and Gemini CLI / Gemini Code Assist hosts that write MCP configs
	// into a user-home dotfile rather than an OS-conventional
	// application-support directory; on hosts where those dirs are
	// absent filterExistingRoots drops them.
	add(filepath.Join(home, ".cursor"), model.RootKindMCPConfig)
	add(filepath.Join(home, ".codeium", "windsurf"), model.RootKindMCPConfig)
	add(filepath.Join(home, ".claude"), model.RootKindMCPConfig)
	// Claude Code stores user-scope MCP servers (top-level `mcpServers`)
	// and local-scope ones (`projects.<dir>.mcpServers`) in this single
	// file, which sits beside the `.claude` dir rather than inside it.
	add(filepath.Join(home, ".claude.json"), model.RootKindMCPConfig)
	add(filepath.Join(home, ".codex"), model.RootKindMCPConfig)
	add(filepath.Join(home, ".gemini"), model.RootKindMCPConfig)
	switch runtime.GOOS {
	case "darwin":
		add(filepath.Join(home, "Library", "Application Support", "Claude"), model.RootKindMCPConfig)
		// Per-user Python from the python.org installer and from
		// `pip install --user`. Layout is
		// ~/Library/Python/<ver>/lib/python/site-packages. This is the
		// per-user twin of the machine-wide /Library/Python already in
		// systemRoots, and on a Mac where pip is used without a venv it
		// is where most PyPI metadata actually lives.
		for _, p := range globExisting(filepath.Join(home, "Library", "Python", "*", "lib", "python", "site-packages")) {
			add(p, model.RootKindUserPackage)
		}
	case "linux":
		add(filepath.Join(home, ".config", "Claude"), model.RootKindMCPConfig)
		add(filepath.Join(home, ".config", "Claude Code"), model.RootKindMCPConfig)
		add(filepath.Join(home, ".continue"), model.RootKindMCPConfig)
	case "windows":
		// Claude Desktop's claude_desktop_config.json lives under
		// %APPDATA%\Claude (Roaming). Other Windows MCP hosts (Cursor,
		// Windsurf, VS Code) already land via the cross-platform
		// ~/.cursor, ~/.codeium/windsurf, and editor-extension dotfile
		// roots added above.
		appdata := windowsRoamingAppData(home)
		add(filepath.Join(appdata, "Claude"), model.RootKindMCPConfig)
		add(filepath.Join(appdata, "Continue"), model.RootKindMCPConfig)
		// Per-user Python. The python.org installer's default (non
		// all-users) mode installs here, so this is where dist-info
		// metadata lives on most Windows developer machines.
		for _, p := range globExisting(filepath.Join(windowsLocalAppData(home), "Programs", "Python", "Python*", "Lib", "site-packages")) {
			add(p, model.RootKindUserPackage)
		}
		// `npm install -g` on Windows writes to %APPDATA%\npm\node_modules
		// rather than any of the Unix prefixes above. Windows has almost
		// no machine-wide package roots, so missing this left global npm
		// installs — the classic compromised-CLI shape — invisible on
		// every Windows endpoint.
		add(filepath.Join(appdata, "npm", "node_modules"), model.RootKindUserPackage)
		local := windowsLocalAppData(home)
		// pnpm, Yarn Berry, and Volta per-user homes.
		add(filepath.Join(local, "pnpm", "global"), model.RootKindUserPackage)
		add(filepath.Join(local, "Yarn", "Data", "global", "node_modules"), model.RootKindUserPackage)
		add(filepath.Join(local, "Volta", "tools", "image", "packages"), model.RootKindUserPackage)
		// Scoop and per-user Chocolatey: user-writable app managers that
		// are a common way software lands on a locked-down Windows box.
		add(filepath.Join(home, "scoop", "apps"), model.RootKindUserPackage)
		// Per-user conda.
		for _, seg := range []string{"miniconda3", "anaconda3", "miniforge3"} {
			add(filepath.Join(home, seg, "envs"), model.RootKindUserPackage)
			add(filepath.Join(home, seg, "Lib", "site-packages"), model.RootKindUserPackage)
		}
	}

	// Agent-skill lock locations. ~/.agents holds the global
	// `.skill-lock.json` written by the skills.sh CLI; $XDG_STATE_HOME
	// overrides that to <state>/skills/.skill-lock.json when set.
	// Absent locations are dropped by filterExistingRoots.
	add(filepath.Join(home, ".agents"), model.RootKindAgentSkill)
	if xdg := os.Getenv("XDG_STATE_HOME"); xdg != "" {
		add(filepath.Join(xdg, "skills"), model.RootKindAgentSkill)
	}

	// Browser extension trees. We point directly at the per-profile
	// Extensions/ directories so the default home-tree excludes (which
	// keep us out of Chromium/Firefox app trees for privacy reasons)
	// do not block enumeration of installed extensions. Only profile
	// dirs that exist on this host pass filterExistingRoots.
	for _, r := range browserExtensionCandidateRoots(home) {
		add(r, model.RootKindBrowserExtension)
	}
	return out
}

// projectHomeCandidates returns the per-home set of curated project
// root candidates for one home directory.
func projectHomeCandidates(home string) []scanner.Root {
	if home == "" {
		return nil
	}
	var out []scanner.Root
	for _, sub := range []string{"code", "src", "Developer", "Projects", "workspace"} {
		out = append(out, scanner.Root{
			Path: filepath.Join(home, sub),
			Kind: model.RootKindProject,
		})
	}
	return out
}

// systemRoots returns the OS-specific system/Homebrew install prefixes
// included in the baseline profile. They are independent of the home
// directory and are emitted once per scan even under --all-users.
func systemRoots() []scanner.Root {
	switch runtime.GOOS {
	case "darwin":
		roots := []scanner.Root{
			{Path: "/opt/homebrew/Cellar", Kind: model.RootKindHomebrew},
			{Path: "/opt/homebrew/Caskroom", Kind: model.RootKindHomebrew},
			{Path: "/opt/homebrew/lib", Kind: model.RootKindHomebrew},
			{Path: "/usr/local/Cellar", Kind: model.RootKindHomebrew},
			{Path: "/usr/local/Caskroom", Kind: model.RootKindHomebrew},
			{Path: "/usr/local/lib", Kind: model.RootKindHomebrew},
			{Path: "/Library/Python", Kind: model.RootKindHomebrew},
		}
		return roots
	case "linux":
		roots := []scanner.Root{
			{Path: "/usr/local/lib", Kind: model.RootKindGlobalPackage},
			{Path: "/home/linuxbrew/.linuxbrew/Cellar", Kind: model.RootKindHomebrew},
			{Path: "/home/linuxbrew/.linuxbrew/Caskroom", Kind: model.RootKindHomebrew},
			// Machine-wide conda and Node prefixes. /usr/local/lib above
			// already covers /usr/local/lib/node_modules, but a distro
			// nodejs package and an /opt conda install land elsewhere.
			{Path: "/opt/conda", Kind: model.RootKindGlobalPackage},
			{Path: "/usr/lib/node_modules", Kind: model.RootKindGlobalPackage},
			{Path: "/usr/share/gems", Kind: model.RootKindGlobalPackage},
		}
		for _, pattern := range []string{"/usr/lib/python*", "/usr/lib64/python*"} {
			for _, p := range globExisting(pattern) {
				roots = append(roots, scanner.Root{Path: p, Kind: model.RootKindGlobalPackage})
			}
		}
		return roots
	case "windows":
		// Windows has no Homebrew/usr-lib analog, and per-user roots are
		// added by baselineHomeCandidates. What does belong here is the
		// machine-wide Python install: the python.org installer's
		// all-users mode writes to %ProgramFiles%\PythonNN, whose
		// Lib\site-packages holds dist-info metadata the PyPI scanner
		// reads.
		var roots []scanner.Root
		for _, base := range []string{os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)")} {
			if strings.TrimSpace(base) == "" {
				continue
			}
			for _, p := range globExisting(filepath.Join(base, "Python*", "Lib", "site-packages")) {
				roots = append(roots, scanner.Root{Path: p, Kind: model.RootKindGlobalPackage})
			}
			// Node installed machine-wide puts global npm packages here.
			roots = append(roots, scanner.Root{
				Path: filepath.Join(base, "nodejs", "node_modules"),
				Kind: model.RootKindGlobalPackage,
			})
		}
		// Chocolatey's default machine-wide install root, and the
		// machine-wide conda prefixes. These are user-writable in many
		// default deployments, which is what makes them worth walking.
		if pd := strings.TrimSpace(os.Getenv("ProgramData")); pd != "" {
			roots = append(roots,
				scanner.Root{Path: filepath.Join(pd, "chocolatey", "lib"), Kind: model.RootKindGlobalPackage},
				scanner.Root{Path: filepath.Join(pd, "miniconda3"), Kind: model.RootKindGlobalPackage},
				scanner.Root{Path: filepath.Join(pd, "anaconda3"), Kind: model.RootKindGlobalPackage},
			)
		}
		return roots
	}
	return nil
}

// windowsRoamingAppData returns the absolute path to %APPDATA% (the
// per-user Roaming AppData directory). It prefers the env var so a
// machine-configured non-default location is honoured, and falls back
// to `<home>\AppData\Roaming` which matches the default Windows layout.
// Callers should only invoke this on Windows.
func windowsRoamingAppData(home string) string {
	if v := strings.TrimSpace(os.Getenv("APPDATA")); v != "" {
		return v
	}
	return filepath.Join(home, "AppData", "Roaming")
}

// windowsLocalAppData returns the absolute path to %LOCALAPPDATA% (the
// per-user Local AppData directory). Browser extension trees live here
// on Windows. Callers should only invoke this on Windows.
func windowsLocalAppData(home string) string {
	if v := strings.TrimSpace(os.Getenv("LOCALAPPDATA")); v != "" {
		return v
	}
	return filepath.Join(home, "AppData", "Local")
}

func globExisting(pattern string) []string {
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil
	}
	var out []string
	for _, p := range matches {
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			out = append(out, p)
		}
	}
	return out
}

// envOverrideRoots returns package roots relocated by environment
// variable. Every other root here is derived from a home directory, so a
// developer who moved their toolchain (GOPATH on a second disk,
// CARGO_HOME on a faster volume, a corporate NPM_CONFIG_PREFIX) would
// otherwise be scanned as if the packages did not exist — a clean result
// that means nothing.
//
// These are read from the scanning process's environment, which is the
// right source for a user-context run and the wrong one for an agent
// running as root or SYSTEM: a service account does not inherit the
// user's shell profile. They are therefore additive to the home-derived
// roots, never a replacement, and absent variables cost nothing.
func envOverrideRoots() []scanner.Root {
	var out []scanner.Root
	// GOMODCACHE and GOPATH/pkg/mod are the same directory on a default
	// setup, and several other pairs can collide once a variable is set
	// to a path the home-derived roots already cover. Dedupe here rather
	// than leaving duplicate roots for the walker to visit twice.
	seen := map[string]bool{}
	add := func(v string, parts ...string) {
		base := strings.TrimSpace(os.Getenv(v))
		if base == "" {
			return
		}
		p := filepath.Clean(filepath.Join(append([]string{base}, parts...)...))
		if seen[p] {
			return
		}
		seen[p] = true
		out = append(out, scanner.Root{Path: p, Kind: model.RootKindUserPackage})
	}
	add("GOMODCACHE")
	add("GOPATH", "pkg", "mod")
	add("CARGO_HOME", "registry")
	add("NPM_CONFIG_PREFIX", "lib", "node_modules")
	add("PNPM_HOME")
	add("GEM_HOME")
	add("COMPOSER_HOME", "vendor")
	add("PUB_CACHE")
	add("MAVEN_OPTS_LOCAL_REPO")
	return out
}

// baselineDefaultRoots returns the curated set of global/user
// package-manager install roots, language toolchains, editor-extension
// trees, MCP config locations, and Homebrew lib prefixes. No
// developer-project trees: those belong to the project profile.
//
// When opts.AllUsers is set on macOS, the per-user candidate set is
// expanded across every real /Users/<name>/ home (see allUsersHomes),
// and system/Homebrew roots are included exactly once.
func baselineDefaultRoots(opts rootsOpts) ([]scanner.Root, []string) {
	var candidates []scanner.Root
	var notes []string

	for _, home := range homesForExpansion(opts) {
		candidates = append(candidates, baselineHomeCandidates(home)...)
	}
	candidates = append(candidates, systemRoots()...)
	candidates = append(candidates, envOverrideRoots()...)

	present, filterNotes := filterExistingRoots(candidates)
	notes = append(notes, filterNotes...)
	if opts.AllUsers && allUsersSupported() {
		notes = append(notes, allUsersExpansionNote())
	} else if opts.AllUsers {
		notes = append(notes, allUsersUnsupportedNote())
	}
	return present, notes
}

// projectDefaultRoots returns the curated set of developer/project
// trees. These are the locations where npm/PyPI exposure overwhelmingly
// lives on a developer endpoint (project lockfiles, node_modules,
// per-project virtualenvs).
func projectDefaultRoots(opts rootsOpts) ([]scanner.Root, []string) {
	var candidates []scanner.Root
	for _, home := range homesForExpansion(opts) {
		candidates = append(candidates, projectHomeCandidates(home)...)
	}
	present, notes := filterExistingRoots(candidates)
	if opts.AllUsers && allUsersSupported() {
		notes = append(notes, allUsersExpansionNote())
	} else if opts.AllUsers {
		notes = append(notes, allUsersUnsupportedNote())
	}
	return present, notes
}

// homesForExpansion returns the list of home directories whose per-user
// candidate sets should be expanded for this run. Under --all-users on
// macOS and Windows, it is every real home under the platform's users
// directory; otherwise it is the current process owner's home (or empty
// when that cannot be determined).
//
// Windows matters here as much as macOS: an EDR or fleet agent runs as
// SYSTEM, whose home is C:\Windows\system32\config\systemprofile. That
// profile has no developer trees, so a baseline or project scan started
// by an agent finds no default roots at all and exits rather than
// scanning the humans' profiles it was pointed at. Expanding across
// <drive>:\Users is what makes an agent-run scan see anything.
//
// Linux honors only the current home: there is no single canonical home
// parent (/home, /var/home, /export/home, ...), and guessing wrong is
// worse than requiring an explicit --root.
func homesForExpansion(opts rootsOpts) []string {
	if opts.AllUsers && allUsersSupported() {
		homes := allUsersHomes(usersDirOverride())
		if len(homes) > 0 {
			return homes
		}
		// Fall back to the current home if enumeration found nothing
		// usable — never silently degrade to no homes.
	}
	if home, _ := os.UserHomeDir(); home != "" {
		return []string{home}
	}
	return nil
}

// allUsersSupported reports whether --all-users can expand on this OS.
func allUsersSupported() bool {
	switch runtime.GOOS {
	case "darwin", "windows":
		return true
	default:
		return false
	}
}

// allUsersExpansionNote returns the human-readable diagnostic line
// surfaced when --all-users is engaged. It is included alongside the
// "default roots: N present, M absent" note so operators can confirm
// the expansion ran.
func allUsersExpansionNote() string {
	homes := allUsersHomes(usersDirOverride())
	return fmt.Sprintf("--all-users expansion: %d home(s) under %s", len(homes), usersDirEffective())
}

func allUsersUnsupportedNote() string {
	return fmt.Sprintf("--all-users expansion: not supported on %s; using current user's default roots", runtime.GOOS)
}

// usersDirEffective returns the /Users-style parent directory currently
// in effect. The override (set in tests) wins; otherwise /Users.
func usersDirEffective() string {
	if d := usersDirOverride(); d != "" {
		return d
	}
	return defaultUsersDir()
}

// defaultUsersDir is the platform's parent directory for user homes.
// On Windows it is derived from %SystemDrive% rather than hardcoded to
// C:, because a machine imaged onto another drive letter still keeps
// Users at the root of the system drive.
func defaultUsersDir() string {
	if runtime.GOOS != "windows" {
		return "/Users"
	}
	drive := strings.TrimSpace(os.Getenv("SystemDrive"))
	if drive == "" {
		drive = "C:"
	}
	return drive + `\Users`
}

// usersDirOverride returns a test-only override of the /Users parent
// directory. Production callers leave BUMBLEBEE_USERS_DIR unset and the
// override resolves to the empty string, which means "use /Users".
//
// The override is read from an environment variable rather than wired
// through resolveRoots' signature so tests do not have to thread a
// fake /Users path through every caller; production builds simply
// never set the variable.
func usersDirOverride() string {
	return strings.TrimSpace(os.Getenv("BUMBLEBEE_USERS_DIR"))
}

// allUsersHomes enumerates real per-user home directories under the
// given /Users-style parent. It is intentionally simple: it lists the
// directory, drops well-known service/system entries and anything that
// is not a plain directory, and returns absolute paths. We do not call
// Directory Services or read /etc/passwd; on a typical macOS host the
// /Users directory listing is authoritative for "users who have a home
// on this box."
//
// Filtering rules (lowercased basename match unless noted):
//
//   - Shared, Guest, root, Deleted Users — Apple/service entries.
//   - .localized and any other dotfile — hidden /Users entries are not
//     user homes.
//   - Entries that are not directories (e.g. .DS_Store).
//
// usersDir == "" defaults to /Users so callers do not need to special-
// case the production path.
func allUsersHomes(usersDir string) []string {
	if usersDir == "" {
		usersDir = defaultUsersDir()
	}
	entries, err := os.ReadDir(usersDir)
	if err != nil {
		return nil
	}
	var homes []string
	for _, e := range entries {
		name := e.Name()
		if !isLikelyUserHomeName(name) {
			continue
		}
		full := filepath.Join(usersDir, name)
		// Resolve symlinks so a /Users entry pointing at a non-directory
		// (or at another /Users entry we already counted) does not
		// double-count.
		info, err := os.Stat(full)
		if err != nil || !info.IsDir() {
			continue
		}
		homes = append(homes, full)
	}
	return homes
}

// isLikelyUserHomeName returns true for a basename that looks like a
// real user home under the platform's users directory. It is name-based
// only; the caller still has to confirm the entry is a directory.
func isLikelyUserHomeName(name string) bool {
	if name == "" || name == "." || name == ".." {
		return false
	}
	// Skip hidden entries (.DS_Store, .localized). Real user accounts
	// are not created with leading dots.
	if strings.HasPrefix(name, ".") {
		return false
	}
	switch strings.ToLower(name) {
	// macOS service entries.
	case "shared", "guest", "root", "deleted users":
		return false
	// Windows service and template profiles. "Default" and "Default
	// User" are the templates new profiles are copied from, "Public" is
	// the shared tree, and the *ServiceProfile entries belong to
	// LOCAL SERVICE / NETWORK SERVICE. None of them is a person, and
	// scanning them yields records attributed to a user that does not
	// exist.
	case "public", "default", "default user", "all users",
		"defaultapppool", "localservice", "networkservice",
		"systemprofile":
		return false
	}
	return true
}

// browserExtensionCandidateRoots returns absolute paths to per-profile
// Chromium-family Extensions/ directories and Firefox profile parents
// where extensions.json lives. The list is per-OS; non-existent paths
// are dropped later by filterExistingRoots.
//
// We enumerate the common profile names (Default, Profile 1..Profile 9)
// rather than walking the parent app directory, because the parent
// directory contains TCC-protected and privacy-sensitive subtrees
// (Cookies, Login Data, IndexedDB) we must not enter.
func browserExtensionCandidateRoots(home string) []string {
	var roots []string
	chromiumProfiles := []string{"Default", "Profile 1", "Profile 2", "Profile 3", "Profile 4", "Profile 5", "Profile 6", "Profile 7", "Profile 8", "Profile 9"}

	chromiumBases := map[string][]string{}
	switch runtime.GOOS {
	case "darwin":
		appSupport := filepath.Join(home, "Library", "Application Support")
		chromiumBases["chrome"] = []string{filepath.Join(appSupport, "Google", "Chrome")}
		chromiumBases["chromium"] = []string{filepath.Join(appSupport, "Chromium")}
		chromiumBases["brave"] = []string{filepath.Join(appSupport, "BraveSoftware", "Brave-Browser")}
		chromiumBases["edge"] = []string{filepath.Join(appSupport, "Microsoft Edge")}
		chromiumBases["vivaldi"] = []string{filepath.Join(appSupport, "Vivaldi")}
		chromiumBases["arc"] = []string{filepath.Join(appSupport, "Arc", "User Data")}
		chromiumBases["comet"] = []string{filepath.Join(appSupport, "Comet")}
	case "linux":
		cfg := filepath.Join(home, ".config")
		chromiumBases["chrome"] = []string{filepath.Join(cfg, "google-chrome")}
		chromiumBases["chromium"] = []string{
			filepath.Join(cfg, "chromium"),
			filepath.Join(home, "snap", "chromium", "common", "chromium"),
			filepath.Join(home, ".var", "app", "org.chromium.Chromium", "config", "chromium"),
		}
		chromiumBases["brave"] = []string{
			filepath.Join(cfg, "BraveSoftware", "Brave-Browser"),
			filepath.Join(home, ".var", "app", "com.brave.Browser", "config", "BraveSoftware", "Brave-Browser"),
		}
		chromiumBases["edge"] = []string{
			filepath.Join(cfg, "microsoft-edge"),
			filepath.Join(home, ".var", "app", "com.microsoft.Edge", "config", "microsoft-edge"),
		}
		chromiumBases["vivaldi"] = []string{filepath.Join(cfg, "vivaldi")}
	case "windows":
		local := windowsLocalAppData(home)
		chromiumBases["chrome"] = []string{filepath.Join(local, "Google", "Chrome", "User Data")}
		chromiumBases["chromium"] = []string{filepath.Join(local, "Chromium", "User Data")}
		chromiumBases["brave"] = []string{filepath.Join(local, "BraveSoftware", "Brave-Browser", "User Data")}
		chromiumBases["edge"] = []string{filepath.Join(local, "Microsoft", "Edge", "User Data")}
		chromiumBases["vivaldi"] = []string{filepath.Join(local, "Vivaldi", "User Data")}
		chromiumBases["arc"] = []string{filepath.Join(local, "Arc", "User Data")}
	}
	for _, bases := range chromiumBases {
		for _, b := range bases {
			for _, prof := range chromiumProfiles {
				roots = append(roots, filepath.Join(b, prof, "Extensions"))
			}
		}
	}

	// Firefox-family: scan the profile parent directory so extensions.json
	// in each <hash>.<name>/ profile is reachable. The profile parent has
	// only a few files we don't open (profiles.ini, installs.ini) plus
	// per-profile subdirs; visiting it is cheap.
	switch runtime.GOOS {
	case "darwin":
		appSupport := filepath.Join(home, "Library", "Application Support")
		roots = append(roots,
			filepath.Join(appSupport, "Firefox", "Profiles"),
			filepath.Join(appSupport, "LibreWolf", "Profiles"),
			filepath.Join(appSupport, "Waterfox", "Profiles"),
		)
	case "linux":
		roots = append(roots,
			filepath.Join(home, ".mozilla", "firefox"),
			filepath.Join(home, "snap", "firefox", "common", ".mozilla", "firefox"),
			filepath.Join(home, ".var", "app", "org.mozilla.firefox", ".mozilla", "firefox"),
			filepath.Join(home, ".librewolf"),
			filepath.Join(home, ".var", "app", "io.gitlab.librewolf-community", ".librewolf"),
			filepath.Join(home, ".waterfox"),
		)
	case "windows":
		appdata := windowsRoamingAppData(home)
		roots = append(roots,
			filepath.Join(appdata, "Mozilla", "Firefox", "Profiles"),
			filepath.Join(appdata, "LibreWolf", "Profiles"),
			filepath.Join(appdata, "Waterfox", "Profiles"),
		)
	}
	return roots
}

// filterExistingRoots returns the subset of candidate roots that exist,
// along with a short note describing how many were skipped. Absent
// candidates are normal on most developer machines. Both directories and
// regular files are kept: a handful of roots (e.g. `~/.claude.json`) are
// single config files rather than trees, and the walker handles a file
// root by visiting just that file.
func filterExistingRoots(candidates []scanner.Root) ([]scanner.Root, []string) {
	var present []scanner.Root
	skipped := 0
	for _, c := range candidates {
		info, err := os.Stat(c.Path)
		if err != nil || (!info.IsDir() && !info.Mode().IsRegular()) {
			skipped++
			continue
		}
		present = append(present, c)
	}
	if len(present) == 0 {
		return nil, nil
	}
	if skipped == 0 {
		return present, nil
	}
	return present, []string{
		fmt.Sprintf("default roots: %d present, %d candidate paths absent (use --root to override)",
			len(present), skipped),
	}
}
