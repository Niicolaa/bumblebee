// Package scanner orchestrates a read-only package inventory scan.
//
// It walks configured roots, dispatches matching files to ecosystem scanners,
// applies a per-scan time bound, and emits NDJSON records through the
// supplied Emitter. The orchestrator owns concurrency: ecosystem scanners
// themselves are single-threaded per file.
package scanner

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/perplexityai/bumblebee/internal/ecosystem/browserext"
	"github.com/perplexityai/bumblebee/internal/ecosystem/bun"
	"github.com/perplexityai/bumblebee/internal/ecosystem/cargo"
	"github.com/perplexityai/bumblebee/internal/ecosystem/composer"
	"github.com/perplexityai/bumblebee/internal/ecosystem/conan"
	"github.com/perplexityai/bumblebee/internal/ecosystem/editorext"
	"github.com/perplexityai/bumblebee/internal/ecosystem/gomod"
	"github.com/perplexityai/bumblebee/internal/ecosystem/hex"
	"github.com/perplexityai/bumblebee/internal/ecosystem/homebrew"
	"github.com/perplexityai/bumblebee/internal/ecosystem/julia"
	"github.com/perplexityai/bumblebee/internal/ecosystem/maven"
	"github.com/perplexityai/bumblebee/internal/ecosystem/mcp"
	"github.com/perplexityai/bumblebee/internal/ecosystem/npm"
	"github.com/perplexityai/bumblebee/internal/ecosystem/nuget"
	"github.com/perplexityai/bumblebee/internal/ecosystem/pnpm"
	"github.com/perplexityai/bumblebee/internal/ecosystem/pub"
	"github.com/perplexityai/bumblebee/internal/ecosystem/pypi"
	"github.com/perplexityai/bumblebee/internal/ecosystem/rubygems"
	"github.com/perplexityai/bumblebee/internal/ecosystem/skills"
	"github.com/perplexityai/bumblebee/internal/ecosystem/swift"
	"github.com/perplexityai/bumblebee/internal/ecosystem/yarn"
	"github.com/perplexityai/bumblebee/internal/exposure"
	"github.com/perplexityai/bumblebee/internal/model"
	"github.com/perplexityai/bumblebee/internal/output"
	"github.com/perplexityai/bumblebee/internal/walk"
)

// Job kinds link the walker's dispatch switch to the worker's
// handler switch. They are constants rather than literals so a typo
// on either side is a compile error instead of an ecosystem that
// silently stops producing records.
const (
	kindBunLock           = "bun-lock"
	kindCargoLock         = "cargo-lock"
	kindChromiumExt       = "chromium-ext"
	kindCocoapodsLock     = "cocoapods-lock"
	kindComposerInstalled = "composer-installed"
	kindComposerLock      = "composer-lock"
	kindConanLock         = "conan-lock"
	kindEditorExt         = "editor-ext"
	kindFirefoxExt        = "firefox-ext"
	kindGoBinary          = "go-binary"
	kindGoMod             = "go-mod"
	kindGoSum             = "go-sum"
	kindGoVendor          = "go-vendor"
	kindGoWorkSum         = "go-work-sum"
	kindHexLock           = "hex-lock"
	kindHomebrewCask      = "homebrew-cask"
	kindHomebrewFormula   = "homebrew-formula"
	kindJuliaManifest     = "julia-manifest"
	kindMavenArchive      = "maven-archive"
	kindMavenGradle       = "maven-gradle"
	kindMavenPom          = "maven-pom"
	kindMavenSbt          = "maven-sbt"
	kindMcpClaudeConfig   = "mcp-claude-config"
	kindMcpCodex          = "mcp-codex"
	kindMcpConfig         = "mcp-config"
	kindNpmLock           = "npm-lock"
	kindNpmPj             = "npm-pj"
	kindNugetConfig       = "nuget-config"
	kindNugetDeps         = "nuget-deps"
	kindNugetLock         = "nuget-lock"
	kindNugetNuspec       = "nuget-nuspec"
	kindNugetProps        = "nuget-props"
	kindPnpmLock          = "pnpm-lock"
	kindPnpmPj            = "pnpm-pj"
	kindPubLock           = "pub-lock"
	kindPyDist            = "py-dist"
	kindPyEgg             = "py-egg"
	kindPyPipfile         = "py-pipfile"
	kindPyPoetry          = "py-poetry"
	kindPyPylock          = "py-pylock"
	kindPyRequirements    = "py-requirements"
	kindPyUv              = "py-uv"
	kindRbLock            = "rb-lock"
	kindRbSpec            = "rb-spec"
	kindSkillLock         = "skill-lock"
	kindSwiftResolved     = "swift-resolved"
	kindYarnLock          = "yarn-lock"
)

// Root pairs a filesystem path with the RootKind that explains why it
// is being walked. The RootKind of the longest enclosing configured
// root is stamped onto every record produced from the subtree so
// receivers can tell global toolchain inventory apart from a
// configured project tree apart from a deep incident sweep. Scanners
// that pre-fill RootKind on their records (e.g. browser extensions,
// MCP configs) are overridden by the enclosing configured root when
// one matches; their value is used only as a fallback for records
// that fall outside every configured root.
type Root struct {
	Path string
	Kind string
}

// isExpectedAccessError reports whether err is one of the routine
// "I can't read this" errors that show up constantly when walking a
// macOS home directory or any privacy-protected tree. These are not
// scanner failures; they are the OS telling us a subtree is off-limits.
// We surface them at debug level so operators who want to audit them
// can, but they no longer make a healthy scan look broken.
func isExpectedAccessError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrPermission) || errors.Is(err, fs.ErrPermission) {
		return true
	}
	// macOS TCC denials surface as EPERM ("operation not permitted")
	// rather than EACCES; cover both.
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case syscall.EACCES, syscall.EPERM:
			return true
		}
	}

	return false
}

// isMissingPathError reports whether err is a "no such file or directory"
// (ENOENT) — typical for a default-candidate root that the host does not
// have. We surface these at info rather than warn so fleet pipelines do
// not have to whitelist routine per-host absences.
func isMissingPathError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, fs.ErrNotExist) {
		return true
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno == syscall.ENOENT
	}
	return false
}

type Config struct {
	Profile     string
	Roots       []Root
	Excludes    []string
	Ecosystems  map[string]bool
	MaxFileSize int64
	MaxDuration time.Duration
	Concurrency int

	// Catalog, when non-nil, drives finding emission. Every accepted
	// package record is matched against it; matches produce a
	// model.Finding record on the same sink.
	Catalog *exposure.Catalog
	// FindingsOnly suppresses package records from the records sink while
	// still evaluating them for exposure matches.
	FindingsOnly bool

	BaseRecord model.Record
	Emitter    *output.Emitter
}

type Result struct {
	FilesConsidered          int
	RecordsEmitted           int
	PackageRecordsSuppressed int
	FindingsEmitted          int
	Duplicates               int
	Diagnostics              int
	TimedOut                 bool
	Duration                 time.Duration
}

// Run executes one scan and returns aggregate counters. It blocks until
// the walker finishes or ctx is cancelled.
func Run(ctx context.Context, cfg Config) (Result, error) {
	if cfg.Concurrency < 1 {
		cfg.Concurrency = 4
	}
	if cfg.MaxDuration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cfg.MaxDuration)
		defer cancel()
	}

	start := time.Now()
	cfg.BaseRecord.Profile = cfg.Profile

	rootKindFor := newRootKindLookup(cfg.Roots)

	var findingsEmitted int
	var findingsMu sync.Mutex
	var packageRecordsSuppressed int
	var suppressedMu sync.Mutex
	var emitErr error
	var emitErrMu sync.Mutex
	setEmitErr := func(err error) {
		if err == nil {
			return
		}
		emitErrMu.Lock()
		if emitErr == nil {
			emitErr = err
		}
		emitErrMu.Unlock()
	}
	emit := func(r model.Record) {
		// Prefer the root_kind derived from the configured Roots so we
		// keep populations consistent. If the lookup can't classify the
		// source file (e.g. an operator-supplied root with an unrelated
		// kind), fall back to a scanner-supplied RootKind on the record
		// before defaulting to unknown.
		if rk := rootKindFor(r.SourceFile); rk != model.RootKindUnknown {
			r.RootKind = rk
		} else if r.RootKind == "" {
			r.RootKind = model.RootKindUnknown
		}
		if r.Profile == "" {
			r.Profile = cfg.Profile
		}
		r, written := cfg.Emitter.ObservePackage(r)
		if cfg.FindingsOnly {
			if written {
				suppressedMu.Lock()
				packageRecordsSuppressed++
				suppressedMu.Unlock()
			}
		} else {
			if written {
				if err := cfg.Emitter.EmitObservedPackage(r); err != nil {
					setEmitErr(fmt.Errorf("emit package record: %w", err))
					return
				}
			}
		}
		if !written {
			// Dedup suppressed; an earlier identical record already
			// produced its finding (if any). Skip to avoid emitting
			// the same finding twice for the same source file.
			return
		}
		if cfg.Catalog != nil {
			// Emit one finding per matching catalog entry. With one
			// catalog file per advisory, overlapping advisories on the
			// same (ecosystem, name, version) are realistic and must not
			// be silently masked. Finding.StableID includes catalog_id,
			// so per-entry findings have distinct record_ids.
			for _, m := range cfg.Catalog.MatchAll(r) {
				entry, version := m.Entry, m.Version
				evidence := "exact name+version match (version=" + version + ")"
				if entry.AnyVersion() {
					evidence = "exact name match, catalog entry matches any version (version=" + version + ")"
				}
				f := model.Finding{
					RecordType:     model.RecordTypeFinding,
					SchemaVersion:  cfg.BaseRecord.SchemaVersion,
					ScannerName:    cfg.BaseRecord.ScannerName,
					ScannerVersion: cfg.BaseRecord.ScannerVersion,
					RunID:          cfg.BaseRecord.RunID,
					ScanTime:       cfg.BaseRecord.ScanTime,
					Endpoint:       cfg.BaseRecord.Endpoint,
					Profile:        cfg.Profile,
					FindingType:    model.FindingTypePackageExposure,
					Severity:       entry.Severity,
					CatalogID:      entry.ID,
					CatalogName:    entry.Name,
					Ecosystem:      r.Ecosystem,
					PackageName:    r.PackageName,
					NormalizedName: r.NormalizedName,
					Version:        r.Version,
					RootKind:       r.RootKind,
					ProjectPath:    r.ProjectPath,
					SourceType:     r.SourceType,
					SourceFile:     r.SourceFile,
					Confidence:     r.Confidence,
					Evidence:       evidence,
				}
				if err := cfg.Emitter.EmitFinding(f); err == nil {
					findingsMu.Lock()
					findingsEmitted++
					findingsMu.Unlock()
				} else {
					setEmitErr(fmt.Errorf("emit finding record: %w", err))
					break
				}
			}
		}
	}
	diag := cfg.Emitter.Diag

	npmS := &npm.Scanner{MaxFileSize: cfg.MaxFileSize, Emit: emit, Diag: diag}
	pyS := &pypi.Scanner{MaxFileSize: cfg.MaxFileSize, Emit: emit, Diag: diag}
	pnpmS := &pnpm.Scanner{MaxFileSize: cfg.MaxFileSize, Emit: emit, Diag: diag}
	yarnS := &yarn.Scanner{MaxFileSize: cfg.MaxFileSize, Emit: emit, Diag: diag}
	bunS := &bun.Scanner{MaxFileSize: cfg.MaxFileSize, Emit: emit, Diag: diag}
	goS := &gomod.Scanner{MaxFileSize: cfg.MaxFileSize, Emit: emit, Diag: diag}
	rbS := &rubygems.Scanner{MaxFileSize: cfg.MaxFileSize, Emit: emit, Diag: diag}
	cmpS := &composer.Scanner{MaxFileSize: cfg.MaxFileSize, Emit: emit, Diag: diag}
	mcpS := &mcp.Scanner{MaxFileSize: cfg.MaxFileSize, Emit: emit, Diag: diag}
	skillS := &skills.Scanner{MaxFileSize: cfg.MaxFileSize, Emit: emit, Diag: diag}
	extS := &editorext.Scanner{MaxFileSize: cfg.MaxFileSize, Emit: emit, Diag: diag}
	bxS := &browserext.Scanner{MaxFileSize: cfg.MaxFileSize, Emit: emit, Diag: diag}
	hbS := &homebrew.Scanner{MaxFileSize: cfg.MaxFileSize, Emit: emit, Diag: diag}
	nugetS := &nuget.Scanner{MaxFileSize: cfg.MaxFileSize, Emit: emit, Diag: diag}
	cargoS := &cargo.Scanner{MaxFileSize: cfg.MaxFileSize, Emit: emit, Diag: diag}
	mavenS := &maven.Scanner{MaxFileSize: cfg.MaxFileSize, Emit: emit, Diag: diag}
	swiftS := &swift.Scanner{MaxFileSize: cfg.MaxFileSize, Emit: emit, Diag: diag}
	pubS := &pub.Scanner{MaxFileSize: cfg.MaxFileSize, Emit: emit, Diag: diag}
	hexS := &hex.Scanner{MaxFileSize: cfg.MaxFileSize, Emit: emit, Diag: diag}
	conanS := &conan.Scanner{MaxFileSize: cfg.MaxFileSize, Emit: emit, Diag: diag}
	juliaS := &julia.Scanner{MaxFileSize: cfg.MaxFileSize, Emit: emit, Diag: diag}

	type job struct {
		kind        string
		path        string
		projectPath string
		extra1      string // generic slot 1 (e.g., extRoot, name)
		extra2      string // generic slot 2 (e.g., extDir, version)
	}
	jobs := make(chan job, 256)

	var wg sync.WaitGroup
	for i := 0; i < cfg.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}
				emitErrMu.Lock()
				hasEmitErr := emitErr != nil
				emitErrMu.Unlock()
				if hasEmitErr {
					return
				}
				var err error
				switch j.kind {
				case kindNpmLock:
					err = npmS.ScanLockfile(j.path, cfg.BaseRecord)
				case kindNpmPj:
					err = npmS.ScanNodeModulesPackageJSON(j.path, j.projectPath, cfg.BaseRecord)
				case kindPyDist:
					err = pyS.ScanDistInfo(j.path, j.projectPath, cfg.BaseRecord)
				case kindPyEgg:
					err = pyS.ScanEggInfo(j.path, j.projectPath, cfg.BaseRecord)
				case kindPnpmLock:
					err = pnpmS.ScanLockfile(j.path, cfg.BaseRecord)
				case kindPnpmPj:
					err = pnpmS.ScanStorePackageJSON(j.path, j.projectPath, j.extra1, j.extra2, cfg.BaseRecord)
				case kindYarnLock:
					err = yarnS.ScanLockfile(j.path, cfg.BaseRecord)
				case kindBunLock:
					err = bunS.ScanTextLockfile(j.path, cfg.BaseRecord)
				case kindGoSum:
					err = goS.ScanGoSum(j.path, cfg.BaseRecord)
				case kindGoMod:
					err = goS.ScanGoMod(j.path, cfg.BaseRecord)
				case kindRbLock:
					err = rbS.ScanGemfileLock(j.path, cfg.BaseRecord)
				case kindRbSpec:
					err = rbS.ScanGemspec(j.path, j.projectPath, cfg.BaseRecord)
				case kindComposerLock:
					err = cmpS.ScanComposerLock(j.path, cfg.BaseRecord)
				case kindComposerInstalled:
					err = cmpS.ScanInstalledJSON(j.path, cfg.BaseRecord)
				case kindMcpConfig:
					err = mcpS.ScanConfig(j.path, cfg.BaseRecord)
				case kindMcpClaudeConfig:
					err = mcpS.ScanClaudeConfig(j.path, cfg.BaseRecord)
				case kindSkillLock:
					err = skillS.ScanLockFile(j.path, cfg.BaseRecord)
				case kindMcpCodex:
					err = mcpS.ScanCodexConfigTOML(j.path, cfg.BaseRecord)
				case kindEditorExt:
					err = extS.ScanExtension(j.path, j.extra1, j.extra2, cfg.BaseRecord)
				case kindChromiumExt:
					err = bxS.ScanChromiumExtension(j.path, j.extra1, j.extra2, j.projectPath, cfg.BaseRecord)
				case kindFirefoxExt:
					err = bxS.ScanFirefoxExtensions(j.path, cfg.BaseRecord)
				case kindHomebrewFormula:
					err = hbS.ScanFormulaReceipt(j.path, j.extra1, j.extra2, j.projectPath, cfg.BaseRecord)
				case kindHomebrewCask:
					err = hbS.ScanCaskMetadata(j.path, j.extra1, j.extra2, j.projectPath, cfg.BaseRecord)
				case kindGoWorkSum:
					err = goS.ScanGoWorkSum(j.path, cfg.BaseRecord)
				case kindGoVendor:
					err = goS.ScanVendorModulesTxt(j.path, cfg.BaseRecord)
				case kindGoBinary:
					err = goS.ScanGoBinary(j.path, cfg.BaseRecord)
				case kindPyRequirements:
					err = pyS.ScanRequirementsTxt(j.path, cfg.BaseRecord)
				case kindPyPipfile:
					err = pyS.ScanPipfileLock(j.path, cfg.BaseRecord)
				case kindPyPoetry:
					err = pyS.ScanPoetryLock(j.path, cfg.BaseRecord)
				case kindPyUv:
					err = pyS.ScanUvLock(j.path, cfg.BaseRecord)
				case kindPyPylock:
					err = pyS.ScanPylockTOML(j.path, cfg.BaseRecord)
				case kindNugetLock:
					err = nugetS.ScanPackagesLockJSON(j.path, cfg.BaseRecord)
				case kindNugetConfig:
					err = nugetS.ScanPackagesConfig(j.path, cfg.BaseRecord)
				case kindNugetDeps:
					err = nugetS.ScanDepsJSON(j.path, cfg.BaseRecord)
				case kindNugetProps:
					err = nugetS.ScanPackagesProps(j.path, cfg.BaseRecord)
				case kindNugetNuspec:
					err = nugetS.ScanNuspec(j.path, cfg.BaseRecord)
				case kindCargoLock:
					err = cargoS.ScanCargoLock(j.path, cfg.BaseRecord)
				case kindMavenPom:
					err = mavenS.ScanPomXML(j.path, cfg.BaseRecord)
				case kindMavenGradle:
					err = mavenS.ScanGradleLockfile(j.path, cfg.BaseRecord)
				case kindMavenSbt:
					err = mavenS.ScanSbtLock(j.path, cfg.BaseRecord)
				case kindMavenArchive:
					err = mavenS.ScanJavaArchive(j.path, cfg.BaseRecord)
				case kindSwiftResolved:
					err = swiftS.ScanPackageResolved(j.path, cfg.BaseRecord)
				case kindCocoapodsLock:
					err = swiftS.ScanPodfileLock(j.path, cfg.BaseRecord)
				case kindPubLock:
					err = pubS.ScanPubspecLock(j.path, cfg.BaseRecord)
				case kindHexLock:
					err = hexS.ScanMixLock(j.path, cfg.BaseRecord)
				case kindConanLock:
					err = conanS.ScanConanLock(j.path, cfg.BaseRecord)
				case kindJuliaManifest:
					err = juliaS.ScanManifestTOML(j.path, cfg.BaseRecord)
				}
				if err != nil {
					cfg.Emitter.Diag("error", j.path, err.Error())
				}
			}
		}()
	}

	var filesConsidered int
	excludes := append([]string{}, walk.DefaultExcludes...)
	excludes = append(excludes, cfg.Excludes...)
	walkOpts := walk.Options{
		Roots:    rootPaths(cfg.Roots),
		Excludes: excludes,
		OnError: func(path string, err error) {
			level := "warn"
			switch {
			case isExpectedAccessError(err):
				level = "debug"
			case isMissingPathError(err):
				// An absent default-candidate root is a benign,
				// expected outcome on machines that don't have that
				// path. Surface it so operators can audit, but at
				// info so fleet pipelines don't have to whitelist
				// a per-host warning.
				level = "info"
			}
			cfg.Emitter.Diag(level, path, err.Error())
		},
	}

	send := func(j job) bool {
		select {
		case <-ctx.Done():
			return false
		default:
		}
		emitErrMu.Lock()
		hasEmitErr := emitErr != nil
		emitErrMu.Unlock()
		if hasEmitErr {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case jobs <- j:
			return true
		}
	}
	enabled := func(ecosystem string) bool {
		if len(cfg.Ecosystems) == 0 {
			return true
		}
		return cfg.Ecosystems[ecosystem]
	}
	walkErr := walk.Walk(walkOpts, func(path string, d fs.DirEntry) error {
		select {
		case <-ctx.Done():
			return filepath.SkipDir
		default:
		}
		emitErrMu.Lock()
		hasEmitErr := emitErr != nil
		emitErrMu.Unlock()
		if hasEmitErr {
			return filepath.SkipDir
		}
		if d.IsDir() {
			return nil
		}
		base := d.Name()
		// Skip obvious credential-ish dotfiles even outside excluded dirs.
		if base == ".env" || base == ".envrc" {
			return nil
		}
		filesConsidered++
		switch {
		case enabled(model.EcosystemNPM) && npm.IsLockfile(base):
			send(job{kind: kindNpmLock, path: path})
		case enabled(model.EcosystemNPM) && pnpm.IsLockfile(base):
			send(job{kind: kindPnpmLock, path: path})
		case enabled(model.EcosystemNPM) && yarn.IsLockfile(base):
			send(job{kind: kindYarnLock, path: path})
		case enabled(model.EcosystemNPM) && bun.IsTextLockfile(base):
			send(job{kind: kindBunLock, path: path})
		case enabled(model.EcosystemNPM) && bun.IsBinaryLockfile(base):
			bunS.NoteBinaryLockfile(path)
		case enabled(model.EcosystemGo) && gomod.IsGoSum(base):
			send(job{kind: kindGoSum, path: path})
		case enabled(model.EcosystemGo) && gomod.IsGoMod(base):
			send(job{kind: kindGoMod, path: path})
		case enabled(model.EcosystemRubyGems) && rubygems.IsGemfileLock(base):
			send(job{kind: kindRbLock, path: path})
		case enabled(model.EcosystemRubyGems) && rubygems.IsGemspec(base):
			if ok, gemsDir := rubygems.IsInstalledGemspec(path); ok {
				send(job{kind: kindRbSpec, path: path, projectPath: gemsDir})
			}
		case enabled(model.EcosystemPackagist) && composer.IsComposerLock(base):
			send(job{kind: kindComposerLock, path: path})
		case enabled(model.EcosystemPackagist) && base == "installed.json" && composer.IsInstalledJSON(path):
			send(job{kind: kindComposerInstalled, path: path})
		case enabled(model.EcosystemMCP) && mcp.IsKnownMCPConfig(base):
			send(job{kind: kindMcpConfig, path: path})
		case enabled(model.EcosystemMCP) && base == "settings.json" && mcp.IsGeminiSettingsJSON(path):
			send(job{kind: kindMcpConfig, path: path})
		case enabled(model.EcosystemMCP) && mcp.IsClaudeConfigJSON(path):
			send(job{kind: kindMcpClaudeConfig, path: path})
		case enabled(model.EcosystemAgentSkill) && skills.IsKnownLockFile(base):
			send(job{kind: kindSkillLock, path: path})
		case enabled(model.EcosystemMCP) && base == "config.toml" && mcp.IsCodexConfigTOML(path):
			send(job{kind: kindMcpCodex, path: path})
		case enabled(model.EcosystemBrowserExtension) && base == "manifest.json":
			if ok, extID, verDir, profDir := browserext.IsChromiumExtensionManifest(path); ok {
				send(job{kind: kindChromiumExt, path: path, projectPath: profDir, extra1: extID, extra2: verDir})
			}
		case enabled(model.EcosystemBrowserExtension) && base == "extensions.json":
			if browserext.IsFirefoxExtensionsJSON(path) {
				send(job{kind: kindFirefoxExt, path: path})
			}
		case enabled(model.EcosystemHomebrew) && base == "INSTALL_RECEIPT.json":
			if ok, name, version, cellarDir := homebrew.IsFormulaReceipt(path); ok {
				send(job{kind: kindHomebrewFormula, path: path, projectPath: cellarDir, extra1: name, extra2: version})
			}
		case enabled(model.EcosystemHomebrew) && homebrew.LooksLikeCaskMetadataMarker(path):
			// This one intentionally does a tiny sibling check in the walker
			// so a cask with .internal.json, .json, and .rb markers emits only
			// Homebrew's preferred installed-cask snapshot. That adds serial
			// I/O to cask marker dispatch, but typical Caskroom cardinality is
			// small and avoiding duplicate records keeps downstream state clean.
			if ok, token, version, caskroomDir := homebrew.IsCaskMetadataMarker(path); ok {
				send(job{kind: kindHomebrewCask, path: path, projectPath: caskroomDir, extra1: token, extra2: version})
			}
		case base == "package.json":
			// Prefer extension match over node_modules.
			if enabled(model.EcosystemEditorExtension) {
				if ok, extRoot, extDir := editorext.IsExtensionPackageJSON(path); ok {
					send(job{kind: kindEditorExt, path: path, extra1: extRoot, extra2: extDir})
					break
				}
			}
			if !enabled(model.EcosystemNPM) {
				break
			}
			if ok, proj, name, ver := pnpm.IsPnpmStorePackageJSON(path); ok {
				send(job{kind: kindPnpmPj, path: path, projectPath: proj, extra1: name, extra2: ver})
				break
			}
			if ok, proj := npm.IsNodeModulesPackageJSON(path); ok {
				send(job{kind: kindNpmPj, path: path, projectPath: proj})
			}
		case enabled(model.EcosystemPyPI) && base == "METADATA":
			if ok, dir := pypi.IsDistInfoMetadata(path); ok {
				send(job{kind: kindPyDist, path: path, projectPath: dir})
			}
		case enabled(model.EcosystemPyPI) && base == "PKG-INFO":
			if ok, dir := pypi.IsEggInfoPKGInfo(path); ok {
				send(job{kind: kindPyEgg, path: path, projectPath: dir})
			}
		case enabled(model.EcosystemGo) && gomod.IsGoWorkSum(base):
			send(job{kind: kindGoWorkSum, path: path})
		case enabled(model.EcosystemGo) && base == "modules.txt" && gomod.IsVendorModulesTxt(path):
			send(job{kind: kindGoVendor, path: path})
		case enabled(model.EcosystemPyPI) && pypi.IsPipfileLock(base):
			send(job{kind: kindPyPipfile, path: path})
		case enabled(model.EcosystemPyPI) && pypi.IsPoetryLock(base):
			send(job{kind: kindPyPoetry, path: path})
		case enabled(model.EcosystemPyPI) && pypi.IsUvLock(base):
			send(job{kind: kindPyUv, path: path})
		case enabled(model.EcosystemPyPI) && pypi.IsPylockTOML(base):
			send(job{kind: kindPyPylock, path: path})
		case enabled(model.EcosystemPyPI) && pypi.IsRequirementsTxt(base):
			send(job{kind: kindPyRequirements, path: path})
		case enabled(model.EcosystemNuGet) && nuget.IsPackagesLockJSON(base):
			send(job{kind: kindNugetLock, path: path})
		case enabled(model.EcosystemNuGet) && nuget.IsPackagesConfig(base):
			send(job{kind: kindNugetConfig, path: path})
		case enabled(model.EcosystemNuGet) && nuget.IsDepsJSON(base):
			send(job{kind: kindNugetDeps, path: path})
		case enabled(model.EcosystemNuGet) && nuget.IsPackagesProps(base):
			send(job{kind: kindNugetProps, path: path})
		case enabled(model.EcosystemNuGet) && nuget.IsNuspec(base):
			if nuget.IsCachedNuspec(path) {
				send(job{kind: kindNugetNuspec, path: path})
			}
		case enabled(model.EcosystemCratesIO) && cargo.IsCargoLock(base):
			send(job{kind: kindCargoLock, path: path})
		case enabled(model.EcosystemMaven) && maven.IsPomXML(base):
			send(job{kind: kindMavenPom, path: path})
		case enabled(model.EcosystemMaven) && maven.IsGradleLockfile(base):
			send(job{kind: kindMavenGradle, path: path})
		case enabled(model.EcosystemMaven) && maven.IsSbtLock(base):
			send(job{kind: kindMavenSbt, path: path})
		case enabled(model.EcosystemMaven) && maven.IsJavaArchive(base):
			send(job{kind: kindMavenArchive, path: path})
		case enabled(model.EcosystemSwift) && swift.IsPackageResolved(base):
			send(job{kind: kindSwiftResolved, path: path})
		case enabled(model.EcosystemCocoaPods) && swift.IsPodfileLock(base):
			send(job{kind: kindCocoapodsLock, path: path})
		case enabled(model.EcosystemPub) && pub.IsPubspecLock(base):
			send(job{kind: kindPubLock, path: path})
		case enabled(model.EcosystemHex) && hex.IsMixLock(base):
			send(job{kind: kindHexLock, path: path})
		case enabled(model.EcosystemConan) && conan.IsConanLock(base):
			send(job{kind: kindConanLock, path: path})
		case enabled(model.EcosystemJulia) && julia.IsManifestTOML(base):
			send(job{kind: kindJuliaManifest, path: path})
		// Checked last: any executable in a bin/ directory is a candidate,
		// which is the broadest predicate here. Everything with a
		// recognisable filename has already matched above.
		case enabled(model.EcosystemGo) && gomod.IsGoBinaryCandidate(path, d):
			send(job{kind: kindGoBinary, path: path})
		}
		return nil
	})

	close(jobs)
	wg.Wait()

	res := Result{
		FilesConsidered: filesConsidered,
		RecordsEmitted:  cfg.Emitter.RecordsEmitted,
		FindingsEmitted: findingsEmitted,
		Duplicates:      cfg.Emitter.Duplicates,
		Diagnostics:     cfg.Emitter.Diagnostics,
		Duration:        time.Since(start),
	}
	suppressedMu.Lock()
	res.PackageRecordsSuppressed = packageRecordsSuppressed
	suppressedMu.Unlock()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		res.TimedOut = true
	}
	if emitErr != nil {
		if walkErr != nil {
			return res, fmt.Errorf("%v; %w", walkErr, emitErr)
		}
		return res, emitErr
	}
	return res, walkErr
}

// rootPaths is a small adapter so the walker keeps its []string contract.
func rootPaths(roots []Root) []string {
	out := make([]string, 0, len(roots))
	for _, r := range roots {
		out = append(out, r.Path)
	}
	return out
}

// newRootKindLookup returns a function that maps an arbitrary file path
// to the RootKind of the longest root that contains it. Paths that are
// outside any configured root (e.g. when a parser hands us a value
// the walker did not visit) get RootKindUnknown.
func newRootKindLookup(roots []Root) func(string) string {
	cleaned := make([]Root, 0, len(roots))
	for _, r := range roots {
		if r.Path == "" {
			continue
		}
		p, err := filepath.Abs(r.Path)
		if err != nil {
			p = r.Path
		}
		cleaned = append(cleaned, Root{Path: filepath.Clean(p), Kind: r.Kind})
	}
	return func(path string) string {
		if path == "" {
			return model.RootKindUnknown
		}
		abs, err := filepath.Abs(path)
		if err != nil {
			abs = path
		}
		abs = filepath.Clean(abs)
		bestLen := -1
		best := model.RootKindUnknown
		for _, r := range cleaned {
			if abs == r.Path || strings.HasPrefix(abs, r.Path+string(filepath.Separator)) {
				if len(r.Path) > bestLen {
					bestLen = len(r.Path)
					best = r.Kind
				}
			}
		}
		return best
	}
}
