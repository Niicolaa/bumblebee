// Dispatch registry: the mapping from "the walker recognised this file" to
// "this parser handles it".
//
// The walker and the worker pool are deliberately decoupled — the walker
// only does cheap basename/path matching, and the actual file read happens
// on a worker. That hand-off used to be two switch statements linked by bare
// string literals, so a typo in either one compiled cleanly and silently
// dropped every file of that type. The kinds are now typed constants with a
// single handler table, and TestEveryJobKindHasHandler asserts the table is
// complete.
package scanner

import (
	"github.com/perplexityai/bumblebee/internal/ecosystem/browserext"
	"github.com/perplexityai/bumblebee/internal/ecosystem/bun"
	"github.com/perplexityai/bumblebee/internal/ecosystem/cargo"
	"github.com/perplexityai/bumblebee/internal/ecosystem/composer"
	"github.com/perplexityai/bumblebee/internal/ecosystem/dartelixir"
	"github.com/perplexityai/bumblebee/internal/ecosystem/editorext"
	"github.com/perplexityai/bumblebee/internal/ecosystem/gomod"
	"github.com/perplexityai/bumblebee/internal/ecosystem/homebrew"
	"github.com/perplexityai/bumblebee/internal/ecosystem/maven"
	"github.com/perplexityai/bumblebee/internal/ecosystem/mcp"
	"github.com/perplexityai/bumblebee/internal/ecosystem/npm"
	"github.com/perplexityai/bumblebee/internal/ecosystem/nuget"
	"github.com/perplexityai/bumblebee/internal/ecosystem/pnpm"
	"github.com/perplexityai/bumblebee/internal/ecosystem/pylock"
	"github.com/perplexityai/bumblebee/internal/ecosystem/pypi"
	"github.com/perplexityai/bumblebee/internal/ecosystem/rubygems"
	"github.com/perplexityai/bumblebee/internal/ecosystem/skills"
	"github.com/perplexityai/bumblebee/internal/ecosystem/swiftpkg"
	"github.com/perplexityai/bumblebee/internal/ecosystem/yarn"
	"github.com/perplexityai/bumblebee/internal/model"
)

// jobKind identifies which parser entry point handles a dispatched file.
type jobKind string

const (
	jobNPMLock           jobKind = "npm-lock"
	jobNPMPackageJSON    jobKind = "npm-pj"
	jobPnpmLock          jobKind = "pnpm-lock"
	jobPnpmPackageJSON   jobKind = "pnpm-pj"
	jobYarnLock          jobKind = "yarn-lock"
	jobBunLock           jobKind = "bun-lock"
	jobPyDistInfo        jobKind = "py-dist"
	jobPyEggInfo         jobKind = "py-egg"
	jobPyRequirements    jobKind = "py-requirements"
	jobPyPipfileLock     jobKind = "py-pipfile-lock"
	jobPyPoetryLock      jobKind = "py-poetry-lock"
	jobPyUVLock          jobKind = "py-uv-lock"
	jobPyPylockTOML      jobKind = "py-pylock-toml"
	jobGoSum             jobKind = "go-sum"
	jobGoMod             jobKind = "go-mod"
	jobGoWorkSum         jobKind = "go-work-sum"
	jobGoVendorModules   jobKind = "go-vendor-modules"
	jobGemfileLock       jobKind = "rb-lock"
	jobGemspec           jobKind = "rb-spec"
	jobComposerLock      jobKind = "composer-lock"
	jobComposerInstalled jobKind = "composer-installed"
	jobMCPConfig         jobKind = "mcp-config"
	jobMCPClaudeConfig   jobKind = "mcp-claude-config"
	jobSkillLock         jobKind = "skill-lock"
	jobEditorExtension   jobKind = "editor-ext"
	jobChromiumExtension jobKind = "chromium-ext"
	jobFirefoxExtensions jobKind = "firefox-ext"
	jobHomebrewFormula   jobKind = "homebrew-formula"
	jobHomebrewCask      jobKind = "homebrew-cask"
	jobNuGetCache        jobKind = "nuget-cache"
	jobNuGetPackagesLock jobKind = "nuget-packages-lock"
	jobNuGetPackagesCfg  jobKind = "nuget-packages-config"
	jobCargoLock         jobKind = "cargo-lock"
	jobCargoRegistrySrc  jobKind = "cargo-registry-src"
	jobGradleLockfile    jobKind = "gradle-lockfile"
	jobPomXML            jobKind = "pom-xml"
	jobMavenLocalRepo    jobKind = "maven-local-repo"
	jobPackageResolved   jobKind = "swift-package-resolved"
	jobPodfileLock       jobKind = "podfile-lock"
	jobPubspecLock       jobKind = "pubspec-lock"
	jobMixLock           jobKind = "mix-lock"
)

// allJobKinds lists every kind the walker may dispatch. Adding a constant
// above without adding it here, or here without adding a handler in
// parsers.handlers, fails TestEveryJobKindHasHandler.
var allJobKinds = []jobKind{
	jobNPMLock,
	jobNPMPackageJSON,
	jobPnpmLock,
	jobPnpmPackageJSON,
	jobYarnLock,
	jobBunLock,
	jobPyDistInfo,
	jobPyEggInfo,
	jobPyRequirements,
	jobPyPipfileLock,
	jobPyPoetryLock,
	jobPyUVLock,
	jobPyPylockTOML,
	jobGoSum,
	jobGoMod,
	jobGoWorkSum,
	jobGoVendorModules,
	jobGemfileLock,
	jobGemspec,
	jobComposerLock,
	jobComposerInstalled,
	jobMCPConfig,
	jobMCPClaudeConfig,
	jobSkillLock,
	jobEditorExtension,
	jobChromiumExtension,
	jobFirefoxExtensions,
	jobHomebrewFormula,
	jobHomebrewCask,
	jobNuGetCache,
	jobNuGetPackagesLock,
	jobNuGetPackagesCfg,
	jobCargoLock,
	jobCargoRegistrySrc,
	jobGradleLockfile,
	jobPomXML,
	jobMavenLocalRepo,
	jobPackageResolved,
	jobPodfileLock,
	jobPubspecLock,
	jobMixLock,
}

// job is one recognised file handed from the walker to a worker. The
// extra slots stay generic because the walker sometimes has to do the
// path inspection itself (extension IDs, Homebrew cask tokens) and
// re-deriving it on the worker would mean a second stat of the tree.
type job struct {
	kind        jobKind
	path        string
	projectPath string
	extra1      string // generic slot 1 (e.g., extRoot, name)
	extra2      string // generic slot 2 (e.g., extDir, version)
}

// jobHandler runs one parser over one dispatched file.
type jobHandler func(j job, base model.Record) error

// parsers holds one instance of every ecosystem scanner for a run. The
// instances are stateless with respect to each other and safe for the
// worker pool to share; bun is the one that carries per-run state
// (binary-lockfile diagnostics), and it guards that itself.
type parsers struct {
	npm       *npm.Scanner
	pypi      *pypi.Scanner
	pylock    *pylock.Scanner
	pnpm      *pnpm.Scanner
	yarn      *yarn.Scanner
	bun       *bun.Scanner
	gomod     *gomod.Scanner
	rubygems  *rubygems.Scanner
	composer  *composer.Scanner
	mcp       *mcp.Scanner
	skills    *skills.Scanner
	editorext *editorext.Scanner
	browser   *browserext.Scanner
	homebrew  *homebrew.Scanner
	nuget     *nuget.Scanner
	cargo     *cargo.Scanner
	maven     *maven.Scanner
	swift     *swiftpkg.Scanner
	dartelix  *dartelixir.Scanner
}

func newParsers(maxFileSize int64, emit func(model.Record), diag func(level, path, msg string)) *parsers {
	return &parsers{
		npm:       &npm.Scanner{MaxFileSize: maxFileSize, Emit: emit, Diag: diag},
		pypi:      &pypi.Scanner{MaxFileSize: maxFileSize, Emit: emit, Diag: diag},
		pylock:    &pylock.Scanner{MaxFileSize: maxFileSize, Emit: emit, Diag: diag},
		pnpm:      &pnpm.Scanner{MaxFileSize: maxFileSize, Emit: emit, Diag: diag},
		yarn:      &yarn.Scanner{MaxFileSize: maxFileSize, Emit: emit, Diag: diag},
		bun:       &bun.Scanner{MaxFileSize: maxFileSize, Emit: emit, Diag: diag},
		gomod:     &gomod.Scanner{MaxFileSize: maxFileSize, Emit: emit, Diag: diag},
		rubygems:  &rubygems.Scanner{MaxFileSize: maxFileSize, Emit: emit, Diag: diag},
		composer:  &composer.Scanner{MaxFileSize: maxFileSize, Emit: emit, Diag: diag},
		mcp:       &mcp.Scanner{MaxFileSize: maxFileSize, Emit: emit, Diag: diag},
		skills:    &skills.Scanner{MaxFileSize: maxFileSize, Emit: emit, Diag: diag},
		editorext: &editorext.Scanner{MaxFileSize: maxFileSize, Emit: emit, Diag: diag},
		browser:   &browserext.Scanner{MaxFileSize: maxFileSize, Emit: emit, Diag: diag},
		homebrew:  &homebrew.Scanner{MaxFileSize: maxFileSize, Emit: emit, Diag: diag},
		nuget:     &nuget.Scanner{MaxFileSize: maxFileSize, Emit: emit, Diag: diag},
		cargo:     &cargo.Scanner{MaxFileSize: maxFileSize, Emit: emit, Diag: diag},
		maven:     &maven.Scanner{MaxFileSize: maxFileSize, Emit: emit, Diag: diag},
		swift:     &swiftpkg.Scanner{MaxFileSize: maxFileSize, Emit: emit, Diag: diag},
		dartelix:  &dartelixir.Scanner{MaxFileSize: maxFileSize, Emit: emit, Diag: diag},
	}
}

// handlers returns the dispatch table. It is built once per run and only
// read from the worker goroutines.
func (p *parsers) handlers() map[jobKind]jobHandler {
	return map[jobKind]jobHandler{
		jobNPMLock: func(j job, b model.Record) error {
			return p.npm.ScanLockfile(j.path, b)
		},
		jobNPMPackageJSON: func(j job, b model.Record) error {
			return p.npm.ScanNodeModulesPackageJSON(j.path, j.projectPath, b)
		},
		jobPnpmLock: func(j job, b model.Record) error {
			return p.pnpm.ScanLockfile(j.path, b)
		},
		jobPnpmPackageJSON: func(j job, b model.Record) error {
			return p.pnpm.ScanStorePackageJSON(j.path, j.projectPath, j.extra1, j.extra2, b)
		},
		jobYarnLock: func(j job, b model.Record) error {
			return p.yarn.ScanLockfile(j.path, b)
		},
		jobBunLock: func(j job, b model.Record) error {
			return p.bun.ScanTextLockfile(j.path, b)
		},
		jobPyDistInfo: func(j job, b model.Record) error {
			return p.pypi.ScanDistInfo(j.path, j.projectPath, b)
		},
		jobPyEggInfo: func(j job, b model.Record) error {
			return p.pypi.ScanEggInfo(j.path, j.projectPath, b)
		},
		jobPyRequirements: func(j job, b model.Record) error {
			return p.pylock.ScanRequirementsTxt(j.path, b)
		},
		jobPyPipfileLock: func(j job, b model.Record) error {
			return p.pylock.ScanPipfileLock(j.path, b)
		},
		jobPyPoetryLock: func(j job, b model.Record) error {
			return p.pylock.ScanPoetryLock(j.path, b)
		},
		jobPyUVLock: func(j job, b model.Record) error {
			return p.pylock.ScanUVLock(j.path, b)
		},
		jobPyPylockTOML: func(j job, b model.Record) error {
			return p.pylock.ScanPylockTOML(j.path, b)
		},
		jobGoSum: func(j job, b model.Record) error {
			return p.gomod.ScanGoSum(j.path, b)
		},
		jobGoMod: func(j job, b model.Record) error {
			return p.gomod.ScanGoMod(j.path, b)
		},
		jobGoWorkSum: func(j job, b model.Record) error {
			return p.gomod.ScanGoWorkSum(j.path, b)
		},
		jobGoVendorModules: func(j job, b model.Record) error {
			return p.gomod.ScanVendorModulesTxt(j.path, b)
		},
		jobGemfileLock: func(j job, b model.Record) error {
			return p.rubygems.ScanGemfileLock(j.path, b)
		},
		jobGemspec: func(j job, b model.Record) error {
			return p.rubygems.ScanGemspec(j.path, j.projectPath, b)
		},
		jobComposerLock: func(j job, b model.Record) error {
			return p.composer.ScanComposerLock(j.path, b)
		},
		jobComposerInstalled: func(j job, b model.Record) error {
			return p.composer.ScanInstalledJSON(j.path, b)
		},
		jobMCPConfig: func(j job, b model.Record) error {
			return p.mcp.ScanConfig(j.path, b)
		},
		jobMCPClaudeConfig: func(j job, b model.Record) error {
			return p.mcp.ScanClaudeConfig(j.path, b)
		},
		jobSkillLock: func(j job, b model.Record) error {
			return p.skills.ScanLockFile(j.path, b)
		},
		jobEditorExtension: func(j job, b model.Record) error {
			return p.editorext.ScanExtension(j.path, j.extra1, j.extra2, b)
		},
		jobChromiumExtension: func(j job, b model.Record) error {
			return p.browser.ScanChromiumExtension(j.path, j.extra1, j.extra2, j.projectPath, b)
		},
		jobFirefoxExtensions: func(j job, b model.Record) error {
			return p.browser.ScanFirefoxExtensions(j.path, b)
		},
		jobHomebrewFormula: func(j job, b model.Record) error {
			return p.homebrew.ScanFormulaReceipt(j.path, j.extra1, j.extra2, j.projectPath, b)
		},
		jobHomebrewCask: func(j job, b model.Record) error {
			return p.homebrew.ScanCaskMetadata(j.path, j.extra1, j.extra2, j.projectPath, b)
		},
		jobNuGetCache: func(j job, b model.Record) error {
			return p.nuget.ScanCachePackage(j.path, j.extra1, j.extra2, j.projectPath, b)
		},
		jobNuGetPackagesLock: func(j job, b model.Record) error {
			return p.nuget.ScanPackagesLockJSON(j.path, b)
		},
		jobNuGetPackagesCfg: func(j job, b model.Record) error {
			return p.nuget.ScanPackagesConfig(j.path, b)
		},
		jobCargoLock: func(j job, b model.Record) error {
			return p.cargo.ScanCargoLock(j.path, b)
		},
		jobCargoRegistrySrc: func(j job, b model.Record) error {
			return p.cargo.ScanRegistrySrc(j.path, j.extra1, j.extra2, j.projectPath, b)
		},
		jobGradleLockfile: func(j job, b model.Record) error {
			return p.maven.ScanGradleLockfile(j.path, b)
		},
		jobPomXML: func(j job, b model.Record) error {
			return p.maven.ScanPomXML(j.path, b)
		},
		jobMavenLocalRepo: func(j job, b model.Record) error {
			return p.maven.ScanLocalRepoArtifact(j.path, j.extra1, j.extra2, j.projectPath, b)
		},
		jobPackageResolved: func(j job, b model.Record) error {
			return p.swift.ScanPackageResolved(j.path, b)
		},
		jobPodfileLock: func(j job, b model.Record) error {
			return p.swift.ScanPodfileLock(j.path, b)
		},
		jobPubspecLock: func(j job, b model.Record) error {
			return p.dartelix.ScanPubspecLock(j.path, b)
		},
		jobMixLock: func(j job, b model.Record) error {
			return p.dartelix.ScanMixLock(j.path, b)
		},
	}
}
