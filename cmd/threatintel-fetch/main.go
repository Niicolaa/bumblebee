// Command threatintel-fetch pulls public threat-intelligence feeds and
// writes them into bumblebee's threat_intel/ directory as exposure
// catalogs (one file per upstream source, or one per ecosystem for OSV).
//
// Usage:
//
//	go run ./cmd/threatintel-fetch all              # refresh every source
//	go run ./cmd/threatintel-fetch malext-sentry    # one source
//	go run ./cmd/threatintel-fetch extsentry
//	go run ./cmd/threatintel-fetch vsxsentry
//	go run ./cmd/threatintel-fetch osv-malicious
//	go run ./cmd/threatintel-fetch datadog
//
// Flags:
//
//	--out <dir>     destination directory (default ./threat_intel)
//	--source <s>    override source URL (or local path/dir for tests)
//	--min-ratio <f> `all` only: fail if any existing catalog shrinks below
//	                this fraction of its previous entry count (default 0.5).
//	                Guards against a renamed upstream field silently
//	                emptying a catalog. Set to 0 to disable.
//
// Generated files are prefixed `auto-` so they are easy to distinguish
// from hand-curated campaign catalogs. The output is sorted and atomic-
// written; re-running with no upstream change is a no-op (the existing
// file is left untouched, mtime preserved).
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: threatintel-fetch <all|malext-sentry|extsentry|vsxsentry|osv-malicious|datadog> [flags]")
		os.Exit(2)
	}
	cmd := os.Args[1]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	outDir := fs.String("out", "./threat_intel", "destination directory for catalog files")
	source := fs.String("source", "", "override source URL or local path (default: upstream URL)")
	minRatio := fs.Float64("min-ratio", 0.5, "`all` only: fail if a catalog shrinks below this fraction of its previous entry count (0 disables)")
	if err := fs.Parse(os.Args[2:]); err != nil {
		os.Exit(2)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	rc := 0
	switch cmd {
	case "all":
		// Snapshot pre-fetch entry counts so the shrink guard below can
		// tell "upstream legitimately removed entries" from "upstream
		// renamed a column and we now parse zero rows".
		before := snapshotCounts(*outDir)

		if err := runMalExtSentry(ctx, *outDir, ""); err != nil {
			fmt.Fprintln(os.Stderr, "malext-sentry:", err)
			rc = 1
		}
		if err := runExtSentry(ctx, *outDir, ""); err != nil {
			fmt.Fprintln(os.Stderr, "extsentry:", err)
			rc = 1
		}
		if err := runVSXSentry(ctx, *outDir, ""); err != nil {
			fmt.Fprintln(os.Stderr, "vsxsentry:", err)
			rc = 1
		}
		if err := runOSVAll(ctx, *outDir, ""); err != nil {
			fmt.Fprintln(os.Stderr, "osv-malicious:", err)
			rc = 1
		}
		if err := runDataDogAll(ctx, *outDir, ""); err != nil {
			fmt.Fprintln(os.Stderr, "datadog:", err)
			rc = 1
		}
		if violations := checkShrink(*outDir, before, *minRatio); len(violations) > 0 {
			for _, v := range violations {
				fmt.Fprintln(os.Stderr, "shrink guard:", v)
			}
			fmt.Fprintf(os.Stderr, "shrink guard: refusing to publish; re-run with --min-ratio=0 to override\n")
			rc = 1
		}
	case "malext-sentry":
		if err := runMalExtSentry(ctx, *outDir, *source); err != nil {
			fmt.Fprintln(os.Stderr, err)
			rc = 1
		}
	case "extsentry":
		if err := runExtSentry(ctx, *outDir, *source); err != nil {
			fmt.Fprintln(os.Stderr, err)
			rc = 1
		}
	case "vsxsentry":
		if err := runVSXSentry(ctx, *outDir, *source); err != nil {
			fmt.Fprintln(os.Stderr, err)
			rc = 1
		}
	case "osv-malicious":
		if err := runOSVAll(ctx, *outDir, *source); err != nil {
			fmt.Fprintln(os.Stderr, err)
			rc = 1
		}
	case "datadog":
		if err := runDataDogAll(ctx, *outDir, *source); err != nil {
			fmt.Fprintln(os.Stderr, err)
			rc = 1
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", cmd)
		os.Exit(2)
	}
	os.Exit(rc)
}

func runMalExtSentry(ctx context.Context, outDir, source string) error {
	if source == "" {
		source = malExtSentryURL
	}
	c, err := fetchMalExtSentry(ctx, source)
	if err != nil {
		return err
	}
	path := filepath.Join(outDir, "auto-malext-sentry-browser-extensions.json")
	changed, err := writeCatalog(path, c)
	if err != nil {
		return err
	}
	report(path, len(c.Entries), changed)
	return nil
}

func runExtSentry(ctx context.Context, outDir, source string) error {
	if source == "" {
		source = extSentryURL
	}
	c, err := fetchExtSentry(ctx, source)
	if err != nil {
		return err
	}
	path := filepath.Join(outDir, "auto-extsentry-browser-extensions.json")
	changed, err := writeCatalog(path, c)
	if err != nil {
		return err
	}
	report(path, len(c.Entries), changed)
	return nil
}

func runVSXSentry(ctx context.Context, outDir, source string) error {
	if source == "" {
		source = vsxSentryURL
	}
	c, err := fetchVSXSentry(ctx, source)
	if err != nil {
		return err
	}
	path := filepath.Join(outDir, "auto-vsxsentry-editor-extensions.json")
	changed, err := writeCatalog(path, c)
	if err != nil {
		return err
	}
	report(path, len(c.Entries), changed)
	return nil
}

func runOSVAll(ctx context.Context, outDir, source string) error {
	var firstErr error
	for _, eco := range osvEcosystems {
		c, err := fetchOSVMalicious(ctx, eco, source)
		if err != nil {
			fmt.Fprintf(os.Stderr, "osv %s: %v\n", eco.osv, err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if n := osvShardCount[eco.bumblebee]; n > 1 {
			paths := shardPaths(outDir, "osv-malicious-"+eco.bumblebee, n)
			changed, total, werr := writeShardedCatalog(paths, c)
			if werr != nil {
				fmt.Fprintf(os.Stderr, "osv %s: %v\n", eco.osv, werr)
				if firstErr == nil {
					firstErr = werr
				}
				continue
			}
			state := "unchanged"
			if changed > 0 {
				state = fmt.Sprintf("updated (%d/%d shards)", changed, n)
			}
			fmt.Printf("%s (sharded x%d): %d entries (%s)\n",
				filepath.Join(outDir, "auto-osv-malicious-"+eco.bumblebee+"-*.json"),
				n, total, state)
			continue
		}
		path := filepath.Join(outDir, "auto-osv-malicious-"+eco.bumblebee+".json")
		changed, err := writeCatalog(path, c)
		if err != nil {
			fmt.Fprintf(os.Stderr, "osv %s: %v\n", eco.osv, err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		report(path, len(c.Entries), changed)
	}
	return firstErr
}

func runDataDogAll(ctx context.Context, outDir, source string) error {
	var firstErr error
	for _, eco := range dataDogEcosystems {
		c, err := fetchDataDog(ctx, eco, source)
		if err != nil {
			fmt.Fprintf(os.Stderr, "datadog %s: %v\n", eco.datadog, err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		path := filepath.Join(outDir, "auto-datadog-malicious-"+eco.bumblebee+".json")
		changed, err := writeCatalog(path, c)
		if err != nil {
			fmt.Fprintf(os.Stderr, "datadog %s: %v\n", eco.datadog, err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		report(path, len(c.Entries), changed)
	}
	return firstErr
}

func report(path string, count int, changed bool) {
	state := "unchanged"
	if changed {
		state = "updated"
	}
	fmt.Printf("%s: %d entries (%s)\n", path, count, state)
}
