// Command binsize reports and diffs compiled binary size, attributed to the
// packages responsible.
//
//	binsize analyze ./bin/app --label cli -o report.json
//	binsize diff base.json head.json --format markdown --threshold 10240
//
// Exit codes: 0 ok, 1 error, 2 size budget exceeded (so CI can fail the job).
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/hassonyshaker633-svg/binsize/internal/analyze"
	"github.com/hassonyshaker633-svg/binsize/internal/diffreport"
	"github.com/hassonyshaker633-svg/binsize/internal/report"
)

var version = "0.1.0-dev" // set via -ldflags at release time

const exitBudgetExceeded = 2

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	var err error
	switch os.Args[1] {
	case "analyze":
		err = cmdAnalyze(os.Args[2:])
	case "diff":
		err = cmdDiff(os.Args[2:])
	case "version":
		fmt.Println(version)
	case "-h", "--help", "help":
		usage()
	default:
		usage()
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "binsize:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `binsize - track binary size regressions

  binsize analyze <binary> [flags]     write a size report
  binsize diff <base.json> <head.json> [flags]
  binsize version

Run "binsize analyze -h" or "binsize diff -h" for flags.
`)
}

func cmdAnalyze(args []string) error {
	fs := flag.NewFlagSet("analyze", flag.ContinueOnError)
	out := fs.String("o", "-", "output path, or - for stdout")
	label := fs.String("label", "", "target label (defaults to file name)")
	buildFlags := fs.String("build-flags", "", "override detected build flags")
	runnerImage := fs.String("runner-image", os.Getenv("ImageOS"), "CI runner image identifier")
	keepSymbols := fs.Bool("symbols", false, "include individual symbols in the report")
	topSymbols := fs.Int("top-symbols", 500, "max symbols to keep when -symbols is set")
	compiler := fs.String("compiler", "", "override detected compiler (go|rustc|clang|gcc)")
	if err := fs.Parse(permute(args)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("expected exactly one binary path")
	}

	r, err := analyze.Run(fs.Arg(0), analyze.Options{
		Label:       *label,
		BuildFlags:  *buildFlags,
		RunnerImage: *runnerImage,
		ToolVersion: version,
		KeepSymbols: *keepSymbols,
		TopSymbols:  *topSymbols,
		Compiler:    *compiler,
	})
	if err != nil {
		return err
	}

	w := os.Stdout
	if *out != "-" {
		f, err := os.Create(*out)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}
	return r.Write(w)
}

func cmdDiff(args []string) error {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	format := fs.String("format", "markdown", "markdown | json")
	threshold := fs.Int64("threshold", 10*1024, "bytes of growth tolerated before the diff is called a regression")
	budget := fs.Int64("budget", 0, "exit 2 if growth exceeds this many bytes (0 disables)")
	topN := fs.Int("top", 15, "rows shown before collapsing the rest")
	out := fs.String("o", "-", "output path, or - for stdout")
	if err := fs.Parse(permute(args)); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return fmt.Errorf("expected <base.json> <head.json>")
	}

	base, err := readReport(fs.Arg(0))
	if err != nil {
		return err
	}
	head, err := readReport(fs.Arg(1))
	if err != nil {
		return err
	}

	d := diffreport.Compute(base, head)

	w := os.Stdout
	if *out != "-" {
		f, err := os.Create(*out)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}

	switch *format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(d); err != nil {
			return err
		}
	case "markdown":
		fmt.Fprint(w, diffreport.Markdown(d, *threshold, *topN))
	default:
		return fmt.Errorf("unknown format %q", *format)
	}

	// Budget enforcement runs even when the reports are incomparable: total
	// file size is always a valid signal, and silently passing a build that
	// blew the budget is worse than a spurious failure the user can explain.
	if *budget > 0 && d.Delta > *budget {
		fmt.Fprintf(os.Stderr, "binsize: growth %d B exceeds budget %d B\n", d.Delta, *budget)
		os.Exit(exitBudgetExceeded)
	}
	return nil
}

// permute moves flags ahead of positional arguments. Go's flag package stops
// parsing at the first non-flag argument, but every user will reasonably write
// "binsize analyze ./bin/app --label cli". Everything after a literal "--" is
// left untouched.
func permute(args []string) []string {
	var flags, positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if len(a) > 1 && a[0] == '-' {
			flags = append(flags, a)
			// A flag consumes the next token only when it is not "-flag=value"
			// and the following token is not itself a flag.
			if !strings.Contains(a, "=") && i+1 < len(args) &&
				!strings.HasPrefix(args[i+1], "-") && !isBoolFlag(a) {
				flags = append(flags, args[i+1])
				i++
			}
			continue
		}
		positional = append(positional, a)
	}
	return append(flags, positional...)
}

// isBoolFlag lists flags that take no value, so permute does not swallow the
// following positional argument.
func isBoolFlag(f string) bool {
	switch strings.TrimLeft(f, "-") {
	case "symbols", "h", "help":
		return true
	}
	return false
}

func readReport(path string) (*report.Report, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r, err := report.Read(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return r, nil
}
