// Package report defines the on-disk schema emitted by `binsize analyze`.
//
// This schema is the contract between the CLI, the GitHub Action, and any
// future hosted service. Baselines committed by users are encoded with it, so
// treat SchemaVersion as a real compatibility boundary: additive fields are
// fine, renames and semantic changes are not.
package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// SchemaVersion is bumped only on breaking changes to the Report shape.
const SchemaVersion = 1

// Report is the full size profile of a single binary artifact.
type Report struct {
	SchemaVersion int       `json:"schema_version"`
	ToolVersion   string    `json:"tool_version"`
	GeneratedAt   time.Time `json:"generated_at"`

	Target    Target    `json:"target"`
	Toolchain Toolchain `json:"toolchain"`
	Totals    Totals    `json:"totals"`

	Sections []Section `json:"sections"`
	Groups   []Group   `json:"groups"`
	Symbols  []Symbol  `json:"symbols,omitempty"`
}

// Target describes the artifact itself.
type Target struct {
	// Label distinguishes artifacts within one repo (e.g. "cli", "daemon").
	// It is part of the baseline key, so a matrix build can track many targets.
	Label   string `json:"label"`
	Path    string `json:"path"`
	Format  string `json:"format"` // elf | macho | pe
	OS      string `json:"os"`
	Arch    string `json:"arch"`
	BuildID string `json:"build_id,omitempty"`
	// Stripped means no usable symbol table was found; the report degrades to
	// section-level only and symbol/group deltas must not be reported as zero.
	Stripped bool `json:"stripped"`
}

// Toolchain captures everything that changes binary size without the source
// changing. Comparing across a difference in any of these fields produces
// noise that reads as a regression, which is the fastest way to lose a user's
// trust in the bot.
type Toolchain struct {
	Compiler   string `json:"compiler"` // go | rustc | clang | gcc | unknown
	Version    string `json:"version"`
	BuildFlags string `json:"build_flags,omitempty"`
	// RunnerImage is best-effort (ImageOS on GitHub runners). Linker output can
	// differ between runner images even at an identical compiler version.
	RunnerImage string `json:"runner_image,omitempty"`
}

// Totals are the headline numbers.
type Totals struct {
	FileSize int64 `json:"file_size"`
	VMSize   int64 `json:"vm_size"`
	// Attributed is the sum of symbol sizes we could assign to a group.
	// Unattributed = FileSize - Attributed, and is expected to be large:
	// debug info, string tables and padding are not symbols.
	Attributed   int64 `json:"attributed"`
	Unattributed int64 `json:"unattributed"`
	SymbolCount  int   `json:"symbol_count"`
	// AttributionMethod records how symbol sizes were obtained.
	//
	//	symtab - exact, read from the symbol table (ELF st_size)
	//	gap    - approximate, derived from the distance to the next symbol
	//
	// Mach-O and PE symbol tables do not store sizes, so "gap" is the only
	// option there. Gap-derived sizes absorb inter-symbol padding, which makes
	// attributed totals run materially higher than symtab totals for identical
	// source. The two are therefore never comparable, which is why this is part
	// of the fingerprint.
	AttributionMethod string `json:"attribution_method"`
	// Overcounted is set when attribution exceeded file size, which should be
	// impossible and indicates a sizing bug rather than a large binary.
	Overcounted bool `json:"overcounted,omitempty"`
}

// Section is a linker section / Mach-O section.
type Section struct {
	Name     string `json:"name"`
	FileSize int64  `json:"file_size"`
	VMSize   int64  `json:"vm_size"`
}

// Group is an aggregation of symbols: a Go package, a Rust crate, a C++
// namespace, or a synthetic bucket like "<runtime>".
type Group struct {
	Name        string `json:"name"`
	Kind        string `json:"kind"` // package | crate | namespace | synthetic
	Size        int64  `json:"size"`
	SymbolCount int    `json:"symbol_count"`
}

// Symbol is one entry from the symbol table.
type Symbol struct {
	Name    string `json:"name"`
	Group   string `json:"group"`
	Section string `json:"section,omitempty"`
	Size    int64  `json:"size"`
}

// Fingerprint hashes the fields that must match for two reports to be
// comparable. Deliberately excludes BuildID and paths, which change on every
// build without meaning anything, and excludes Label, which is compared
// separately so a mismatch can produce a clearer error.
func (r *Report) Fingerprint() string {
	h := sha256.New()
	fmt.Fprintf(h, "v%d\n", r.SchemaVersion)
	fmt.Fprintf(h, "%s\n%s\n%s\n", r.Target.Format, r.Target.OS, r.Target.Arch)
	fmt.Fprintf(h, "%t\n", r.Target.Stripped)
	fmt.Fprintf(h, "%s\n", r.Totals.AttributionMethod)
	fmt.Fprintf(h, "%s\n%s\n%s\n%s\n",
		r.Toolchain.Compiler, r.Toolchain.Version,
		r.Toolchain.BuildFlags, r.Toolchain.RunnerImage)
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// Comparable reports whether two reports can be diffed without producing
// misleading results, and if not, why.
func Comparable(base, head *Report) (bool, string) {
	if base.Target.Label != head.Target.Label {
		return false, fmt.Sprintf("different targets (%q vs %q)",
			base.Target.Label, head.Target.Label)
	}
	if base.Fingerprint() == head.Fingerprint() {
		return true, ""
	}
	var d []string
	add := func(field, a, b string) {
		if a != b {
			d = append(d, fmt.Sprintf("%s %q -> %q", field, a, b))
		}
	}
	add("os", base.Target.OS, head.Target.OS)
	add("arch", base.Target.Arch, head.Target.Arch)
	add("format", base.Target.Format, head.Target.Format)
	add("compiler", base.Toolchain.Compiler, head.Toolchain.Compiler)
	add("compiler version", base.Toolchain.Version, head.Toolchain.Version)
	add("build flags", base.Toolchain.BuildFlags, head.Toolchain.BuildFlags)
	add("runner image", base.Toolchain.RunnerImage, head.Toolchain.RunnerImage)
	add("attribution method", base.Totals.AttributionMethod, head.Totals.AttributionMethod)
	if base.Target.Stripped != head.Target.Stripped {
		d = append(d, fmt.Sprintf("stripped %t -> %t",
			base.Target.Stripped, head.Target.Stripped))
	}
	if len(d) == 0 {
		d = append(d, "schema version changed")
	}
	return false, strings.Join(d, "; ")
}

// Finalize sorts collections into a stable order and computes derived totals.
// Stable ordering keeps committed baseline JSON diff-friendly in git.
func (r *Report) Finalize() {
	sort.Slice(r.Sections, func(i, j int) bool { return r.Sections[i].Name < r.Sections[j].Name })
	sort.Slice(r.Groups, func(i, j int) bool {
		if r.Groups[i].Size != r.Groups[j].Size {
			return r.Groups[i].Size > r.Groups[j].Size
		}
		return r.Groups[i].Name < r.Groups[j].Name
	})
	sort.Slice(r.Symbols, func(i, j int) bool {
		if r.Symbols[i].Size != r.Symbols[j].Size {
			return r.Symbols[i].Size > r.Symbols[j].Size
		}
		return r.Symbols[i].Name < r.Symbols[j].Name
	})

	var attributed int64
	for _, g := range r.Groups {
		attributed += g.Size
	}
	r.Totals.Attributed = attributed
	r.Totals.Unattributed = r.Totals.FileSize - attributed
	// Attribution must never exceed the file. Flag rather than clamp: silently
	// clamping would hide the sizing bug that caused it.
	r.Totals.Overcounted = r.Totals.Unattributed < 0
}

// Write emits indented JSON with a trailing newline.
func (r *Report) Write(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// Read parses a report and rejects schema versions from the future.
func Read(rd io.Reader) (*Report, error) {
	var r Report
	if err := json.NewDecoder(rd).Decode(&r); err != nil {
		return nil, err
	}
	if r.SchemaVersion > SchemaVersion {
		return nil, fmt.Errorf(
			"report uses schema v%d but this binsize understands up to v%d; upgrade binsize",
			r.SchemaVersion, SchemaVersion)
	}
	return &r, nil
}
