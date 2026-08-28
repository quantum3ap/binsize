// Package diffreport compares two reports and renders the result.
//
// The markdown renderer here becomes the PR comment, which is the entire
// product surface most users ever see. It is worth more polish than the
// parsing code.
package diffreport

import (
	"fmt"
	"sort"
	"strings"

	"github.com/quantum3ap/binsize/internal/report"
)

// GroupDelta is one group's change between base and head.
type GroupDelta struct {
	Name  string `json:"name"`
	Kind  string `json:"kind"`
	Base  int64  `json:"base"`
	Head  int64  `json:"head"`
	Delta int64  `json:"delta"`
	// New and Removed mark groups present on only one side.
	New     bool `json:"new,omitempty"`
	Removed bool `json:"removed,omitempty"`
}

// Diff is the full comparison.
type Diff struct {
	Label       string       `json:"label"`
	Comparable  bool         `json:"comparable"`
	Reason      string       `json:"reason,omitempty"`
	Stripped    bool         `json:"stripped"`
	Approximate bool         `json:"approximate"`
	BaseTotal   int64        `json:"base_total"`
	HeadTotal   int64        `json:"head_total"`
	Delta       int64        `json:"delta"`
	Percent     float64      `json:"percent"`
	Groups      []GroupDelta `json:"groups"`
	Sections    []GroupDelta `json:"sections"`
}

// Compute diffs two reports. An incomparable pair still yields total file size
// deltas, because that number is always meaningful; only the attribution is
// suppressed, with the reason surfaced to the user.
func Compute(base, head *report.Report) *Diff {
	ok, reason := report.Comparable(base, head)
	d := &Diff{
		Label:       head.Target.Label,
		Comparable:  ok,
		Reason:      reason,
		Stripped:    head.Target.Stripped || base.Target.Stripped,
		Approximate: head.Totals.AttributionMethod == "gap",
		BaseTotal:   base.Totals.FileSize,
		HeadTotal:   head.Totals.FileSize,
	}
	d.Delta = d.HeadTotal - d.BaseTotal
	if d.BaseTotal > 0 {
		d.Percent = float64(d.Delta) / float64(d.BaseTotal) * 100
	}
	if !ok {
		return d
	}

	d.Sections = deltas(
		index(base.Sections, func(s report.Section) (string, string, int64) {
			return s.Name, "section", s.FileSize
		}),
		index(head.Sections, func(s report.Section) (string, string, int64) {
			return s.Name, "section", s.FileSize
		}))

	d.Groups = deltas(
		index(base.Groups, func(g report.Group) (string, string, int64) {
			return g.Name, g.Kind, g.Size
		}),
		index(head.Groups, func(g report.Group) (string, string, int64) {
			return g.Name, g.Kind, g.Size
		}))
	return d
}

type entry struct {
	kind string
	size int64
}

func index[T any](items []T, key func(T) (string, string, int64)) map[string]entry {
	m := make(map[string]entry, len(items))
	for _, it := range items {
		n, k, s := key(it)
		m[n] = entry{kind: k, size: s}
	}
	return m
}

func deltas(base, head map[string]entry) []GroupDelta {
	seen := map[string]bool{}
	var out []GroupDelta
	for name, h := range head {
		seen[name] = true
		b, ok := base[name]
		if h.size == b.size {
			continue
		}
		out = append(out, GroupDelta{
			Name: name, Kind: h.kind, Base: b.size, Head: h.size,
			Delta: h.size - b.size, New: !ok,
		})
	}
	for name, b := range base {
		if seen[name] {
			continue
		}
		out = append(out, GroupDelta{
			Name: name, Kind: b.kind, Base: b.size, Head: 0,
			Delta: -b.size, Removed: true,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		ai, aj := out[i].Delta, out[j].Delta
		if ai < 0 {
			ai = -ai
		}
		if aj < 0 {
			aj = -aj
		}
		if ai != aj {
			return ai > aj
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// CommentMarker lets the Action find and update its own previous comment
// instead of posting a new one on every push. Keep this string stable forever.
const CommentMarker = "<!-- binsize-report -->"

// Markdown renders the PR comment. topN caps the visible rows; the rest go
// into a collapsed section so the comment stays scannable on a busy PR.
func Markdown(d *Diff, threshold int64, topN int) string {
	var b strings.Builder
	b.WriteString(CommentMarker + "\n")
	fmt.Fprintf(&b, "### Binary size: `%s`\n\n", d.Label)

	verdict := "no significant change"
	switch {
	case !d.Comparable:
		verdict = "not comparable"
	case d.Delta > threshold:
		verdict = fmt.Sprintf("grew %s", human(d.Delta))
	case d.Delta < -threshold:
		verdict = fmt.Sprintf("shrank %s", human(-d.Delta))
	}

	fmt.Fprintf(&b, "**%s** — %s to %s (%+.2f%%)\n\n",
		verdict, human(d.BaseTotal), human(d.HeadTotal), d.Percent)

	if !d.Comparable {
		fmt.Fprintf(&b,
			"> Attribution suppressed: the baseline was built differently (%s).\n"+
				"> Sizes across differing build settings are not comparable, so only the\n"+
				"> total is shown. Rebuild the baseline on the default branch to restore detail.\n",
			d.Reason)
		return b.String()
	}

	if d.Approximate {
		b.WriteString("> Sizes are approximate: this format's symbol table stores no " +
			"sizes, so they are derived from the gap to the next symbol and include " +
			"padding. Deltas remain meaningful; absolute totals run high.\n\n")
	}

	if d.Stripped {
		b.WriteString("> Symbol table not present (binary is stripped). " +
			"Section-level detail only.\n\n")
	}

	if len(d.Groups) > 0 {
		b.WriteString("| " + groupHeader(d) + " | Base | Head | Delta |\n|---|--:|--:|--:|\n")
		writeRows(&b, d.Groups, topN)
		if len(d.Groups) > topN {
			fmt.Fprintf(&b, "\n<details><summary>%d more changed</summary>\n\n",
				len(d.Groups)-topN)
			b.WriteString("| " + groupHeader(d) + " | Base | Head | Delta |\n|---|--:|--:|--:|\n")
			writeRows(&b, d.Groups[topN:], len(d.Groups))
			b.WriteString("\n</details>\n")
		}
	}

	if len(d.Sections) > 0 {
		b.WriteString("\n<details><summary>Sections</summary>\n\n")
		b.WriteString("| Section | Base | Head | Delta |\n|---|--:|--:|--:|\n")
		writeRows(&b, d.Sections, len(d.Sections))
		b.WriteString("\n</details>\n")
	}
	return b.String()
}

// groupHeader picks a column label matching what the groups actually are.
// "Package" is wrong for a Rust or C++ binary.
func groupHeader(d *Diff) string {
	kinds := map[string]int{}
	for _, g := range d.Groups {
		kinds[g.Kind]++
	}
	best, n := "", 0
	for k, c := range kinds {
		if c > n && k != "synthetic" {
			best, n = k, c
		}
	}
	switch best {
	case "package":
		return "Package"
	case "crate":
		return "Crate"
	case "namespace":
		return "Namespace"
	default:
		return "Group"
	}
}

func writeRows(b *strings.Builder, rows []GroupDelta, n int) {
	for i, g := range rows {
		if i >= n {
			break
		}
		tag := ""
		if g.New {
			tag = " *(new)*"
		} else if g.Removed {
			tag = " *(removed)*"
		}
		fmt.Fprintf(b, "| `%s`%s | %s | %s | %s |\n",
			g.Name, tag, human(g.Base), human(g.Head), signed(g.Delta))
	}
}

func signed(n int64) string {
	if n > 0 {
		return "+" + human(n)
	}
	if n < 0 {
		return "-" + human(-n)
	}
	return "0 B"
}

func human(n int64) string {
	neg := n < 0
	if neg {
		n = -n
	}
	var s string
	switch {
	case n < 1024:
		s = fmt.Sprintf("%d B", n)
	case n < 1024*1024:
		s = fmt.Sprintf("%.1f KiB", float64(n)/1024)
	case n < 1024*1024*1024:
		s = fmt.Sprintf("%.2f MiB", float64(n)/(1024*1024))
	default:
		s = fmt.Sprintf("%.2f GiB", float64(n)/(1024*1024*1024))
	}
	if neg {
		return "-" + s
	}
	return s
}
