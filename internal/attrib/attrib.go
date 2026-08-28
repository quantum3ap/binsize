// Package attrib maps raw symbol names onto human-meaningful groups.
//
// This is where most of the product value lives. "Your binary grew 400KB" is
// not actionable; "github.com/aws/aws-sdk-go/service/s3 grew 400KB" is.
package attrib

import (
	"regexp"
	"strings"
)

// Kind values for report.Group.Kind.
const (
	KindPackage   = "package"
	KindCrate     = "crate"
	KindNamespace = "namespace"
	KindSynthetic = "synthetic"
)

// rustHash matches the trailing disambiguator on legacy-mangled Rust symbols
// (e.g. ..17h9f3c1a2b4d5e6f70E). The hash is derived from crate metadata and
// is NOT stable across builds, so leaving it in place makes every symbol look
// renamed on every diff. Strip it before grouping or comparing.
var rustHash = regexp.MustCompile(`17h[0-9a-f]{16}E$`)

// goCompilerGenerated are prefixes the Go toolchain emits that belong to no
// user package. Bucketing them separately stops them from swamping the report.
var goCompilerGenerated = []string{
	"type:", "type..", "go:", "go.", "gclocals·", "runtime.gcbits.",
	"$f64.", "$f32.", "_cgo_",
}

// Result is the outcome of attributing one symbol.
type Result struct {
	Group string
	Kind  string
}

// Attribute picks a group for a symbol given the binary's compiler.
func Attribute(compiler, symbol string) Result {
	switch compiler {
	case "go":
		return attributeGo(symbol)
	case "rustc":
		return attributeRust(symbol)
	default:
		return attributeCLike(symbol)
	}
}

// attributeGo maps a Go symbol to its import path.
//
// Go symbol names look like:
//
//	github.com/foo/bar.Func
//	github.com/foo/bar.(*Type).Method
//	runtime.mallocgc
//	type:.eq.[8]interface {}
//
// The package path ends at the first '.' that appears after the final '/'.
func attributeGo(sym string) Result {
	for _, p := range goCompilerGenerated {
		if strings.HasPrefix(sym, p) {
			return Result{Group: "<compiler-generated>", Kind: KindSynthetic}
		}
	}

	// Generic instantiations embed whole type expressions in brackets, and
	// those contain both slashes and dots:
	//
	//	slices.pdqsortCmpFunc[go.shape.struct { encoding/json.v reflect.Value }]
	//
	// Method receivers do the same with parentheses. Cut both off before
	// looking for the package boundary, or the last '/' lands inside the type
	// argument and the group name becomes a mangled fragment.
	head := sym
	truncated := false
	if i := strings.IndexAny(head, "[("); i >= 0 {
		head = head[:i]
		truncated = true
	}
	head = strings.TrimSuffix(head, ".")

	searchFrom := 0
	if i := strings.LastIndex(head, "/"); i >= 0 {
		searchFrom = i
	}
	dot := strings.Index(head[searchFrom:], ".")
	if dot < 0 {
		// No dot after the final path element. Symbols like "runtime/cgo(.text)"
		// and "net(.text)" truncate to exactly the package path. Require that a
		// truncation actually happened, so bare linker symbols such as
		// "_rt0_amd64_linux" stay unattributed instead of inventing a package.
		if head != "" && (strings.Contains(head, "/") || truncated) {
			return Result{Group: head, Kind: KindPackage}
		}
		// Assembly stubs and linker-defined symbols.
		return Result{Group: "<unattributed>", Kind: KindSynthetic}
	}
	pkg := head[:searchFrom+dot]
	if pkg == "" {
		return Result{Group: "<unattributed>", Kind: KindSynthetic}
	}
	return Result{Group: pkg, Kind: KindPackage}
}

// attributeRust maps a mangled Rust symbol to its crate.
//
// Handles legacy mangling (_ZN4core3fmt...17h<hash>E) and v0 (_R...). For v0
// the crate name follows the leading length prefix; full v0 demangling is a
// real parser and is deliberately out of scope for v0.1.
func attributeRust(sym string) Result {
	s := strings.TrimSuffix(rustHash.ReplaceAllString(sym, ""), "::")

	if strings.HasPrefix(s, "_ZN") {
		rest := s[3:]
		// Legacy mangling is a sequence of <len><name> components.
		n := 0
		for n < len(rest) && rest[n] >= '0' && rest[n] <= '9' {
			n++
		}
		if n > 0 {
			length := 0
			for _, c := range rest[:n] {
				length = length*10 + int(c-'0')
			}
			if end := n + length; end <= len(rest) && length > 0 {
				return Result{Group: rest[n:end], Kind: KindCrate}
			}
		}
	}
	if strings.HasPrefix(s, "_R") {
		return Result{Group: "<rust-v0-mangled>", Kind: KindSynthetic}
	}
	if i := strings.Index(s, "::"); i > 0 {
		return Result{Group: s[:i], Kind: KindCrate}
	}
	return Result{Group: "<unattributed>", Kind: KindSynthetic}
}

// attributeCLike groups C and C++ symbols by top-level namespace where the
// Itanium mangling makes that cheap to read, and otherwise buckets them.
// Proper C++ demangling needs a real parser; the intended v0.2 path is to
// shell out to bloaty and ingest its output rather than reimplement it.
func attributeCLike(sym string) Result {
	if strings.HasPrefix(sym, "_ZN") {
		rest := sym[3:]
		n := 0
		for n < len(rest) && rest[n] >= '0' && rest[n] <= '9' {
			n++
		}
		if n > 0 {
			length := 0
			for _, c := range rest[:n] {
				length = length*10 + int(c-'0')
			}
			if end := n + length; end <= len(rest) && length > 0 {
				return Result{Group: rest[n:end], Kind: KindNamespace}
			}
		}
		return Result{Group: "<c++-mangled>", Kind: KindSynthetic}
	}
	if strings.HasPrefix(sym, "_") || strings.HasPrefix(sym, ".") {
		return Result{Group: "<runtime>", Kind: KindSynthetic}
	}
	return Result{Group: "<unattributed>", Kind: KindSynthetic}
}

// NormalizeSymbol strips build-unstable parts of a symbol name so the same
// function compares equal across builds.
func NormalizeSymbol(compiler, sym string) string {
	if compiler == "rustc" {
		return rustHash.ReplaceAllString(sym, "")
	}
	return sym
}
