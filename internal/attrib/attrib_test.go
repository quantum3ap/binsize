package attrib

import "testing"

func TestAttributeGo(t *testing.T) {
	cases := []struct {
		sym  string
		want string
	}{
		{"github.com/foo/bar.Func", "github.com/foo/bar"},
		{"github.com/foo/bar.(*Type).Method", "github.com/foo/bar"},
		{"runtime.mallocgc", "runtime"},
		{"net/http.(*Server).Serve", "net/http"},
		{"main.main", "main"},
		{"vendor/golang.org/x/net/idna.ToASCII", "vendor/golang.org/x/net/idna"},

		// Generic instantiations: the type argument contains its own slashes
		// and dots and must not be mistaken for the package path.
		{"slices.pdqsortCmpFunc[go.shape.struct { encoding/json.v reflect.Value }]", "slices"},
		{"reflect..dict.TypeFor[encoding/asn1.RawValue]", "reflect"},
		{"slices..dict.heapSortCmpFunc[encoding/json.field]", "slices"},

		// Parenthesised linker-generated symbols.
		{"runtime/cgo(.text)", "runtime/cgo"},
		{"net(.text)", "net"},

		// Compiler-generated buckets.
		{"type:.eq.[8]interface {}", "<compiler-generated>"},
		{"go:itab.*os.File,io.Writer", "<compiler-generated>"},
		{"gclocals·abc123", "<compiler-generated>"},

		{"_rt0_amd64_linux", "<unattributed>"},
	}
	for _, c := range cases {
		if got := Attribute("go", c.sym).Group; got != c.want {
			t.Errorf("Attribute(go, %q) = %q, want %q", c.sym, got, c.want)
		}
	}
}

func TestAttributeRust(t *testing.T) {
	cases := []struct{ sym, want string }{
		{"_ZN4core3fmt9Formatter3pad17h9f3c1a2b4d5e6f70E", "core"},
		{"_ZN5serde2de6impls5visit17h0123456789abcdefE", "serde"},
		{"my_crate::module::func", "my_crate"},
	}
	for _, c := range cases {
		if got := Attribute("rustc", c.sym).Group; got != c.want {
			t.Errorf("Attribute(rustc, %q) = %q, want %q", c.sym, got, c.want)
		}
	}
}

// The trailing hash on legacy-mangled Rust symbols is not stable across
// builds. Leaving it in place would make every symbol look renamed on every
// diff, which would render symbol-level comparison useless.
func TestNormalizeSymbolStripsRustHash(t *testing.T) {
	in := "_ZN4core3fmt9Formatter3pad17h9f3c1a2b4d5e6f70E"
	want := "_ZN4core3fmt9Formatter3pad"
	if got := NormalizeSymbol("rustc", in); got != want {
		t.Errorf("NormalizeSymbol = %q, want %q", got, want)
	}
	if got := NormalizeSymbol("go", in); got != in {
		t.Errorf("NormalizeSymbol(go) must not rewrite: got %q", got)
	}
}
