package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestBudgetExitCode verifies the contract CI depends on: exit 2 when growth
// exceeds the budget, exit 0 when it does not. A wrong exit code here means
// every downstream workflow silently passes.
func TestBudgetExitCode(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	dir := t.TempDir()
	bin := toolBinaryPath(dir)
	if b, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, b)
	}

	base := buildFixture(t, dir, "base", `package main

import "fmt"

func main() { fmt.Println("hi") }
`)
	head := buildFixture(t, dir, "head", `package main

import (
	"encoding/json"
	"fmt"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]int{"a": 1})
	})
	fmt.Println("hi")
}
`)

	baseJSON := filepath.Join(dir, "base.json")
	headJSON := filepath.Join(dir, "head.json")
	run(t, bin, "analyze", base, "--label", "cli", "-o", baseJSON)
	run(t, bin, "analyze", head, "--label", "cli", "-o", headJSON)

	tests := []struct {
		name   string
		budget string
		want   int
	}{
		{"exceeded", "1000", 2},
		{"within", "999999999", 0},
		{"disabled", "0", 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(bin, "diff", baseJSON, headJSON,
				"--budget", tc.budget, "-o", os.DevNull)
			err := cmd.Run()
			got := 0
			if ee, ok := err.(*exec.ExitError); ok {
				got = ee.ExitCode()
			} else if err != nil {
				t.Fatalf("run: %v", err)
			}
			if got != tc.want {
				t.Errorf("budget %s: exit %d, want %d", tc.budget, got, tc.want)
			}
		})
	}
}

// TestFlagsAfterPositional covers the arg permutation: users write the binary
// path before the flags, and Go's flag package stops parsing at the first
// positional without it.
func TestFlagsAfterPositional(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	dir := t.TempDir()
	bin := toolBinaryPath(dir)
	if b, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, b)
	}
	app := buildFixture(t, dir, "app", "package main\n\nfunc main() {}\n")

	out := filepath.Join(dir, "r.json")
	run(t, bin, "analyze", app, "--label", "cli", "-o", out)
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("report not written: %v", err)
	}
}

// toolBinaryPath returns the path to build the binsize CLI itself for exec'ing
// in a test. This is the host binary, not a cross-compiled fixture: "go build
// -o binsize ." on Windows does not append .exe automatically the way the
// default (no -o) build does, and a file with no extension is not
// recognized as executable, so exec.Command fails with "file not found"
// even though the file exists.
func toolBinaryPath(dir string) string {
	name := "binsize"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join(dir, name)
}

func buildFixture(t *testing.T, dir, name, src string) string {
	t.Helper()
	sub := filepath.Join(dir, name)
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(sub, "main.go"), src)
	write(t, filepath.Join(sub, "go.mod"), "module "+name+"\n\ngo 1.22\n")
	out := filepath.Join(dir, name+".bin")
	cmd := exec.Command("go", "build", "-o", out, ".")
	cmd.Dir = sub
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", name, err, b)
	}
	return out
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func run(t *testing.T, args ...string) {
	t.Helper()
	cmd := exec.Command(args[0], args[1:]...)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, b)
	}
}
