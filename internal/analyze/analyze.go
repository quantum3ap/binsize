// Package analyze reads a compiled artifact and produces a report.Report.
//
// Everything here uses only the standard library (debug/elf, debug/macho,
// debug/pe, debug/buildinfo), which is why the CLI cross-compiles to every
// runner platform with no cgo and no system dependencies. That property is
// what lets the GitHub Action be a composite action that runs on Linux, macOS
// and Windows runners rather than a Linux-only Docker action.
package analyze

import (
	"debug/buildinfo"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/quantum3ap/binsize/internal/attrib"
	"github.com/quantum3ap/binsize/internal/report"
)

// Options configures a single analysis run.
type Options struct {
	Label       string
	BuildFlags  string
	RunnerImage string
	ToolVersion string
	// Compiler, when set, overrides detection. Detection is a heuristic for
	// anything that is not a Go binary, so an explicit value is preferred in CI.
	Compiler string
	// KeepSymbols retains the full symbol list in the report. Baselines
	// committed to a repo usually want this off; a 40MB binary can carry
	// hundreds of thousands of symbols.
	KeepSymbols bool
	// TopSymbols caps retained symbols when KeepSymbols is set.
	TopSymbols int
}

type rawSymbol struct {
	name    string
	size    int64
	section string
}

// Run analyzes the artifact at path.
func Run(path string, opt Options) (*report.Report, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}

	label := opt.Label
	if label == "" {
		label = filepath.Base(path)
	}

	r := &report.Report{
		SchemaVersion: report.SchemaVersion,
		ToolVersion:   opt.ToolVersion,
		GeneratedAt:   time.Now().UTC().Truncate(time.Second),
		Target: report.Target{
			Label: label,
			Path:  filepath.ToSlash(path),
		},
		Toolchain: report.Toolchain{
			Compiler:    "unknown",
			BuildFlags:  opt.BuildFlags,
			RunnerImage: opt.RunnerImage,
		},
		Totals: report.Totals{FileSize: fi.Size()},
	}

	var syms []rawSymbol
	switch {
	case isELF(path):
		r.Totals.AttributionMethod = "symtab"
		err = readELF(path, r, &syms)
	case isMachO(path):
		r.Totals.AttributionMethod = "gap"
		err = readMachO(path, r, &syms)
	case isPE(path):
		r.Totals.AttributionMethod = "gap"
		err = readPE(path, r, &syms)
	default:
		return nil, fmt.Errorf("%s: unrecognized binary format (want ELF, Mach-O or PE)", path)
	}
	if err != nil {
		return nil, err
	}

	// Go build info is embedded in the binary itself and survives -s -w, so
	// this works even on stripped binaries where the symbol table is gone.
	if bi, biErr := buildinfo.ReadFile(path); biErr == nil {
		r.Toolchain.Compiler = "go"
		r.Toolchain.Version = bi.GoVersion
		if opt.BuildFlags == "" {
			r.Toolchain.BuildFlags = goBuildFlags(bi)
		}
		// GOOS/GOARCH from build info are authoritative and use Go's naming,
		// which keeps the fingerprint consistent across all three formats.
		for _, st := range bi.Settings {
			switch st.Key {
			case "GOOS":
				r.Target.OS = st.Value
			case "GOARCH":
				r.Target.Arch = st.Value
			}
		}
	} else if r.Toolchain.Compiler == "unknown" {
		r.Toolchain.Compiler = guessCompiler(syms)
	}

	if opt.Compiler != "" {
		r.Toolchain.Compiler = opt.Compiler
	}
	r.Target.Stripped = len(syms) == 0
	attributeAll(r, syms, opt)
	r.Finalize()
	return r, nil
}

// goBuildFlags extracts the size-relevant build settings. Changing any of
// these changes binary size without the source changing, which is exactly
// what the comparability fingerprint needs to catch.
func goBuildFlags(bi *buildinfo.BuildInfo) string {
	want := map[string]bool{
		"-ldflags": true, "-gcflags": true, "-tags": true,
		"-trimpath": true, "CGO_ENABLED": true, "-buildmode": true,
	}
	var parts []string
	for _, s := range bi.Settings {
		if want[s.Key] && s.Value != "" {
			parts = append(parts, s.Key+"="+s.Value)
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, " ")
}

// Mach-O section types that occupy virtual memory but no file bytes.
// (Values from <mach-o/loader.h>: S_ZEROFILL, S_GB_ZEROFILL,
// S_THREAD_LOCAL_ZEROFILL.)
func isZeroFill(flags uint32) bool {
	switch flags & 0xff {
	case 0x1, 0xc, 0x12:
		return true
	}
	return false
}

// normalizeArch maps the many spellings of an architecture onto Go's GOARCH
// names, so an amd64 report from ELF, Mach-O and PE all compare equal.
func normalizeArch(s string) string {
	switch strings.ToLower(s) {
	case "x86_64", "amd64":
		return "amd64"
	case "aarch64", "arm64":
		return "arm64"
	case "386", "i386", "x86":
		return "386"
	case "arm":
		return "arm"
	case "riscv", "riscv64":
		return "riscv64"
	case "ppc64", "ppc64le":
		return "ppc64le"
	case "s390", "s390x":
		return "s390x"
	default:
		return strings.ToLower(s)
	}
}

func guessCompiler(syms []rawSymbol) string {
	for _, s := range syms {
		if strings.Contains(s.name, "17h") && strings.HasPrefix(s.name, "_ZN") {
			return "rustc"
		}
	}
	return "unknown"
}

func attributeAll(r *report.Report, syms []rawSymbol, opt Options) {
	type agg struct {
		size  int64
		count int
		kind  string
	}
	groups := map[string]*agg{}
	kept := make([]report.Symbol, 0, len(syms))

	for _, s := range syms {
		if s.size <= 0 {
			continue
		}
		name := attrib.NormalizeSymbol(r.Toolchain.Compiler, s.name)
		res := attrib.Attribute(r.Toolchain.Compiler, name)
		g, ok := groups[res.Group]
		if !ok {
			g = &agg{kind: res.Kind}
			groups[res.Group] = g
		}
		g.size += s.size
		g.count++
		kept = append(kept, report.Symbol{
			Name: name, Group: res.Group, Section: s.section, Size: s.size,
		})
	}

	for name, g := range groups {
		r.Groups = append(r.Groups, report.Group{
			Name: name, Kind: g.kind, Size: g.size, SymbolCount: g.count,
		})
	}

	r.Totals.SymbolCount = len(kept)

	if opt.KeepSymbols {
		sort.Slice(kept, func(i, j int) bool { return kept[i].Size > kept[j].Size })
		if opt.TopSymbols > 0 && len(kept) > opt.TopSymbols {
			kept = kept[:opt.TopSymbols]
		}
		r.Symbols = kept
	}
}

// --- format detection ---

func magic(path string, n int) []byte {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	b := make([]byte, n)
	if _, err := f.Read(b); err != nil {
		return nil
	}
	return b
}

func isELF(path string) bool {
	m := magic(path, 4)
	return len(m) == 4 && m[0] == 0x7f && m[1] == 'E' && m[2] == 'L' && m[3] == 'F'
}

func isMachO(path string) bool {
	m := magic(path, 4)
	if len(m) != 4 {
		return false
	}
	h := hex.EncodeToString(m)
	// 32/64-bit, both endiannesses, plus universal ("fat") binaries.
	switch h {
	case "feedface", "cefaedfe", "feedfacf", "cffaedfe", "cafebabe", "bebafeca":
		return true
	}
	return false
}

func isPE(path string) bool {
	m := magic(path, 2)
	return len(m) == 2 && m[0] == 'M' && m[1] == 'Z'
}

// --- ELF ---

func readELF(path string, r *report.Report, syms *[]rawSymbol) error {
	f, err := elf.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	r.Target.Format = "elf"
	// ELF OSABI is ELFOSABI_NONE for almost every real binary, including every
	// Go binary, so it carries no information. Default to linux and let Go
	// build info override with the true GOOS when present.
	r.Target.OS = "linux"
	r.Target.Arch = normalizeArch(strings.TrimPrefix(f.Machine.String(), "EM_"))

	names := make([]string, len(f.Sections))
	nobits := make([]bool, len(f.Sections))
	for i, s := range f.Sections {
		names[i] = s.Name
		nobits[i] = s.Type == elf.SHT_NOBITS
		fileSize := int64(s.Size)
		if s.Type == elf.SHT_NOBITS { // .bss occupies no file space
			fileSize = 0
		}
		r.Sections = append(r.Sections, report.Section{
			Name: s.Name, FileSize: fileSize, VMSize: int64(s.Size),
		})
		r.Totals.VMSize += int64(s.Size)
	}

	if id := elfBuildID(f); id != "" {
		r.Target.BuildID = id
	}

	table, err := f.Symbols()
	if err != nil {
		return nil // no .symtab: stripped binary, section data still valid
	}
	for _, s := range table {
		sec := ""
		if int(s.Section) < len(names) && s.Section != elf.SHN_UNDEF {
			// A symbol in a SHT_NOBITS section (.bss, .tbss) has a real st_size
			// but occupies no file bytes. Attributing it would inflate the
			// report by the size of every zero-initialised global.
			if nobits[s.Section] {
				continue
			}
			sec = names[s.Section]
		}
		*syms = append(*syms, rawSymbol{name: s.Name, size: int64(s.Size), section: sec})
	}
	return nil
}

func elfBuildID(f *elf.File) string {
	s := f.Section(".note.gnu.build-id")
	if s == nil {
		return ""
	}
	data, err := s.Data()
	if err != nil || len(data) <= 16 {
		return ""
	}
	return hex.EncodeToString(data[16:])
}

// --- Mach-O ---

func readMachO(path string, r *report.Report, syms *[]rawSymbol) error {
	f, err := macho.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	r.Target.Format = "macho"
	r.Target.OS = "darwin"
	r.Target.Arch = normalizeArch(strings.TrimPrefix(f.Cpu.String(), "Cpu"))

	type secRange struct {
		name       string
		start, end uint64
	}
	var ranges []secRange
	for _, s := range f.Sections {
		full := s.Seg + "," + s.Name
		zeroFill := isZeroFill(s.Flags)
		fileSize := int64(s.Size)
		if zeroFill {
			fileSize = 0 // __bss and __common occupy no file bytes
		}
		r.Sections = append(r.Sections, report.Section{
			Name: full, FileSize: fileSize, VMSize: int64(s.Size),
		})
		r.Totals.VMSize += int64(s.Size)
		if zeroFill || s.Size == 0 {
			continue
		}
		ranges = append(ranges, secRange{full, s.Addr, s.Addr + s.Size})
	}

	if f.Symtab == nil {
		return nil
	}
	// Mach-O symbol table entries carry no size field, so derive size from the
	// gap to the next symbol address within the same section. This is the same
	// approach `nm` users end up taking by hand.
	type addrSym struct {
		name string
		addr uint64
		sect string
	}
	var list []addrSym
	for _, s := range f.Symtab.Syms {
		if s.Sect == 0 || s.Value == 0 || s.Name == "" {
			continue
		}
		sect := ""
		for _, rg := range ranges {
			if s.Value >= rg.start && s.Value < rg.end {
				sect = rg.name
				break
			}
		}
		if sect == "" {
			continue // outside every file-backed section
		}
		list = append(list, addrSym{strings.TrimPrefix(s.Name, "_"), s.Value, sect})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].addr < list[j].addr })

	for i, s := range list {
		var end uint64
		if i+1 < len(list) && list[i+1].sect == s.sect {
			end = list[i+1].addr
		} else {
			for _, rg := range ranges {
				if rg.name == s.sect {
					end = rg.end
					break
				}
			}
		}
		if end > s.addr {
			*syms = append(*syms, rawSymbol{
				name: s.name, size: int64(end - s.addr), section: s.sect,
			})
		}
	}
	return nil
}

// --- PE ---

func readPE(path string, r *report.Report, syms *[]rawSymbol) error {
	f, err := pe.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	r.Target.Format = "pe"
	r.Target.OS = "windows"
	switch f.Machine {
	case pe.IMAGE_FILE_MACHINE_AMD64:
		r.Target.Arch = "amd64"
	case pe.IMAGE_FILE_MACHINE_ARM64:
		r.Target.Arch = "arm64"
	case pe.IMAGE_FILE_MACHINE_I386:
		r.Target.Arch = "386"
	default:
		r.Target.Arch = fmt.Sprintf("machine-0x%x", uint16(f.Machine))
	}

	type secRange struct {
		name       string
		start, end uint32
	}
	var ranges []secRange
	for _, s := range f.Sections {
		r.Sections = append(r.Sections, report.Section{
			Name: s.Name, FileSize: int64(s.Size), VMSize: int64(s.VirtualSize),
		})
		r.Totals.VMSize += int64(s.VirtualSize)
		// Bound symbol attribution by SizeOfRawData, not VirtualSize. A
		// zero-fill section (.bss and friends) can claim hundreds of MB of
		// virtual address space backed by zero file bytes; attributing that
		// span to the last symbol inflates the report by orders of magnitude.
		extent := s.VirtualSize
		if s.Size < extent {
			extent = s.Size
		}
		if extent == 0 {
			continue
		}
		ranges = append(ranges, secRange{s.Name, s.VirtualAddress, s.VirtualAddress + extent})
	}

	// COFF symbols also lack sizes; same next-address approach as Mach-O.
	type addrSym struct {
		name string
		addr uint32
		sect string
	}
	inRange := func(name string, addr uint32) bool {
		for _, rg := range ranges {
			if rg.name == name && addr >= rg.start && addr < rg.end {
				return true
			}
		}
		return false
	}
	var list []addrSym
	for _, s := range f.Symbols {
		if s.SectionNumber <= 0 || int(s.SectionNumber) > len(f.Sections) {
			continue
		}
		sec := f.Sections[s.SectionNumber-1]
		addr := sec.VirtualAddress + s.Value
		if !inRange(sec.Name, addr) {
			continue // symbol lives in zero-fill space; no file bytes to attribute
		}
		list = append(list, addrSym{s.Name, addr, sec.Name})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].addr < list[j].addr })

	for i, s := range list {
		var end uint32
		if i+1 < len(list) && list[i+1].sect == s.sect {
			end = list[i+1].addr
		} else {
			for _, rg := range ranges {
				if rg.name == s.sect {
					end = rg.end
					break
				}
			}
		}
		if end > s.addr {
			*syms = append(*syms, rawSymbol{
				name: s.name, size: int64(end - s.addr), section: s.sect,
			})
		}
	}
	return nil
}
