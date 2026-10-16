package sudoers

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestGolden compares Validate against results recorded from a real
// visudo(8) by scripts/gen-golden.sh (see testdata/VISUDO_VERSION).
func TestGolden(t *testing.T) {
	inputs, err := filepath.Glob("testdata/cases/*.sudoers")
	if err != nil {
		t.Fatal(err)
	}
	regress, err := filepath.Glob("testdata/regress/*.in")
	if err != nil {
		t.Fatal(err)
	}
	inputs = append(inputs, regress...)
	if len(inputs) == 0 {
		t.Fatal("no golden inputs found")
	}

	for _, in := range inputs {
		golden := strings.TrimSuffix(in, filepath.Ext(in)) + ".golden"
		want := readGolden(t, golden)
		content, err := os.ReadFile(in)
		if err != nil {
			t.Fatal(err)
		}
		for _, mode := range []string{"default", "strict"} {
			t.Run(filepath.Base(in)+"/"+mode, func(t *testing.T) {
				res := Validate(content, Options{
					Filename: filepath.Base(in),
					Strict:   mode == "strict",
				})
				got := renderGolden(res)
				if got != want[mode] {
					t.Errorf("mismatch for %s (%s)\n--- got\n%s--- want\n%s",
						in, mode, got, want[mode])
				}
			})
		}
	}
}

// renderGolden formats a Result the way scripts/gen-golden.sh records
// visudo output.
func renderGolden(res *Result) string {
	var b strings.Builder
	if res.Valid() {
		b.WriteString("status: valid\n")
	} else {
		b.WriteString("status: invalid\n")
	}
	for _, d := range res.Diagnostics {
		b.WriteString(d.String())
		b.WriteByte('\n')
	}
	return b.String()
}

func readGolden(t *testing.T, path string) map[string]string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run scripts/gen-golden.sh)", err)
	}
	sections := map[string]string{}
	var cur string
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			cur = strings.Trim(line, "[]")
			continue
		}
		sections[cur] += line + "\n"
	}
	return sections
}
