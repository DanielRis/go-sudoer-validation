package sudoers

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzValidate checks that no input makes Validate panic or produce an
// empty diagnostic.
func FuzzValidate(f *testing.F) {
	for _, pattern := range []string{"testdata/cases/*.sudoers", "testdata/regress/*.in"} {
		files, _ := filepath.Glob(pattern)
		for _, file := range files {
			if data, err := os.ReadFile(file); err == nil {
				f.Add(data, false)
			}
		}
	}
	f.Fuzz(func(t *testing.T, data []byte, strict bool) {
		res := Validate(data, Options{Strict: strict})
		for _, d := range res.Diagnostics {
			if d.Message == "" {
				t.Fatalf("empty diagnostic message: %+v", d)
			}
		}
	})
}
