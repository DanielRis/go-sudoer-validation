package sudoers

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"
)

func TestValidateString(t *testing.T) {
	res := ValidateString("bob ALL = foo\n", Options{Filename: "upload"})
	want := []string{"upload:1:11: expected a fully-qualified path name"}
	if got := diagStrings(res.Errors()); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
	if !ValidateString("root ALL=(ALL) ALL\n", Options{}).Valid() {
		t.Fatal("valid string reported invalid")
	}
}

func TestValidateReader(t *testing.T) {
	res, err := ValidateReader(strings.NewReader("bob ALL = foo\n"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Valid() {
		t.Fatal("invalid content reported valid")
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

func TestValidateReaderError(t *testing.T) {
	res, err := ValidateReader(failingReader{}, Options{})
	if err == nil || res != nil {
		t.Fatalf("got res=%v err=%v", res, err)
	}
}

// A server validates uploads concurrently; run with -race.
func TestConcurrentValidate(t *testing.T) {
	inputs := []struct {
		src   string
		valid bool
	}{
		{"root ALL=(ALL) ALL\n", true},
		{"bob ALL = foo\n", false},
		{"Defaults bogus\n", false},
		{"Cmnd_Alias C = /bin/ls\nbob ALL = C\n", true},
		{"User_Alias U = \"a b\"\nU ALL = sudoedit /etc/hosts\n", true},
	}
	var wg sync.WaitGroup
	errs := make(chan string, 100)
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				in := inputs[(g+i)%len(inputs)]
				if got := ValidateString(in.src, Options{Strict: i%2 == 0}).Valid(); got != in.valid {
					errs <- fmt.Sprintf("%q: valid=%v", in.src, got)
					return
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}

func TestResultJSON(t *testing.T) {
	res := ValidateString("Cmnd_Alias C = /bin/ls\nbob ALL = foo\nroot ALL = ALL\n", Options{Filename: "upload"})
	data, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"valid":false,"diagnostics":[{"severity":"error","file":"upload","line":2,"column":11,"message":"expected a fully-qualified path name"}]}`
	if string(data) != want {
		t.Fatalf("got  %s\nwant %s", data, want)
	}

	var back Result
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back.Diagnostics, res.Diagnostics) {
		t.Fatalf("round trip: got %+v, want %+v", back.Diagnostics, res.Diagnostics)
	}

	data, _ = json.Marshal(ValidateString("Cmnd_Alias C = /bin/ls\nroot ALL = ALL\n", Options{}))
	want = `{"valid":true,"diagnostics":[{"severity":"warning","file":"sudoers","line":1,"column":12,"message":"unused Cmnd_Alias \"C\""}]}`
	if string(data) != want {
		t.Fatalf("got  %s\nwant %s", data, want)
	}
}

// Uploaded bundles (main file plus sudoers.d) can be validated from
// memory through Options.FS.
func TestValidateUploadedBundle(t *testing.T) {
	bundle := fstest.MapFS{
		"etc/sudoers.d/admins": {Data: []byte("ADMINS ALL = (ALL) ALL\n")},
	}
	main := "User_Alias ADMINS = alice, bob\n@includedir /etc/sudoers.d\n"
	res := ValidateString(main, Options{Filename: "/etc/sudoers", FS: bundle, Strict: true})
	if len(res.Diagnostics) != 0 {
		t.Fatalf("got %v", diagStrings(res.Diagnostics))
	}
}

// Untrusted input must not make validation slow: the time taken must
// grow linearly with the input. Quadrupling the input of a quadratic
// algorithm takes 16 times as long; allow up to 8 for noise.
func TestHostileInputIsLinear(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test")
	}
	gens := map[string]func(n int) string{
		"long word":       func(n int) string { return "bob ALL = /bin/" + strings.Repeat("x", n) + "\n" },
		"long args":       func(n int) string { return "bob ALL = /bin/ls " + strings.Repeat("a ", n/2) + "\n" },
		"long comment":    func(n int) string { return "# " + strings.Repeat("x", n) + "\n" },
		"long string":     func(n int) string { return "Defaults secure_path=\"" + strings.Repeat("a\\b", n/3) + "\"\n" },
		"long regex":      func(n int) string { return "bob ALL = ^/" + strings.Repeat("x", n) + "$\n" },
		"many commas":     func(n int) string { return "bob ALL = /bin/ls" + strings.Repeat(", /bin/ls", n/9) + "\n" },
		"many lines":      func(n int) string { return strings.Repeat("root ALL = ALL\n", n/15) },
		"continuations":   func(n int) string { return "bob ALL = /bin/ls" + strings.Repeat(" \\\n", n/3) + "\n" },
		"unterminated":    func(n int) string { return "Defaults env_keep=\"" + strings.Repeat("x", n) },
		"many errors":     func(n int) string { return strings.Repeat("= = =\n", n/6) },
		"long alias name": func(n int) string { return "Cmnd_Alias " + strings.Repeat("A", n) + " = /bin/ls\n" },
		"many aliases": func(n int) string {
			var b strings.Builder
			for i := 0; b.Len() < n; i++ {
				fmt.Fprintf(&b, "Cmnd_Alias A%d = A%d\n", i, i+1)
			}
			return b.String()
		},
	}
	measure := func(in string) time.Duration {
		best := time.Duration(1<<63 - 1)
		for i := 0; i < 3; i++ {
			start := time.Now()
			ValidateString(in, Options{Strict: true})
			best = min(best, time.Since(start))
		}
		return best
	}
	const n = 1 << 16
	for name, gen := range gens {
		small, large := measure(gen(n)), measure(gen(4*n))
		if ratio := float64(large) / float64(max(small, time.Millisecond)); ratio > 8 {
			t.Errorf("%s: %v for %d bytes but %v for %d bytes (x%.1f)", name, small, n, large, 4*n, ratio)
		}
	}
}
