package sudoers

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// testsudoers writes diagnostics to the same stream as the token trace;
// they are checked by TestGolden, so strip them here.
var traceDiag = regexp.MustCompile(`sudoers:\d+:\d+: [^\n]*\n`)

// TestLexerTrace replays the upstream sudo regression suite: each
// testdata/regress/*.toke.ok holds the token trace that sudo's own
// lexer emits (via "testsudoers -dt") for the matching *.in file,
// including "<*>" markers where the parser reported an error.
func TestLexerTrace(t *testing.T) {
	inputs, err := filepath.Glob("testdata/regress/*.in")
	if err != nil {
		t.Fatal(err)
	}
	if len(inputs) == 0 {
		t.Fatal("no regress inputs found")
	}
	for _, in := range inputs {
		t.Run(filepath.Base(in), func(t *testing.T) {
			content, err := os.ReadFile(in)
			if err != nil {
				t.Fatal(err)
			}
			want, err := os.ReadFile(strings.TrimSuffix(in, ".in") + ".toke.ok")
			if err != nil {
				t.Fatal(err)
			}
			var trace strings.Builder
			// testsudoers runs the parser in strict mode.
			check(content, Options{Filename: filepath.Base(in), Strict: true}, &trace)
			wantTrace := traceDiag.ReplaceAllString(string(want), "")
			if got := trace.String(); got != wantTrace {
				t.Errorf("token trace mismatch\n--- got\n%s\n--- want\n%s", got, wantTrace)
			}
		})
	}
}
