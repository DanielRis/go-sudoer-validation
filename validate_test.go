package sudoers

import (
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
)

func diagStrings(ds []Diagnostic) []string {
	out := []string{}
	for _, d := range ds {
		out = append(out, d.String())
	}
	return out
}

func TestValidateEmpty(t *testing.T) {
	res := Validate(nil, Options{})
	if !res.Valid() || len(res.Diagnostics) != 0 {
		t.Fatalf("empty file: got %v", diagStrings(res.Diagnostics))
	}
}

func TestDefaultFilename(t *testing.T) {
	res := Validate([]byte("bob ALL = foo\n"), Options{})
	want := []string{"sudoers:1:11: expected a fully-qualified path name"}
	if got := diagStrings(res.Errors()); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestDiagnosticString(t *testing.T) {
	d := Diagnostic{File: "f", Line: 2, Column: 3, Message: "m"}
	if got := d.String(); got != "f:2:3: m" {
		t.Errorf("got %q", got)
	}
	d = Diagnostic{File: "f", Column: 15, Message: "m"}
	if got := d.String(); got != "f:0:15: m" {
		t.Errorf("got %q", got)
	}
	d = Diagnostic{File: "f", Message: "m"}
	if got := d.String(); got != "f: m" {
		t.Errorf("got %q", got)
	}
}

func TestSeverities(t *testing.T) {
	src := []byte("Cmnd_Alias C = /bin/ls\nroot ALL = (ALL) FOO\n")

	res := Validate(src, Options{Filename: "x"})
	if !res.Valid() {
		t.Fatalf("non-strict should be valid: %v", diagStrings(res.Errors()))
	}
	wantWarn := []string{
		`x:2:21: Cmnd_Alias "FOO" referenced but not defined`,
		`x:1:12: unused Cmnd_Alias "C"`,
	}
	if got := diagStrings(res.Warnings()); !reflect.DeepEqual(got, wantWarn) {
		t.Errorf("warnings: got %q, want %q", got, wantWarn)
	}

	res = Validate(src, Options{Filename: "x", Strict: true})
	if res.Valid() {
		t.Fatal("strict should be invalid")
	}
	wantErr := []string{`x:2:21: Cmnd_Alias "FOO" referenced but not defined`}
	if got := diagStrings(res.Errors()); !reflect.DeepEqual(got, wantErr) {
		t.Errorf("errors: got %q, want %q", got, wantErr)
	}
	wantWarn = []string{`x:1:12: unused Cmnd_Alias "C"`}
	if got := diagStrings(res.Warnings()); !reflect.DeepEqual(got, wantWarn) {
		t.Errorf("warnings: got %q, want %q", got, wantWarn)
	}
}

// Behaviour introduced after sudo 1.9.17p2 (the golden files' visudo).
func TestUpstreamMasterBehaviour(t *testing.T) {
	tests := []struct {
		src  string
		want []string
	}{
		{"bob ALL = sudoedit /etc/hosts, sudoedit /etc/*.conf\n", nil},
		{"bob ALL = sudoedit foo\n", []string{"x:1:20: invalid sudoedit file name"}},
		{"bob ALL = sudoedit /a b\n", []string{"x:1:23: invalid sudoedit file name"}},
		{"Defaults runcwd=foo\n", []string{`x:1:17: values for "runcwd" must begin with a '/' or '~', or be '*'`}},
	}
	for _, tt := range tests {
		res := Validate([]byte(tt.src), Options{Filename: "x"})
		got := diagStrings(res.Errors())
		if len(tt.want) == 0 && len(got) == 0 {
			continue
		}
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%q: got %q, want %q", tt.src, got, tt.want)
		}
	}
}

func TestIgnoreUnknownDefaultsStillInvalid(t *testing.T) {
	// visudo rejects this silently; we still explain why.
	res := Validate([]byte("Defaults ignore_unknown_defaults\nDefaults bogus\n"), Options{Filename: "x"})
	want := []string{`x:2:15: unknown defaults entry "bogus"`}
	if got := diagStrings(res.Errors()); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestEmbeddedNULTruncatesLine(t *testing.T) {
	// sudo's input routine truncates a line at an embedded NUL.
	res := Validate([]byte("root ALL = ALL\x00 garbage here\n"), Options{})
	if !res.Valid() {
		t.Fatalf("got %v", diagStrings(res.Diagnostics))
	}
}

func TestStrictRegex(t *testing.T) {
	src := []byte("root ALL = ^/bin/(ls$\n")
	if res := Validate(src, Options{}); !res.Valid() {
		t.Fatalf("non-strict: got %v", diagStrings(res.Diagnostics))
	}
	res := Validate(src, Options{Filename: "x", Strict: true})
	errs := res.Errors()
	if len(errs) != 1 || errs[0].Line != 1 || errs[0].Column != 12 {
		t.Fatalf("strict: got %v", diagStrings(errs))
	}
}

func TestIncludesNotFollowedWithoutFS(t *testing.T) {
	src := "@include /etc/sudoers.local\n@includedir /etc/sudoers.d\n" +
		"#include /etc/x\n#includedir /etc/y\n@include \"/etc/with space\"\nroot ALL=ALL\n"
	if res := Validate([]byte(src), Options{}); len(res.Diagnostics) != 0 {
		t.Fatalf("got %v", diagStrings(res.Diagnostics))
	}
}

func TestIncludeSyntax(t *testing.T) {
	res := Validate([]byte("@include\n"), Options{Filename: "x"})
	if res.Valid() {
		t.Fatal("@include without a path should be invalid")
	}
}

func TestIncludesWithFS(t *testing.T) {
	fsys := fstest.MapFS{
		"etc/sudoers.local":       {Data: []byte("Cmnd_Alias LS = /bin/ls\n")},
		"etc/sudoers.d/10-admins": {Data: []byte("bob ALL = LS\n")},
		"etc/sudoers.d/20-bad":    {Data: []byte("\nalice ALL = foo\n")},
		"etc/sudoers.d/skip.conf": {Data: []byte("garbage\n")},
		"etc/sudoers.d/skip~":     {Data: []byte("garbage\n")},
		"etc/host-web1":           {Data: []byte("carol ALL = ALL\n")},
	}
	src := "@include sudoers.local\n@includedir /etc/sudoers.d\n" +
		"@includedir /etc/missing.d\n@include /etc/host-%h\n"
	res := Validate([]byte(src), Options{Filename: "/etc/sudoers", FS: fsys, Hostname: "web1"})
	want := []string{"/etc/sudoers.d/20-bad:2:13: expected a fully-qualified path name"}
	if got := diagStrings(res.Diagnostics); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestIncludeMissingFile(t *testing.T) {
	res := Validate([]byte("@include /etc/nope\n"), Options{Filename: "/etc/sudoers", FS: fstest.MapFS{}})
	errs := res.Errors()
	if len(errs) != 1 || errs[0].File != "/etc/sudoers" || errs[0].Line != 1 ||
		!strings.Contains(errs[0].Message, "/etc/nope") {
		t.Fatalf("got %v", diagStrings(errs))
	}
}

func TestIncludeCycle(t *testing.T) {
	fsys := fstest.MapFS{"etc/a": {Data: []byte("@include /etc/a\n")}}
	res := Validate([]byte("@include /etc/a\n"), Options{Filename: "/etc/sudoers", FS: fsys})
	if res.Valid() {
		t.Fatal("recursive include should be invalid")
	}
}

func TestAliasesAcrossIncludes(t *testing.T) {
	fsys := fstest.MapFS{
		"etc/sudoers.d/a": {Data: []byte("Cmnd_Alias LS = /bin/ls\n")},
	}
	res := Validate([]byte("@includedir /etc/sudoers.d\nbob ALL = LS\n"),
		Options{Filename: "/etc/sudoers", FS: fsys, Strict: true})
	if len(res.Diagnostics) != 0 {
		t.Fatalf("got %v", diagStrings(res.Diagnostics))
	}
}
