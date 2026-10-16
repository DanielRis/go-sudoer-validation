package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func runCLI(t *testing.T, stdin string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut strings.Builder
	code = run(args, strings.NewReader(stdin), &out, &errOut)
	return code, out.String(), errOut.String()
}

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestValidFile(t *testing.T) {
	f := writeFile(t, t.TempDir(), "sudoers", "root ALL=(ALL) ALL\n")
	code, out, errOut := runCLI(t, "", f)
	if code != 0 || out != f+": parsed OK\n" || errOut != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errOut)
	}
}

func TestInvalidFile(t *testing.T) {
	f := writeFile(t, t.TempDir(), "sudoers", "bob ALL = foo\n")
	code, out, errOut := runCLI(t, "", f)
	want := f + ":1:11: expected a fully-qualified path name\n"
	if code != 1 || out != "" || errOut != want {
		t.Fatalf("code=%d out=%q err=%q", code, out, errOut)
	}
}

func TestQuietAndWarnings(t *testing.T) {
	f := writeFile(t, t.TempDir(), "sudoers", "Cmnd_Alias C = /bin/ls\nroot ALL = ALL\n")
	code, out, errOut := runCLI(t, "", f)
	if code != 0 || out != f+": parsed OK\n" || errOut != "Warning: "+f+":1:12: unused Cmnd_Alias \"C\"\n" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errOut)
	}
	code, out, errOut = runCLI(t, "", "-q", f)
	if code != 0 || out != "" || errOut != "" {
		t.Fatalf("quiet: code=%d out=%q err=%q", code, out, errOut)
	}
}

func TestStrict(t *testing.T) {
	f := writeFile(t, t.TempDir(), "sudoers", "root ALL = FOO\n")
	if code, _, _ := runCLI(t, "", f); code != 0 {
		t.Fatalf("non-strict code=%d", code)
	}
	code, _, errOut := runCLI(t, "", "-s", f)
	if code != 1 || !strings.Contains(errOut, `Cmnd_Alias "FOO" referenced but not defined`) {
		t.Fatalf("strict: code=%d err=%q", code, errOut)
	}
}

func TestStdin(t *testing.T) {
	code, out, _ := runCLI(t, "root ALL=ALL\n", "-")
	if code != 0 || out != "stdin: parsed OK\n" {
		t.Fatalf("code=%d out=%q", code, out)
	}
}

func TestFollowsIncludes(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "sudoers.d/bad", "bob ALL = foo\n")
	f := writeFile(t, dir, "sudoers", "@includedir "+filepath.Join(dir, "sudoers.d")+"\n")
	code, _, errOut := runCLI(t, "", f)
	want := filepath.Join(dir, "sudoers.d/bad") + ":1:11: expected a fully-qualified path name\n"
	if code != 1 || errOut != want {
		t.Fatalf("code=%d err=%q", code, errOut)
	}
	if code, _, _ := runCLI(t, "", "-no-includes", f); code != 0 {
		t.Fatalf("-no-includes: code=%d", code)
	}
}

func TestMissingFile(t *testing.T) {
	code, _, errOut := runCLI(t, "", filepath.Join(t.TempDir(), "nope"))
	if code != 1 || !strings.Contains(errOut, "unable to open") {
		t.Fatalf("code=%d err=%q", code, errOut)
	}
}

func TestUsage(t *testing.T) {
	if code, _, _ := runCLI(t, ""); code != 2 {
		t.Fatalf("no args: code=%d", code)
	}
}
