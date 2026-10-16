// Package sudoers validates sudoers(5) policy files the way visudo(8)
// does, in pure Go.
//
// The lexer, grammar and post-parse checks are ported from the sudo
// sources (plugins/sudoers/toke.l, gram.y, defaults.c, check_aliases.c
// and visudo.c), so a file that Validate accepts is one that
// "visudo -c" accepts, and diagnostics carry the same messages and
// file:line:column positions.
package sudoers

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
)

// Severity classifies a Diagnostic.
type Severity int

const (
	// SeverityError makes the file invalid; visudo would refuse it.
	SeverityError Severity = iota
	// SeverityWarning is reported by visudo but does not make the file
	// invalid (for example an unused alias).
	SeverityWarning
)

func (s Severity) String() string {
	if s == SeverityWarning {
		return "warning"
	}
	return "error"
}

// MarshalText encodes the severity as "error" or "warning".
func (s Severity) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

// UnmarshalText decodes "error" or "warning".
func (s *Severity) UnmarshalText(text []byte) error {
	switch string(text) {
	case "error":
		*s = SeverityError
	case "warning":
		*s = SeverityWarning
	default:
		return fmt.Errorf("sudoers: unknown severity %q", text)
	}
	return nil
}

// Diagnostic is a single problem found in a sudoers file.
type Diagnostic struct {
	Severity Severity `json:"severity"`
	File     string   `json:"file"`
	// Line and Column are 1-based, or 0 when the problem has no
	// position. Like sudo, a few errors on a final line without a
	// trailing newline are reported on line 0 with a column.
	Line    int    `json:"line"`
	Column  int    `json:"column"`
	Message string `json:"message"`
}

// String formats the diagnostic like visudo: "file:line:column: message".
func (d Diagnostic) String() string {
	if d.Line > 0 || d.Column > 0 {
		return fmt.Sprintf("%s:%d:%d: %s", d.File, d.Line, d.Column, d.Message)
	}
	return fmt.Sprintf("%s: %s", d.File, d.Message)
}

// Options controls validation.
type Options struct {
	// Filename is used in diagnostics. Defaults to "sudoers".
	Filename string

	// Strict enables visudo's strict mode (-s): undefined aliases and
	// alias cycles become errors, regular expressions are compiled, and
	// sudoedit may not be given with a path.
	Strict bool

	// FS, when set, is used to read @include and @includedir targets,
	// so that aliases and errors across included files are checked as
	// visudo does. As in sudo, a relative include path is relative to
	// the directory of the including file, and "%h" is replaced by
	// Hostname. The resulting path is looked up in FS with any leading
	// "/" removed, so os.DirFS("/") with an absolute Filename reads the
	// host's files. When FS is nil, include directives are syntax-checked
	// but the referenced files are not read.
	FS fs.FS

	// Hostname replaces "%h" in include paths. Defaults to "localhost".
	Hostname string
}

// Result holds the outcome of a validation.
type Result struct {
	// Diagnostics lists errors and warnings in the order visudo
	// reports them.
	Diagnostics []Diagnostic `json:"diagnostics"`
}

// MarshalJSON encodes the result as
// {"valid": bool, "diagnostics": [...]}, ready to return from an API.
func (r *Result) MarshalJSON() ([]byte, error) {
	diags := r.Diagnostics
	if diags == nil {
		diags = []Diagnostic{}
	}
	return json.Marshal(struct {
		Valid       bool         `json:"valid"`
		Diagnostics []Diagnostic `json:"diagnostics"`
	}{r.Valid(), diags})
}

// Valid reports whether the file has no errors.
func (r *Result) Valid() bool {
	return len(r.Errors()) == 0
}

// Errors returns the error diagnostics.
func (r *Result) Errors() []Diagnostic {
	return r.filter(SeverityError)
}

// Warnings returns the warning diagnostics.
func (r *Result) Warnings() []Diagnostic {
	return r.filter(SeverityWarning)
}

func (r *Result) filter(s Severity) []Diagnostic {
	var out []Diagnostic
	for _, d := range r.Diagnostics {
		if d.Severity == s {
			out = append(out, d)
		}
	}
	return out
}

// Validate checks the content of a sudoers file. It is safe for
// concurrent use and does not touch the file system unless opts.FS is
// set.
func Validate(content []byte, opts Options) *Result {
	return check(content, opts, nil)
}

// ValidateString checks sudoers content held in a string.
func ValidateString(content string, opts Options) *Result {
	return Validate([]byte(content), opts)
}

// ValidateReader reads r to the end and checks its content. When r is
// untrusted, such as an HTTP request body, limit its size first (for
// example with http.MaxBytesReader).
func ValidateReader(r io.Reader, opts Options) (*Result, error) {
	content, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return Validate(content, opts), nil
}

// check validates content, writing a sudo-style lexer trace to trace
// when it is non-nil.
func check(content []byte, opts Options, trace io.Writer) *Result {
	if opts.Filename == "" {
		opts.Filename = "sudoers"
	}
	p := newParser(content, opts, trace)
	p.parse()
	if !p.parseError {
		p.postParseChecks()
	}
	res := &Result{Diagnostics: p.diags}
	if p.parseError && res.Valid() {
		// sudo can fail a parse without printing anything (for example
		// sudoerserror(NULL)); never report such a file as valid.
		res.Diagnostics = append(res.Diagnostics, Diagnostic{
			Severity: SeverityError, File: opts.Filename, Message: "failed to parse file",
		})
	}
	return res
}
