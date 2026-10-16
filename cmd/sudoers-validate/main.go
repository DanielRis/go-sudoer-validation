// Command sudoers-validate checks sudoers files like "visudo -c".
//
// Usage:
//
//	sudoers-validate [-s] [-q] [-no-includes] [-hostname name] file...
//
// A file named "-" is read from standard input. The exit status is 0
// when every file is valid, 1 when any is invalid and 2 on usage errors.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	sudoers "github.com/risticd/go-sudoer-validation"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("sudoers-validate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	strict := flags.Bool("s", false, "strict checking: undefined aliases and alias cycles are errors")
	quiet := flags.Bool("q", false, "quiet: only report errors through the exit status")
	noIncludes := flags.Bool("no-includes", false, "do not read @include and @includedir files")
	hostname := flags.String("hostname", "", "host name substituted for %h in include paths")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "usage: sudoers-validate [-s] [-q] [-no-includes] [-hostname name] file...")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() == 0 {
		flags.Usage()
		return 2
	}

	status := 0
	for _, file := range flags.Args() {
		opts := sudoers.Options{Strict: *strict, Hostname: *hostname}
		var content []byte
		var err error
		if file == "-" {
			opts.Filename = "stdin"
			content, err = io.ReadAll(stdin)
		} else {
			opts.Filename, err = filepath.Abs(file)
			if err == nil {
				content, err = os.ReadFile(opts.Filename)
			}
		}
		if err != nil {
			fmt.Fprintf(stderr, "sudoers-validate: unable to open %s: %v\n", file, err)
			status = 1
			continue
		}
		if !*noIncludes {
			// Include paths are absolute or relative to the file, which
			// Validate resolves against the root of this FS.
			opts.FS = os.DirFS("/")
		}

		res := sudoers.Validate(content, opts)
		if !*quiet {
			for _, d := range res.Diagnostics {
				if d.Severity == sudoers.SeverityWarning {
					fmt.Fprint(stderr, "Warning: ")
				}
				fmt.Fprintln(stderr, d)
			}
		}
		if !res.Valid() {
			status = 1
		} else if !*quiet {
			fmt.Fprintf(stdout, "%s: parsed OK\n", opts.Filename)
		}
	}
	return status
}
