// Command sudoers-validate checks sudoers files like "visudo -c".
//
// Usage:
//
//	sudoers-validate [-s] [-q] [-no-includes] [-hostname name] file...
//	sudoers-validate -version
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
	"runtime/debug"

	sudoers "github.com/DanielRis/go-sudoer-validation"
)

// version is set at link time by release builds
// (-ldflags "-X main.version=v1.2.3").
var version string

func buildVersion() string {
	if version != "" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
		return info.Main.Version // set by "go install ...@v1.2.3"
	}
	return "(devel)"
}

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
	showVersion := flags.Bool("version", false, "print the version and exit")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "usage: sudoers-validate [-s] [-q] [-no-includes] [-hostname name] file...")
		fmt.Fprintln(stderr, "       sudoers-validate -version")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Fprintln(stdout, "sudoers-validate", buildVersion())
		return 0
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
