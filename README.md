# go-sudoer-validation

[![CI](https://github.com/DanielRis/go-sudoer-validation/actions/workflows/ci.yml/badge.svg)](https://github.com/DanielRis/go-sudoer-validation/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/DanielRis/go-sudoer-validation.svg)](https://pkg.go.dev/github.com/DanielRis/go-sudoer-validation)

A pure Go validator for [sudoers(5)](https://www.sudo.ws/docs/man/sudoers.man/)
files that applies the same checks as `visudo -c`.

It is a port of sudo's own parser rather than an approximation of it:

| sudo source (`plugins/sudoers/`) | Go |
| --- | --- |
| `toke.l` (flex lexer), `toke_util.c` | `lexer.go` — emulates flex: longest match, rule order, start conditions, `^` anchors, `yyless` |
| `gram.y` (bison grammar) | `parser.go` — recursive descent that reads lookahead where bison's LALR tables do, with bison's error recovery |
| `defaults.c`, `def_data.in` | `defaults.go`, generated `defaults_table.go` |
| `check_aliases.c`, `alias.c`, `visudo.c` | `checks.go` |
| `lib/util/regex.c` | `regex.go` (strict mode only) |

Because of that, a file this package accepts is one `visudo -c` accepts, and
diagnostics have the same messages and the same `file:line:column` positions.

## Library

Requires Go 1.25 or later. CI tests the minimum version and the latest
stable release.

```go
import sudoers "github.com/DanielRis/go-sudoer-validation"

res := sudoers.Validate(content, sudoers.Options{
	Filename: "/etc/sudoers", // used in diagnostics and to resolve relative includes
	Strict:   false,          // visudo -s
	FS:       os.DirFS("/"),  // optional: follow @include / @includedir
})
if !res.Valid() {
	for _, d := range res.Errors() {
		fmt.Println(d) // /etc/sudoers:4:11: expected a fully-qualified path name
	}
}
```

`Result.Diagnostics` holds errors and warnings in the order visudo prints
them. Each `Diagnostic` has a `Severity`, `File`, `Line`, `Column` and
`Message`.

### Validating content in a server

The validator never reads files unless you pass `FS`, so content received
over the network can be checked as a string, a byte slice or a reader:

```go
res := sudoers.ValidateString(content, sudoers.Options{Filename: "upload"})
res, err := sudoers.ValidateReader(http.MaxBytesReader(w, r.Body, 1<<20), opts)
json.NewEncoder(w).Encode(res)
// {"valid":false,"diagnostics":[{"severity":"error","file":"upload","line":2,
//   "column":11,"message":"expected a fully-qualified path name"}]}
```

* All functions are safe to call concurrently. Each call keeps its own
  state, and the test suite runs under `-race`.
* Validation time grows linearly with input size (about 0.5 s per MB in the
  worst case). `TestHostileInputIsLinear` guards against regressions.
  You should still cap the request size, for example with
  `http.MaxBytesReader`.
* An upload that contains a main file plus `sudoers.d` files can be checked as
  one policy by putting them in an in-memory `fs.FS` (for example
  `fstest.MapFS`, or a filesystem built from a zip or tar upload) and setting
  `Filename` to the main file's path, such as `/etc/sudoers`.

What is checked, as in `visudo -c`:

* **Syntax**: every lexer and grammar error, including value checks done while
  parsing (`CWD`/`CHROOT` paths, `TIMEOUT`, `NOTBEFORE`/`NOTAFTER`, digests,
  reserved words used as alias names, duplicate aliases, `sudoedit` arguments).
* **Defaults**: unknown names, missing or unexpected values, invalid operators,
  and type checks for integers, modes, syslog facilities and priorities,
  tuples, timeouts, time specs, rlimits and paths.
* **Aliases**: undefined aliases and alias cycles (warnings, or errors with
  `Strict`), and unused aliases (warnings).

Like visudo, Defaults and alias checks only run when the file parses without
errors.

## Command

Prebuilt binaries for Linux, macOS, FreeBSD and Windows are attached to each
[GitHub release](https://github.com/DanielRis/go-sudoer-validation/releases),
or install from source:

```
go install github.com/DanielRis/go-sudoer-validation/cmd/sudoers-validate@latest

sudoers-validate [-s] [-q] [-no-includes] [-hostname name] file...
sudoers-validate -version
```

It prints diagnostics to stderr and `file: parsed OK` to stdout. The exit
status is 0 when every file is valid, 1 when any is invalid, and 2 on usage
errors. Use `-` to read standard input. Includes are followed by default.

## Tests

Development was test-first. `go test ./...` runs the deterministic tests.
The suite has these layers:

* `TestLexerTrace` replays sudo's own regression suite
  (`testdata/regress/*.in`). Each `*.toke.ok` file is the token trace that
  sudo's lexer prints, and the Go lexer has to produce it exactly.
* `TestGolden` compares results and diagnostics, in default and strict mode,
  with output recorded from a real `visudo`. The corpus is
  `testdata/cases/*.sudoers` plus the regress inputs. To regenerate it, run
  `scripts/gen-golden.sh`. The version used is in `testdata/VISUDO_VERSION`.
* `TestOracle` generates random sudoers files and compares each one with a
  live `visudo`:
  `SUDOERS_VISUDO=$(which visudo) SUDOERS_ORACLE_N=10000 go test -run Oracle`
* `FuzzValidate` checks that no input can crash the validator:
  `go test -run '^$' -fuzz FuzzValidate`
* `TestHostileInputIsLinear` checks that validation time grows linearly with
  input size. It depends on machine speed, so it only runs with
  `SUDOERS_TIMING_TESTS=1`.

CI (`.github/workflows/ci.yml`) runs lint, `go vet`, `govulncheck`, the tests
under `-race` on Linux and macOS, the oracle test against Ubuntu's `visudo`, the
timing test and a short fuzzing session.

## Releasing

Releases are cut by pushing a [semantic version](https://semver.org) tag from
`main`:

```
git switch main && git pull
git tag -a v0.1.0 -m "v0.1.0"
git push origin v0.1.0
```

The `Release` workflow then:

1. runs the full CI suite against the tagged commit;
2. checks that the tag is on `main`;
3. builds the `sudoers-validate` binaries with
   [GoReleaser](https://goreleaser.com) (`.goreleaser.yaml`) and publishes them
   on a GitHub release with a changelog and `checksums.txt`;
4. adds signed [build provenance](https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations)
   for every archive. You can verify it with
   `gh attestation verify <archive> --repo DanielRis/go-sudoer-validation`;
5. asks the Go module proxy to fetch the new version so it appears on
   pkg.go.dev.

Tags with a suffix, such as `v0.2.0-rc.1`, are published as pre-releases.
Follow semantic versioning for the library API: breaking changes need a new
major version (and from v2 on, a `/v2` module path). To try the release build
locally, run `goreleaser release --snapshot --clean`.

## Differences from visudo

The parser follows sudo's development branch (1.9.18). The goldens were
recorded with visudo 1.9.17p2, which differs from the development branch in
two places, both covered by `TestUpstreamMasterBehaviour`:

* `sudoedit` arguments must be absolute paths (`invalid sudoedit file name`).
* Messages for `runcwd`/`runchroot` paths say `must begin with a '/' or '~', or be '*'`.

Checks that depend on the host are not performed:

* File ownership and permissions of the sudoers file and its includes.
* `Defaults sudoers_locale`: visudo fails when the locale isn't installed on the machine.
* Defaults callbacks only run for Defaults bound to the current host or user.
  As a result, the `runchroot` deprecation warning is only reported for
  unbound `Defaults`.

A few reports differ on purpose:

* With `Defaults ignore_unknown_defaults`, visudo still rejects unknown entries
  but prints nothing. This package reports `unknown defaults entry`.
* A missing include file is reported at the include line, not as
  `visudo: path: No such file or directory`.
* If `#` is followed by a digit inside a Defaults line, sudo prints
  `strerror(errno)`, which is whatever errno happens to hold. This package
  reports `syntax error`.
* Strict mode checks command regular expressions with Go's POSIX syntax
  parser, using BSD `regerror` wording. glibc words some errors differently.
* `PATH_MAX` is taken to be 4096, as on Linux.

## License

The files in `testdata/regress/` and `internal/gen/def_data.in` come from
[sudo](https://www.sudo.ws/) and are covered by its ISC-style license
(`testdata/regress/LICENSE.md`).
