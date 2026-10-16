package sudoers

import (
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// TestOracle generates random sudoers files and compares Validate with
// a real visudo(8). It only runs when SUDOERS_VISUDO names the binary:
//
//	SUDOERS_VISUDO=$(which visudo) go test -run Oracle
//
// SUDOERS_ORACLE_N sets the number of files (default 2000) and
// SUDOERS_ORACLE_SEED the random seed.
//
// Constructs whose behaviour changed after sudo 1.9.17p2 (relative
// sudoedit arguments, runcwd/runchroot path messages) are not
// generated, so the test also passes against that release. Two
// differences in reporting are normalized: visudo reports a missing
// include file without a position, and for "#" followed by a digit in
// a Defaults line (or an include path such as ":") it prints
// strerror(errno), whatever errno holds. Regular expression errors are
// compared by position only, since regerror(3) wording varies by libc,
// as are duplicate aliases, whose wording changed in sudo 1.9.16.
// Files that include absolute paths are skipped since visudo would read
// them from the host.
func TestOracle(t *testing.T) {
	visudo := os.Getenv("SUDOERS_VISUDO")
	if visudo == "" {
		t.Skip("SUDOERS_VISUDO not set")
	}
	n := envInt("SUDOERS_ORACLE_N", 2000)
	seed := int64(envInt("SUDOERS_ORACLE_SEED", 1))
	rng := rand.New(rand.NewSource(seed))
	dir := t.TempDir()

	failures := 0
	for i := 0; i < n && failures < 10; i++ {
		content := randomSudoers(rng)
		if absInclude.MatchString(content) {
			continue // visudo would read the host's files
		}
		name := "x" + strconv.Itoa(i)
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		for _, strict := range []bool{false, true} {
			want := errnoMessage.ReplaceAllString(runVisudo(t, visudo, dir, name, strict), "$1: syntax error")
			want = staleIncludeErrno.ReplaceAllString(want, "$1: No such file or directory")
			got := renderGolden(Validate([]byte(content), Options{
				Filename: name, Strict: strict, FS: os.DirFS(dir),
			}))
			got = missingInclude.ReplaceAllString(got, "visudo: $1: No such file or directory")
			got = regexError.ReplaceAllString(got, "$1: <regex error>")
			want = regexError.ReplaceAllString(want, "$1: <regex error>")
			got = duplicateAlias.ReplaceAllString(got, `$1: duplicate alias "$2"`)
			want = duplicateAlias.ReplaceAllString(want, `$1: duplicate alias "$2"`)
			if got != want {
				failures++
				t.Errorf("mismatch (strict=%v) for input:\n%s\n--- got\n%s--- want\n%s",
					strict, content, got, want)
				break
			}
		}
	}
}

var (
	absInclude     = regexp.MustCompile(`(?m)(@include|^#include)(dir)?[ \t]+"?/`)
	missingInclude = regexp.MustCompile(`(?m)^x\d+:\d+:\d+: (.*): No such file or directory$`)
	errnoMessage   = regexp.MustCompile(`(?m)^(x\d+:\d+:\d+): (No such file or directory|Success|Undefined error: 0)$`)
	// regerror(3) wording differs between BSD/macOS and glibc.
	regexError = regexp.MustCompile(`(?m)^(x\d+:\d+:\d+): (` + strings.Join([]string{
		`parentheses not balanced`, `brackets \(\[ \]\) not balanced`,
		`braces not balanced`, `invalid character range`, `invalid character class`,
		`trailing backslash \(\\\)`, `repetition-operator operand invalid`,
		`invalid repetition count\(s\)`, `empty \(sub\)expression`,
		`Unmatched \( or \\\(`, `Unmatched \) or \\\)`, `Unmatched \[.*`,
		`Unmatched \\\{`, `Invalid range end`, `Invalid character class name`,
		`Trailing backslash`, `Invalid preceding regular expression`,
		`Invalid content of \\\{\\\}`, `Invalid regular expression`,
	}, "|") + `)$`)
	// sudo before 1.9.16 words duplicate aliases differently.
	duplicateAlias = regexp.MustCompile(`(?m)^(x\d+:\d+:\d+): (?:duplicate \w+_Alias|Alias) "([^"]*)"(?:, previously defined at .*| already defined)$`)
	// An include path with no non-empty components is never opened, so
	// visudo reports a stale errno.
	staleIncludeErrno = regexp.MustCompile(`(?m)^(visudo: [^\n]*): (Success|Undefined error: 0)$`)
)

func envInt(name string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(name)); err == nil {
		return v
	}
	return def
}

// runVisudo runs "visudo -c[s] -f name" in dir and formats its result
// like scripts/gen-golden.sh.
func runVisudo(t *testing.T, visudo, dir, name string, strict bool) string {
	t.Helper()
	flags := "-c"
	if strict {
		flags = "-cs"
	}
	cmd := exec.Command(visudo, flags, "-f", name)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	var b strings.Builder
	if err == nil {
		b.WriteString("status: valid\n")
	} else {
		if _, ok := err.(*exec.ExitError); !ok {
			t.Fatal(err)
		}
		b.WriteString("status: invalid\n")
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimPrefix(line, "Warning: ")
		if line == name+": parsed OK" {
			continue
		}
		if strings.HasPrefix(line, name+":") || strings.HasPrefix(line, "visudo: ") {
			b.WriteString(line + "\n")
		}
	}
	return b.String()
}

var oracleFragments = []string{
	"root", "bob", "%wheel", "%:admins", "+netgrp", "#1000", "%#100", "ALL", "!",
	"ADMINS", "WEB", "LS", "OP", "FOO", "A", "B",
	"web1", "10.0.0.1", "10.0.0.0/8", "192.168.1.0/255.255.255.0", "::1",
	"fe80::1/64", "1::2::3", "*.example.com",
	"=", "==", ",", ":", "(", ")", "( )", "(:)", "(root)", "(root:wheel)",
	"(:wheel)", "(ALL:ALL)", "(OP)",
	"/bin/ls", "/bin/ls -l", "/usr/bin/", "/bin/echo a\\,b", "/bin/sh \"\"",
	"/usr/bin/kill -9 *", "^/bin/(ls|cat)$", "^/bin/(ls$", "/bin/grep ^x$",
	"/bin/grep ^x", "list", "foo", "\"/bin/ls\"",
	"NOPASSWD:", "PASSWD:", "NOEXEC:", "SETENV:", "LOG_INPUT:", "MAIL:",
	"FOLLOW:", "NOINTERCEPT:",
	"CWD=/tmp", "CWD=*", "CWD=foo", "CHROOT=/srv", "TIMEOUT=1h", "TIMEOUT=5x",
	"NOTBEFORE=20200101000000Z", "NOTAFTER=2020", "ROLE=r", "TYPE=t",
	"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	"sha224:abcd", "sha512:", "\"quoted word\"", "\"\"", "\"%\"", "\"+\"",
	"%", "+", "#", "# comment", "\\", "\\\n", "\"unterminated",
	"Defaults", "Defaults:bob", "Defaults@web1", "Defaults>root", "Defaults!/bin/ls",
	"Defaults!LS", "Defaults:ADMINS",
	"env_reset", "!env_reset", "env_reset=1", "passwd_tries=3", "passwd_tries=x",
	"!passwd_tries", "lecture=always", "lecture=never", "lecture=bad",
	"env_keep+=\"HOME PATH\"", "env_keep-=TZ", "umask=0022", "umask+=1",
	"logfile=/var/log/sudo", "logfile=rel", "secure_path=\"/bin:/usr/bin\"",
	"timestamp_timeout=1.5", "timestamp_timeout=x", "syslog=auth", "syslog=bad",
	"rlimit_core=0", "rlimit_nofile=\"1,2\"", "command_timeout=5m", "bogus",
	"ignore_unknown_defaults",
	"User_Alias", "Host_Alias", "Cmnd_Alias", "Runas_Alias", "Cmd_Alias",
	"@include", "#include",
}

// randomSudoers builds a file mixing plausible entries with random
// token soup.
func randomSudoers(rng *rand.Rand) string {
	pick := func(xs ...string) string { return xs[rng.Intn(len(xs))] }
	var lines []string
	for i, n := 0, 1+rng.Intn(6); i < n; i++ {
		var line string
		switch rng.Intn(6) {
		case 0:
			line = pick("User_Alias", "Host_Alias", "Cmnd_Alias", "Runas_Alias") + " " +
				pick("ADMINS", "WEB", "LS", "OP", "FOO", "A", "B", "ALL") + " = " +
				pick("bob, alice", "web1, 10.0.0.1", "/bin/ls, /bin/cat", "root", "A", "B", "LS, /bin/sh")
		case 1:
			line = pick("Defaults", "Defaults:bob", "Defaults@web1", "Defaults>root", "Defaults!/bin/ls", "Defaults!LS", "Defaults:ADMINS") + " " +
				pick("env_reset", "!lecture", "passwd_tries=3", "env_keep+=\"A B\"", "bogus", "umask=0777", "lecture=once, !syslog")
		case 2:
			line = pick("root", "bob", "%wheel", "ADMINS", "!bob, alice") + " " +
				pick("ALL", "web1", "WEB", "!web1, ALL") + " = " +
				pick("", "(root) ", "(OP) ", "(:wheel) ") +
				pick("", "NOPASSWD: ", "CWD=/ ", "TIMEOUT=1m NOEXEC: ") +
				pick("ALL", "/bin/ls", "LS", "!/bin/su", "/bin/ls, /bin/cat", "/bin/ls : web1 = ALL")
		default:
			var parts []string
			for j, m := 0, 1+rng.Intn(8); j < m; j++ {
				parts = append(parts, oracleFragments[rng.Intn(len(oracleFragments))])
			}
			sep := " "
			if rng.Intn(4) == 0 {
				sep = ""
			}
			line = strings.Join(parts, sep)
		}
		lines = append(lines, line)
	}
	s := strings.Join(lines, "\n")
	if rng.Intn(5) != 0 {
		s += "\n"
	}
	return s
}
