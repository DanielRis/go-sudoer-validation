package sudoers

import (
	"bytes"
	"io"
	"regexp"
	"regexp/syntax"
	"strings"
	"unicode"
	"unicode/utf8"
)

// The lexer is a port of sudo's plugins/sudoers/toke.l. It emulates the
// flex scanner that sudo generates from it: at each position the
// longest match among the rules active in the current start condition
// wins, ties go to the rule listed first, and "^" rules only match at
// the beginning of a line. Token positions (toke_start/toke_end) and
// line numbers are tracked exactly as sudo does, so diagnostics carry
// the same line:column values as visudo.

type tokKind int

const (
	tEOF tokKind = iota
	tCOMMAND
	tALIAS
	tDEFVAR
	tNTWKADDR
	tNETGROUP
	tUSERGROUP
	tWORD
	tDIGEST
	tINCLUDE
	tINCLUDEDIR
	tDEFAULTS
	tDEFAULTS_HOST
	tDEFAULTS_USER
	tDEFAULTS_RUNAS
	tDEFAULTS_CMND
	tNOPASSWD
	tPASSWD
	tNOEXEC
	tEXEC
	tSETENV
	tNOSETENV
	tLOG_INPUT
	tNOLOG_INPUT
	tLOG_OUTPUT
	tNOLOG_OUTPUT
	tMAIL
	tNOMAIL
	tFOLLOWLNK
	tNOFOLLOWLNK
	tINTERCEPT
	tNOINTERCEPT
	tALL
	tHOSTALIAS
	tCMNDALIAS
	tUSERALIAS
	tRUNASALIAS
	tColon
	tEquals
	tComma
	tBang
	tPlus
	tMinus
	tLParen
	tRParen
	tNewline
	tERROR
	tNOMATCH
	tCHROOT
	tCWD
	tTYPE
	tROLE
	tAPPARMOR_PROFILE
	tPRIVS
	tLIMITPRIVS
	tCMND_TIMEOUT
	tNOTBEFORE
	tNOTAFTER
	tSHA224
	tSHA256
	tSHA384
	tSHA512
)

// token is a lexed token and its semantic value (sudoerslval).
type token struct {
	kind tokKind
	str  string // WORD, ALIAS, DEFVAR, ... value
	cmnd string // COMMAND path
	args string // COMMAND arguments
}

// Start conditions.
type startCond int

const (
	scINITIAL startCond = iota
	scGOTDEFS
	scGOTCMND
	scGOTEDIT
	scGOTREGEX
	scSTARTDEFS
	scINDEFS
	scINSTR
	scWANTDIGEST
	scGOTINC
	scEXPECTPATH
	numStartConds
)

// exclusive start conditions (%x) only activate rules that name them.
var exclusive = [numStartConds]bool{
	scGOTCMND: true, scGOTEDIT: true, scGOTREGEX: true, scSTARTDEFS: true,
	scINDEFS: true, scINSTR: true, scGOTINC: true,
}

// buffer is one input file (sudo pushes a new one for each include).
type buffer struct {
	file      string   // name used in diagnostics (sudoers)
	data      []byte   // input not yet read into line
	line      []byte   // current line, always ending in '\n'
	pos       int      // scan position in line
	tokeStart int      // sudolinebuf.toke_start
	tokeEnd   int      // sudolinebuf.toke_end
	lineno    int      // sudolineno
	atBOL     bool     // flex yy_at_bol
	eof       bool     // feof(sudoersin): last line had no newline
	more      []string // remaining @includedir files
}

type lexer struct {
	buf   *buffer
	stack []*buffer // include stack

	state     startCond
	prevState startCond
	continued bool
	sawspace  bool
	digestLen int // digest length in bytes for WANTDIGEST
	errstr    string

	lval    token
	strNil  bool   // sudoerslval.string == NULL inside a quoted string
	strBuf  []byte // quoted string being built
	argsBuf []byte // command arguments being built
	argsSet bool   // sudoerslval.command.args != NULL

	strict bool
	trace  io.Writer

	// sudoersError reports an error raised from inside the lexer
	// (sudoerserror called by fill_cmnd).
	sudoersError func(msg string)
	// openNext opens the next file of an @includedir; nil if none can
	// be opened.
	openNext func(path string) *buffer
}

func newBuffer(file string, data []byte) *buffer {
	return &buffer{file: file, data: data, lineno: 1, atBOL: true}
}

func (l *lexer) lextrace(msg string) {
	if l.trace != nil {
		io.WriteString(l.trace, msg)
	}
}

// begin is flex's BEGIN.
func (l *lexer) begin(sc startCond) { l.state = sc }

// less is sudoersless(n): push back all but the first n matched bytes.
func (l *lexer) less(matchStart, n int) {
	l.buf.tokeEnd = l.buf.tokeStart + n
	l.buf.pos = matchStart + n
}

// readLine is sudoers_input: it loads the next line of the current
// buffer, truncating it at an embedded NUL and adding a missing
// trailing newline. It reports false at end of input.
func (b *buffer) readLine() bool {
	if len(b.data) == 0 {
		return false
	}
	var line []byte
	if i := bytes.IndexByte(b.data, '\n'); i >= 0 {
		line, b.data = b.data[:i+1], b.data[i+1:]
	} else {
		line, b.data = b.data, nil
		b.eof = true
	}
	if i := bytes.IndexByte(line, 0); i >= 0 {
		line = line[:i]
		line = append(line[:i:i], '\n')
	} else if line[len(line)-1] != '\n' {
		line = append(line[:len(line):len(line)], '\n')
	}
	b.line = line
	b.pos = 0
	b.tokeStart, b.tokeEnd = 0, 0
	return true
}

// next returns the next token (sudoerslex).
func (l *lexer) next() token {
	for {
		b := l.buf
		if b.pos >= len(b.line) {
			if !b.readLine() {
				if !l.popInclude() {
					return token{kind: tEOF}
				}
				continue
			}
		}

		rest := b.line[b.pos:]
		best, bestLen := -1, 0
		for _, i := range candidates[l.state][boolIndex(b.atBOL)][rest[0]] {
			loc := rules[i].re.FindIndex(rest)
			if loc != nil && loc[1] > bestLen {
				best, bestLen = i, loc[1]
			}
		}

		matchStart := b.pos
		text := string(rest[:bestLen])
		b.pos += bestLen

		// The line continuation rule inside a string also consumes
		// leading blanks on the next line, which makes flex refill its
		// buffer mid-match (resetting toke_start/toke_end).
		if rules[best].crossLine && b.pos == len(b.line) && b.readLine() {
			n := 0
			for n < len(b.line) && (b.line[n] == ' ' || b.line[n] == '\t') {
				n++
			}
			text += string(b.line[:n])
			b.pos = n
			matchStart = -1
		}

		// YY_RULE_SETUP and YY_USER_ACTION.
		b.atBOL = text[len(text)-1] == '\n'
		b.tokeStart = b.tokeEnd
		b.tokeEnd += len(text)

		if tok, ok := rules[best].action(l, text, matchStart); ok {
			return tok
		}
	}
}

// fill copies a token string, collapsing backslash escapes.
func (l *lexer) fill(s string) {
	l.lval.str = copyString(s)
}

// appendStr appends to the string being built inside double quotes.
func (l *lexer) appendStr(s string) {
	l.strBuf = append(l.strBuf, copyString(s)...)
}

// copyString collapses escaped characters, including \xHH escapes.
func copyString(src string) string {
	var b strings.Builder
	for i := 0; i < len(src); i++ {
		ch := src[i]
		if ch == '\\' && i+1 < len(src) {
			if src[i+1] == 'x' && i+4 <= len(src) {
				if h, ok := hexchar(src[i+2 : i+4]); ok {
					b.WriteByte(h)
					i += 3
					continue
				}
			}
			i++
			ch = src[i]
		}
		b.WriteByte(ch)
	}
	return b.String()
}

func hexchar(s string) (byte, bool) {
	var v byte
	for i := 0; i < 2; i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			c -= '0'
		case c >= 'a' && c <= 'f':
			c -= 'a' - 10
		case c >= 'A' && c <= 'F':
			c -= 'A' - 10
		default:
			return 0, false
		}
		v = v<<4 | c
	}
	return v, true
}

func isSpecial(c byte) bool {
	return c == ',' || c == ':' || c == '=' || c == ' ' || c == '\t' || c == '#'
}

// fillCmnd starts a new command, collapsing escaped sudoers-special
// characters in its path.
func (l *lexer) fillCmnd(s string) {
	l.argsSet = false
	l.argsBuf = l.argsBuf[:0]
	if s[0] == '^' {
		l.lval.cmnd = s
		return
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i != len(s)-1 && isSpecial(s[i+1]) {
			i++
		}
		b.WriteByte(s[i])
	}
	l.lval.cmnd = b.String()

	// Check for sudoedit specified as a fully-qualified path.
	if i := strings.LastIndexByte(l.lval.cmnd, '/'); i >= 0 && l.lval.cmnd[i:] == "/sudoedit" {
		if l.strict {
			l.sudoersError("sudoedit should not be specified with a path")
		}
		l.lval.cmnd = "sudoedit"
	}
}

// fillArgs appends a command line argument.
func (l *lexer) fillArgs(s string, addspace bool) {
	if !l.argsSet {
		l.argsBuf = append(l.argsBuf[:0], s...)
		l.argsSet = true
		return
	}
	if addspace {
		l.argsBuf = append(l.argsBuf, ' ')
	}
	l.argsBuf = append(l.argsBuf, s...)
}

// ipv6Valid rejects addresses with more than one "::".
func ipv6Valid(s string) bool {
	nmatch := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ':' && i+1 < len(s) && s[i+1] == ':' {
			nmatch++
			if nmatch > 1 {
				break
			}
		}
		if s[i] == '/' {
			nmatch = 0
		}
	}
	return nmatch <= 1
}

// checkEditArg is CHECK_EDIT_ARG: sudoedit arguments must be absolute.
func (l *lexer) checkEditArg(text string) (token, bool) {
	if l.state == scGOTEDIT && text[0] != '/' && (!l.argsSet || l.sawspace) {
		l.errstr = "invalid sudoedit file name"
		l.lextrace("ERROR ")
		return token{kind: tERROR}, true
	}
	return token{}, false
}

func (l *lexer) lineContinuationError() (token, bool) {
	l.errstr = "invalid line continuation"
	l.lextrace("ERROR ")
	return token{kind: tERROR}, true
}

func (l *lexer) ret(kind tokKind, trace string) (token, bool) {
	l.lextrace(trace)
	return l.tok(kind), true
}

// tok returns a token carrying the current semantic value.
func (l *lexer) tok(kind tokKind) token {
	t := l.lval
	t.kind = kind
	if kind == tCOMMAND {
		t.args = string(l.argsBuf)
	}
	return t
}

func digestLength(kind tokKind) int {
	switch kind {
	case tSHA224:
		return 28
	case tSHA256:
		return 32
	case tSHA384:
		return 48
	default:
		return 64
	}
}

// lexRule is one flex rule.
type lexRule struct {
	conds     []startCond // nil: all inclusive start conditions
	star      bool        // <*>
	bol       bool        // pattern anchored with ^
	crossLine bool
	re        *regexp.Regexp
	first     [256]bool // bytes a match can start with
	nullable  bool      // pattern can match the empty string
	action    func(l *lexer, text string, matchStart int) (token, bool)
}

func (r *lexRule) active(sc startCond, atBOL bool) bool {
	if r.bol && !atBOL {
		return false
	}
	if r.star {
		return true
	}
	if r.conds == nil {
		return !exclusive[sc]
	}
	for _, c := range r.conds {
		if c == sc {
			return true
		}
	}
	return false
}

// Pattern definitions from toke.l.
var lexDefs = map[string]string{
	"HEX16":    `[0-9A-Fa-f]{1,4}`,
	"OCTET":    `(1?[0-9]{1,2})|(2[0-4][0-9])|(25[0-5])`,
	"IPV4ADDR": `{OCTET}(\.{OCTET}){3}`,
	"IPV6ADDR": `({HEX16}?:){2,7}{HEX16}?|({HEX16}?:){2,6}:{IPV4ADDR}`,
	"WORD":     `([^#>!=:,\(\) \t\r\n\\"]|\\[^\t\n])+`,
	"ID":       `#-?[0-9]+`,
	"PATH":     `/(\\[,:= \t#]|[^,:=\\ \t\r\n#])+`,
	"REGEX":    `\^([^#\r\n\$]|\\[#\$])*\$`,
	"ENVAR":    `([^#!=, \t\r\n\\"]|\\[^\r\n])([^#=, \t\r\n\\"]|\\[^\r\n])*`,
	"DEFVAR":   `[a-z_]+`,
}

var defRef = regexp.MustCompile(`\{([A-Z][A-Z0-9]*)\}`)

// expandDefs substitutes {NAME} definitions, parenthesized as flex does.
func expandDefs(pat string) string {
	for defRef.MatchString(pat) {
		pat = defRef.ReplaceAllStringFunc(pat, func(m string) string {
			return "(" + lexDefs[m[1:len(m)-1]] + ")"
		})
	}
	return pat
}

func rule(conds []startCond, pat string, action func(*lexer, string, int) (token, bool)) lexRule {
	r := lexRule{conds: conds, action: action}
	if strings.HasPrefix(pat, "^") {
		r.bol = true
		pat = pat[1:]
	}
	pat = expandDefs(pat)
	r.re = regexp.MustCompile(`^(?:` + pat + `)`)
	r.re.Longest()
	re, err := syntax.Parse(pat, syntax.Perl)
	if err != nil {
		panic(err)
	}
	r.nullable = firstBytes(re, &r.first)
	return r
}

// firstBytes adds the bytes that a match of re can start with to set
// and reports whether re can match the empty string. It lets the lexer
// skip rules that cannot match at the current position.
func firstBytes(re *syntax.Regexp, set *[256]bool) (nullable bool) {
	addRune := func(lo, hi rune) {
		for c := lo; c <= hi && c < utf8.RuneSelf; c++ {
			set[c] = true
		}
		if hi >= utf8.RuneSelf {
			// Multi-byte runes and invalid bytes (matched as U+FFFD).
			for c := utf8.RuneSelf; c < 256; c++ {
				set[c] = true
			}
		}
	}
	switch re.Op {
	case syntax.OpLiteral:
		if len(re.Rune) == 0 {
			return true
		}
		r := re.Rune[0]
		addRune(r, r)
		if re.Flags&syntax.FoldCase != 0 {
			for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
				addRune(f, f)
			}
		}
		return false
	case syntax.OpCharClass:
		for i := 0; i+1 < len(re.Rune); i += 2 {
			addRune(re.Rune[i], re.Rune[i+1])
		}
		return false
	case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		addRune(0, unicode.MaxRune)
		if re.Op == syntax.OpAnyCharNotNL {
			set['\n'] = false
		}
		return false
	case syntax.OpCapture:
		return firstBytes(re.Sub[0], set)
	case syntax.OpStar, syntax.OpQuest:
		firstBytes(re.Sub[0], set)
		return true
	case syntax.OpPlus:
		return firstBytes(re.Sub[0], set)
	case syntax.OpRepeat:
		return firstBytes(re.Sub[0], set) || re.Min == 0
	case syntax.OpConcat:
		for _, sub := range re.Sub {
			if !firstBytes(sub, set) {
				return false
			}
		}
		return true
	case syntax.OpAlternate:
		for _, sub := range re.Sub {
			if firstBytes(sub, set) {
				nullable = true
			}
		}
		return nullable
	case syntax.OpNoMatch:
		return false
	}
	// Empty-width assertions and OpEmptyMatch.
	return true
}

func starRule(pat string, action func(*lexer, string, int) (token, bool)) lexRule {
	r := rule(nil, pat, action)
	r.star = true
	return r
}

func on(conds ...startCond) []startCond { return conds }

// simple returns an action that returns kind with the given trace.
func simple(kind tokKind, trace string) func(*lexer, string, int) (token, bool) {
	return func(l *lexer, _ string, _ int) (token, bool) {
		return l.ret(kind, trace)
	}
}

func tagRule(name string, kind tokKind, trace string) lexRule {
	return rule(nil, name+`[[:blank:]]*:`, simple(kind, trace))
}

func keywordRule(name string, kind tokKind) lexRule {
	return rule(on(scINITIAL), name, simple(kind, tokName(kind)+" "))
}

func tokName(kind tokKind) string {
	switch kind {
	case tCMND_TIMEOUT:
		return "CMND_TIMEOUT"
	case tNOTBEFORE:
		return "NOTBEFORE"
	case tNOTAFTER:
		return "NOTAFTER"
	case tROLE:
		return "ROLE"
	case tTYPE:
		return "TYPE"
	case tAPPARMOR_PROFILE:
		return "APPARMOR_PROFILE"
	case tPRIVS:
		return "PRIVS"
	case tLIMITPRIVS:
		return "LIMITPRIVS"
	}
	return "?"
}

func ntwkaddr(l *lexer, text string, _ int) (token, bool) {
	l.fill(text)
	return l.ret(tNTWKADDR, "NTWKADDR ")
}

func ntwkaddr6(l *lexer, text string, _ int) (token, bool) {
	if !ipv6Valid(text) {
		l.errstr = "invalid IPv6 address"
		l.lextrace("ERROR ")
		return token{kind: tERROR}, true
	}
	l.fill(text)
	return l.ret(tNTWKADDR, "NTWKADDR ")
}

func digestTok(kind tokKind, trace string) func(*lexer, string, int) (token, bool) {
	return func(l *lexer, _ string, _ int) (token, bool) {
		l.digestLen = digestLength(kind)
		l.begin(scWANTDIGEST)
		return l.ret(kind, trace)
	}
}

func pathlikeExpect(kind tokKind, trace string) func(*lexer, string, int) (token, bool) {
	return func(l *lexer, _ string, _ int) (token, bool) {
		l.lextrace(trace)
		l.prevState = l.state
		l.begin(scEXPECTPATH)
		return l.tok(kind), true
	}
}

func includeTok(kind tokKind, trace string, keep int) func(*lexer, string, int) (token, bool) {
	return func(l *lexer, _ string, matchStart int) (token, bool) {
		if l.continued {
			return l.lineContinuationError()
		}
		if keep > 0 {
			l.less(matchStart, keep)
			l.buf.atBOL = false
		}
		l.begin(scGOTINC)
		return l.ret(kind, trace)
	}
}

func beginStr(l *lexer, _ string, _ int) (token, bool) {
	l.lextrace("BEGINSTR ")
	l.strBuf = l.strBuf[:0]
	l.strNil = true
	if l.state != scEXPECTPATH {
		l.prevState = l.state
	}
	l.begin(scINSTR)
	return token{}, false
}

var rules []lexRule

// candidates[sc][bol][c] lists, in order, the rules that are active in
// start condition sc and can match input starting with byte c.
var candidates [numStartConds][2][256][]int

func boolIndex(b bool) int {
	if b {
		return 1
	}
	return 0
}

func init() {
	initRules()
	for sc := startCond(0); sc < numStartConds; sc++ {
		for bol := 0; bol < 2; bol++ {
			for c := 0; c < 256; c++ {
				for i := range rules {
					r := &rules[i]
					if (r.first[c] || r.nullable) && r.active(sc, bol == 1) {
						candidates[sc][bol][c] = append(candidates[sc][bol][c], i)
					}
				}
			}
		}
	}
}

func initRules() {
	rules = []lexRule{
		rule(on(scGOTDEFS), `[[:blank:]]*,[[:blank:]]*`, simple(tComma, ", ")),
		rule(on(scGOTDEFS), `[[:blank:]]+`, func(l *lexer, _ string, _ int) (token, bool) {
			l.begin(scSTARTDEFS)
			return token{}, false
		}),
		rule(on(scSTARTDEFS), `{DEFVAR}`, func(l *lexer, text string, _ int) (token, bool) {
			l.begin(scINDEFS)
			l.lextrace("DEFVAR ")
			l.fill(text)
			return l.tok(tDEFVAR), true
		}),
		rule(on(scINDEFS), `,`, func(l *lexer, _ string, _ int) (token, bool) {
			l.begin(scSTARTDEFS)
			return l.ret(tComma, ", ")
		}),
		rule(on(scINDEFS), `=`, simple(tEquals, "= ")),
		rule(on(scINDEFS), `\+=`, simple(tPlus, "+= ")),
		rule(on(scINDEFS), `-=`, simple(tMinus, "-= ")),
		rule(on(scINDEFS), `"`, func(l *lexer, _ string, _ int) (token, bool) {
			l.lextrace("BEGINSTR ")
			l.strBuf = l.strBuf[:0]
			l.strNil = true
			l.prevState = l.state
			l.begin(scINSTR)
			return token{}, false
		}),
		rule(on(scINDEFS), `{ENVAR}`, func(l *lexer, text string, _ int) (token, bool) {
			l.lextrace("WORD(2) ")
			l.fill(text)
			return l.tok(tWORD), true
		}),

		// Inside a double-quoted string.
		func() lexRule {
			r := rule(on(scINSTR), `\\[[:blank:]]*\r?\n[[:blank:]]*`, func(l *lexer, _ string, _ int) (token, bool) {
				l.buf.lineno++
				l.continued = true
				return token{}, false
			})
			r.crossLine = true
			return r
		}(),
		rule(on(scINSTR), `"`, func(l *lexer, _ string, _ int) (token, bool) {
			l.lextrace("ENDSTR ")
			l.begin(l.prevState)
			if l.strNil {
				l.errstr = "empty string"
				l.lextrace("ERROR ")
				return token{kind: tERROR}, true
			}
			l.lval.str = string(l.strBuf)
			s := l.lval.str
			if l.prevState == scINITIAL || l.prevState == scGOTDEFS {
				switch s[0] {
				case '%':
					if len(s) == 1 || s == "%:" {
						l.errstr = "empty group"
						l.lextrace("ERROR ")
						return token{kind: tERROR}, true
					}
					return l.ret(tUSERGROUP, "USERGROUP ")
				case '+':
					if len(s) == 1 {
						l.errstr = "empty netgroup"
						l.lextrace("ERROR ")
						return token{kind: tERROR}, true
					}
					return l.ret(tNETGROUP, "NETGROUP ")
				}
			}
			return l.ret(tWORD, "WORD(4) ")
		}),
		rule(on(scINSTR), `\\`, func(l *lexer, text string, _ int) (token, bool) {
			l.lextrace("BACKSLASH ")
			l.appendStr(text)
			l.strNil = false
			return token{}, false
		}),
		rule(on(scINSTR), `([^"\r\n\\]|\\")+`, func(l *lexer, text string, _ int) (token, bool) {
			l.lextrace("STRBODY ")
			l.appendStr(text)
			l.strNil = false
			return token{}, false
		}),

		// Command line arguments.
		rule(on(scGOTCMND, scGOTEDIT), `\\[\*\?\[\]\!^]`, func(l *lexer, text string, _ int) (token, bool) {
			if t, ok := l.checkEditArg(text); ok {
				return t, ok
			}
			l.lextrace("QUOTEDCHAR ")
			l.fillArgs(text[:2], l.sawspace)
			l.sawspace = false
			return token{}, false
		}),
		rule(on(scGOTCMND, scGOTEDIT), `\\[:\\,= \t#]`, func(l *lexer, text string, _ int) (token, bool) {
			if t, ok := l.checkEditArg(text); ok {
				return t, ok
			}
			l.lextrace("QUOTEDCHAR ")
			l.fillArgs(text[1:2], l.sawspace)
			l.sawspace = false
			return token{}, false
		}),
		rule(on(scGOTCMND, scGOTEDIT), `[#:,=\r\n]`, func(l *lexer, _ string, matchStart int) (token, bool) {
			l.begin(scINITIAL)
			l.less(matchStart, 0)
			l.buf.atBOL = false
			return l.tok(tCOMMAND), true
		}),
		rule(on(scGOTCMND, scGOTEDIT), `[^#\\:, \t\r\n]+`, func(l *lexer, text string, matchStart int) (token, bool) {
			if !l.argsSet && text[0] == '^' {
				l.lextrace("ARG REGEX ")
				l.begin(scGOTREGEX)
				l.less(matchStart, 0)
				l.buf.atBOL = false
				return token{}, false
			}
			if t, ok := l.checkEditArg(text); ok {
				return t, ok
			}
			l.lextrace("ARG ")
			l.fillArgs(text, l.sawspace)
			l.sawspace = false
			return token{}, false
		}),

		// Regular expression arguments.
		rule(on(scGOTREGEX), `\\[^\r\n]`, func(l *lexer, text string, _ int) (token, bool) {
			l.lextrace("QUOTEDCHAR ")
			l.fillArgs(text[:2], false)
			return token{}, false
		}),
		rule(on(scGOTREGEX), `[#\r\n]`, func(l *lexer, _ string, matchStart int) (token, bool) {
			l.less(matchStart, 0)
			l.buf.atBOL = false
			l.begin(scINITIAL)
			l.errstr = "unterminated regular expression"
			l.lextrace("ERROR ")
			return token{kind: tERROR}, true
		}),
		rule(on(scGOTREGEX), `\$`, func(l *lexer, _ string, _ int) (token, bool) {
			l.fillArgs("$", false)
			l.begin(scINITIAL)
			l.continued = false
			// sudo compiles only the matched "$" here, which always
			// succeeds; the argument regex itself is not checked.
			return l.tok(tCOMMAND), true
		}),
		rule(on(scGOTREGEX), `[^#\\\r\n$]+`, func(l *lexer, text string, _ int) (token, bool) {
			if l.continued {
				text = strings.TrimLeft(text, " \t")
				l.continued = false
			}
			if text != "" {
				l.fillArgs(text, false)
			}
			return token{}, false
		}),

		// Digests.
		rule(on(scWANTDIGEST), `[[:xdigit:]]+`, func(l *lexer, text string, _ int) (token, bool) {
			l.begin(scINITIAL)
			if len(text) == l.digestLen*2 {
				l.fill(text)
				return l.ret(tDIGEST, "DIGEST ")
			}
			return token{}, false
		}),
		rule(on(scWANTDIGEST), `[A-Za-z0-9\+/=]+`, func(l *lexer, text string, _ int) (token, bool) {
			var n int
			if text[len(text)-1] == '=' {
				n = 4 * ((l.digestLen + 2) / 3) // with padding
			} else {
				n = (4*l.digestLen + 2) / 3 // without padding
			}
			l.begin(scINITIAL)
			if len(text) == n {
				l.fill(text)
				return l.ret(tDIGEST, "DIGEST ")
			}
			return token{}, false
		}),

		rule(on(scINITIAL), `@include`, includeTok(tINCLUDE, "INCLUDE ", 0)),
		rule(on(scINITIAL), `@includedir`, includeTok(tINCLUDEDIR, "INCLUDEDIR ", 0)),
		rule(on(scINITIAL), `^#include[[:blank:]]+.*(\r\n|\n)?`, includeTok(tINCLUDE, "INCLUDE ", len("#include"))),
		rule(on(scINITIAL), `^#includedir[[:blank:]]+.*(\r\n|\n)?`, includeTok(tINCLUDEDIR, "INCLUDEDIR ", len("#includedir"))),

		rule(on(scINITIAL), `^[[:blank:]]*Defaults([:@>\!][[:blank:]]*\!*"?({ID}|{WORD}))?`, func(l *lexer, text string, matchStart int) (token, bool) {
			if l.continued {
				return l.lineContinuationError()
			}
			n := 0
			for n < len(text) && (text[n] == ' ' || text[n] == '\t') {
				n++
			}
			n += len("Defaults")
			var deftype byte
			if n < len(text) {
				deftype = text[n]
				n++
				for n < len(text) && (text[n] == ' ' || text[n] == '\t') {
					n++
				}
			}
			l.begin(scGOTDEFS)
			switch deftype {
			case ':':
				l.less(matchStart, n)
				return l.ret(tDEFAULTS_USER, "DEFAULTS_USER ")
			case '>':
				l.less(matchStart, n)
				return l.ret(tDEFAULTS_RUNAS, "DEFAULTS_RUNAS ")
			case '@':
				l.less(matchStart, n)
				return l.ret(tDEFAULTS_HOST, "DEFAULTS_HOST ")
			case '!':
				l.less(matchStart, n)
				return l.ret(tDEFAULTS_CMND, "DEFAULTS_CMND ")
			}
			return l.ret(tDEFAULTS, "DEFAULTS ")
		}),

		rule(on(scINITIAL), `^[[:blank:]]*(Host|Cmnd|Cmd|User|Runas)_Alias`, func(l *lexer, text string, _ int) (token, bool) {
			if l.continued {
				return l.lineContinuationError()
			}
			switch strings.TrimLeft(text, " \t")[0] {
			case 'H':
				return l.ret(tHOSTALIAS, "HOSTALIAS ")
			case 'C':
				return l.ret(tCMNDALIAS, "CMNDALIAS ")
			case 'U':
				return l.ret(tUSERALIAS, "USERALIAS ")
			default:
				return l.ret(tRUNASALIAS, "RUNASALIAS ")
			}
		}),

		tagRule("NOPASSWD", tNOPASSWD, "NOPASSWD "),
		tagRule("PASSWD", tPASSWD, "PASSWD "),
		tagRule("NOEXEC", tNOEXEC, "NOEXEC "),
		tagRule("EXEC", tEXEC, "EXEC "),
		tagRule("INTERCEPT", tINTERCEPT, "INTERCEPT "),
		tagRule("NOINTERCEPT", tNOINTERCEPT, "NOINTERCEPT "),
		tagRule("SETENV", tSETENV, "SETENV "),
		tagRule("NOSETENV", tNOSETENV, "NOSETENV "),
		tagRule("LOG_OUTPUT", tLOG_OUTPUT, "LOG_OUTPUT "),
		tagRule("NOLOG_OUTPUT", tNOLOG_OUTPUT, "NOLOG_OUTPUT "),
		tagRule("LOG_INPUT", tLOG_INPUT, "LOG_INPUT "),
		tagRule("NOLOG_INPUT", tNOLOG_INPUT, "NOLOG_INPUT "),
		tagRule("MAIL", tMAIL, "MAIL "),
		tagRule("NOMAIL", tNOMAIL, "NOMAIL "),
		tagRule("FOLLOW", tFOLLOWLNK, "FOLLOW "),
		tagRule("NOFOLLOW", tNOFOLLOWLNK, "NOFOLLOW "),

		rule(on(scINITIAL, scGOTDEFS), `(\+|\%|\%:)`, func(l *lexer, text string, _ int) (token, bool) {
			if text[0] == '+' {
				l.errstr = "empty netgroup"
			} else {
				l.errstr = "empty group"
			}
			l.lextrace("ERROR ")
			return token{kind: tERROR}, true
		}),
		rule(nil, `\+{WORD}`, func(l *lexer, text string, _ int) (token, bool) {
			l.fill(text)
			return l.ret(tNETGROUP, "NETGROUP ")
		}),
		rule(nil, `\%:?({WORD}|{ID})`, func(l *lexer, text string, _ int) (token, bool) {
			l.fill(text)
			return l.ret(tUSERGROUP, "USERGROUP ")
		}),
		rule(nil, `{IPV4ADDR}(/{IPV4ADDR})?`, ntwkaddr),
		rule(nil, `{IPV4ADDR}/([12]?[0-9]|3[0-2])`, ntwkaddr),
		rule(nil, `{IPV6ADDR}(/{IPV6ADDR})?`, ntwkaddr6),
		rule(nil, `{IPV6ADDR}/([0-9]|[1-9][0-9]|1[01][0-9]|12[0-8])`, ntwkaddr6),
		rule(nil, `ALL`, simple(tALL, "ALL ")),

		keywordRule("TIMEOUT", tCMND_TIMEOUT),
		keywordRule("NOTBEFORE", tNOTBEFORE),
		keywordRule("NOTAFTER", tNOTAFTER),
		rule(on(scINITIAL), `CWD`, pathlikeExpect(tCWD, "CWD ")),
		rule(on(scINITIAL), `CHROOT`, pathlikeExpect(tCHROOT, "CHROOT ")),
		keywordRule("ROLE", tROLE),
		keywordRule("TYPE", tTYPE),
		keywordRule("APPARMOR_PROFILE", tAPPARMOR_PROFILE),
		keywordRule("PRIVS", tPRIVS),
		keywordRule("LIMITPRIVS", tLIMITPRIVS),

		rule(nil, `[[:upper:]][[:upper:][:digit:]_]*`, func(l *lexer, text string, _ int) (token, bool) {
			l.fill(text)
			return l.ret(tALIAS, "ALIAS ")
		}),
		rule(on(scGOTDEFS), `({PATH}|{REGEX}|sudoedit)`, func(l *lexer, text string, _ int) (token, bool) {
			l.fillCmnd(text)
			return l.ret(tCOMMAND, "COMMAND ")
		}),
		rule(nil, `sha224`, digestTok(tSHA224, "SHA224_TOK ")),
		rule(nil, `sha256`, digestTok(tSHA256, "SHA256_TOK ")),
		rule(nil, `sha384`, digestTok(tSHA384, "SHA384_TOK ")),
		rule(nil, `sha512`, digestTok(tSHA512, "SHA512_TOK ")),
		rule(nil, `sudoedit`, func(l *lexer, text string, _ int) (token, bool) {
			l.begin(scGOTEDIT)
			l.lextrace("COMMAND ")
			l.fillCmnd(text)
			return token{}, false
		}),
		rule(on(scEXPECTPATH), `({PATH}|{WORD})`, func(l *lexer, text string, _ int) (token, bool) {
			l.begin(l.prevState)
			l.fill(text)
			return l.ret(tWORD, "WORD(5) ")
		}),
		rule(nil, `{PATH}`, func(l *lexer, text string, _ int) (token, bool) {
			// directories can't have args...
			if text[len(text)-1] == '/' {
				l.lextrace("COMMAND ")
				l.fillCmnd(text)
				return l.tok(tCOMMAND), true
			}
			l.begin(scGOTCMND)
			l.lextrace("COMMAND ")
			l.fillCmnd(text)
			return token{}, false
		}),
		rule(nil, `{REGEX}`, func(l *lexer, text string, _ int) (token, bool) {
			if l.strict {
				if err := compileRegex(text); err != "" {
					l.errstr = err
					l.lextrace("ERROR ")
					return token{kind: tERROR}, true
				}
			}
			l.begin(scGOTCMND)
			l.lextrace("COMMAND ")
			l.fillCmnd(text)
			return token{}, false
		}),
		rule(on(scINITIAL, scEXPECTPATH, scGOTDEFS), `"`, beginStr),
		rule(on(scINITIAL, scGOTDEFS), `({ID}|{WORD})`, func(l *lexer, text string, _ int) (token, bool) {
			l.fill(text)
			return l.ret(tWORD, "WORD(6) ")
		}),
		rule(on(scGOTINC), `[^"[:space:]]([^[:space:]]|\\[[:blank:]])*`, func(l *lexer, text string, _ int) (token, bool) {
			l.fill(text)
			l.begin(scINITIAL)
			return l.ret(tWORD, "WORD(7) ")
		}),
		rule(on(scGOTINC), `"`, func(l *lexer, _ string, _ int) (token, bool) {
			l.lextrace("BEGINSTR ")
			l.strBuf = l.strBuf[:0]
			l.strNil = true
			l.prevState = scINITIAL
			l.begin(scINSTR)
			return token{}, false
		}),
		rule(nil, `\(`, simple(tLParen, "( ")),
		rule(nil, `\)`, simple(tRParen, ") ")),
		rule(nil, `,`, simple(tComma, ", ")),
		rule(nil, `=`, simple(tEquals, "= ")),
		rule(nil, `:`, simple(tColon, ": ")),
		starRule(`!+`, func(l *lexer, text string, _ int) (token, bool) {
			if len(text)&1 == 1 {
				return l.ret(tBang, "!")
			}
			return token{}, false
		}),
		starRule(`\r?\n`, func(l *lexer, _ string, matchStart int) (token, bool) {
			if l.state == scINSTR {
				l.begin(scINITIAL)
				l.less(matchStart, 0)
				l.errstr = "unexpected line break in string"
				l.lextrace("ERROR ")
				return token{kind: tERROR}, true
			}
			l.begin(scINITIAL)
			l.buf.lineno++
			l.continued = false
			return l.ret(tNewline, "\n")
		}),
		starRule(`[[:blank:]]+`, func(l *lexer, _ string, _ int) (token, bool) {
			l.sawspace = true
			return token{}, false
		}),
		starRule(`\\[[:blank:]]*\r?\n`, func(l *lexer, _ string, _ int) (token, bool) {
			l.sawspace = true
			l.buf.lineno++
			l.continued = true
			return token{}, false
		}),
		rule(on(scINITIAL, scSTARTDEFS, scINDEFS), `#(-[^\r\n0-9].*|[^\r\n0-9-].*)?(\r\n|\n)?`, func(l *lexer, text string, _ int) (token, bool) {
			if text[len(text)-1] == '\n' {
				l.begin(scINITIAL)
				l.buf.lineno++
				l.continued = false
			} else if !l.buf.eof {
				// Only reachable when "#" is followed by a digit in
				// Defaults; sudo reports strerror(errno) here.
				l.errstr = "syntax error"
				l.lextrace("ERROR ")
				return token{kind: tERROR}, true
			}
			return l.ret(tNewline, "#\n")
		}),
		starRule(`.`, simple(tNOMATCH, "NOMATCH ")),
	}
}
