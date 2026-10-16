package sudoers

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"sort"
	"strings"
)

// The parser is a recursive-descent port of sudo's gram.y. It reads a
// lookahead token only where bison's LALR(1) tables do, so semantic
// actions observe the same lexer position (and report the same
// line:column) as sudo, and it reproduces bison's error recovery for
// the grammar's three error rules:
//
//	entry      : error '\n'                 (skip to end of line)
//	privileges : privileges ':' error       (drop the broken privilege)
//	include    : INCLUDE WORD error '\n'    (skip to end of line)

// pathMax is PATH_MAX on Linux, where sudoers files are most common.
const pathMax = 4096

// maxIncludeDepth is MAX_SUDOERS_DEPTH.
const maxIncludeDepth = 128

type memberType int

const (
	mALIAS memberType = iota
	mALL
	mNETGROUP
	mNTWKADDR
	mUSERGROUP
	mWORD
	mCOMMAND
	mMYSELF
)

type member struct {
	typ     memberType
	name    string
	negated bool
}

// Alias types, ordered like sudo's token values (which order aliases
// in its red-black tree and so the unused-alias report).
type aliasType int

const (
	aHost aliasType = iota
	aCmnd
	aUser
	aRunas
)

func (t aliasType) String() string {
	return [...]string{"Host_Alias", "Cmnd_Alias", "User_Alias", "Runas_Alias"}[t]
}

type alias struct {
	name    string
	typ     aliasType
	members []member
	file    string
	line    int
	column  int
	used    bool
}

type aliasKey struct {
	name string
	typ  aliasType
}

type cmndspec struct {
	runasUsers  []member // nil when no runas list was given
	runasGroups []member
	cmnd        member
}

type privilege struct {
	hosts []member
	cmnds []cmndspec
}

type userspec struct {
	users  []member
	privs  []privilege
	file   string
	line   int
	column int
}

// Defaults operators, as stored in struct defaults.op.
const (
	opFalse  = 0
	opTrue   = 1
	opAdd    = '+'
	opRemove = '-'
)

type defaultsEntry struct {
	kind     tokKind // tDEFAULTS, tDEFAULTS_HOST, ...
	binding  []member
	variable string
	value    string
	hasValue bool
	op       int
	file     string
	line     int
	column   int
}

// parseAbort unwinds the parser to an error recovery point (YYERROR).
type parseAbort struct{}

type parser struct {
	lex  *lexer
	la   *token // lookahead token; nil is bison's YYEMPTY
	opts Options

	diags      []Diagnostic
	parseError bool

	aliases   map[aliasKey]*alias
	userspecs []*userspec
	defaults  []*defaultsEntry
}

func newParser(content []byte, opts Options, trace io.Writer) *parser {
	p := &parser{opts: opts, aliases: map[aliasKey]*alias{}}
	p.lex = &lexer{
		buf:    newBuffer(opts.Filename, content),
		strict: opts.Strict,
		trace:  trace,
	}
	p.lex.sudoersError = p.yyerror
	p.lex.openNext = p.openIncludedirFile
	return p
}

func (p *parser) peek() token {
	if p.la == nil {
		t := p.lex.next()
		p.la = &t
	}
	return *p.la
}

// shift consumes the lookahead token.
func (p *parser) shift() token {
	t := p.peek()
	p.la = nil
	return t
}

// lineno is gram.y's this_lineno.
func (p *parser) lineno() int {
	if p.la != nil && p.la.kind == tNewline {
		return p.lex.buf.lineno - 1
	}
	return p.lex.buf.lineno
}

func (p *parser) column() int {
	return p.lex.buf.tokeStart + 1
}

func (p *parser) add(sev Severity, file string, line, column int, msg string) {
	p.diags = append(p.diags, Diagnostic{
		Severity: sev, File: file, Line: line, Column: column, Message: msg,
	})
}

// report is sudoerserrorf: report an error at the current position.
// An empty message marks the parse as failed without reporting.
func (p *parser) report(msg string) {
	if msg != "" {
		p.lex.lextrace("<*> ")
		p.add(SeverityError, p.lex.buf.file, p.lineno(), p.column(), msg)
	}
	p.parseError = true
}

// yyerror is sudoerserror: an ERROR lookahead token replaces the
// message with the lexer's own.
func (p *parser) yyerror(msg string) {
	if p.la != nil && p.la.kind == tERROR {
		msg = p.lex.errstr
		p.lex.errstr = ""
	}
	p.report(msg)
}

func (p *parser) syntaxError() {
	p.yyerror("syntax error")
	panic(parseAbort{})
}

// fail reports msg and unwinds (sudoerserror + YYERROR).
func (p *parser) fail(msg string) {
	p.yyerror(msg)
	panic(parseAbort{})
}

func (p *parser) expect(kind tokKind) token {
	if p.peek().kind != kind {
		p.syntaxError()
	}
	return p.shift()
}

// parse runs the grammar over the whole input.
func (p *parser) parse() {
	for p.peek().kind != tEOF {
		if !p.entry() {
			return // YYABORT: end of input during error recovery
		}
	}
}

// entry parses one entry, recovering from errors by skipping to the
// end of the line. It returns false if the parse must stop.
func (p *parser) entry() (ok bool) {
	defer func() {
		if r := recover(); r != nil {
			if _, isAbort := r.(parseAbort); !isAbort {
				panic(r)
			}
			ok = p.skipLine()
		}
	}()

	switch t := p.peek(); t.kind {
	case tNewline:
		p.shift()
	case tINCLUDE, tINCLUDEDIR:
		p.include()
	case tUSERALIAS:
		p.shift()
		p.aliasDefs(aUser)
		p.expect(tNewline)
	case tHOSTALIAS:
		p.shift()
		p.aliasDefs(aHost)
		p.expect(tNewline)
	case tCMNDALIAS:
		p.shift()
		p.aliasDefs(aCmnd)
		p.expect(tNewline)
	case tRUNASALIAS:
		p.shift()
		p.aliasDefs(aRunas)
		p.expect(tNewline)
	case tDEFAULTS:
		p.shift()
		defs := p.defaultsList()
		p.expect(tNewline)
		p.addDefaults(tDEFAULTS, nil, defs)
	case tDEFAULTS_USER, tDEFAULTS_RUNAS:
		p.shift()
		binding := p.userlist()
		defs := p.defaultsList()
		p.expect(tNewline)
		p.addDefaults(t.kind, binding, defs)
	case tDEFAULTS_HOST:
		p.shift()
		binding := p.hostlist()
		defs := p.defaultsList()
		p.expect(tNewline)
		p.addDefaults(t.kind, binding, defs)
	case tDEFAULTS_CMND:
		p.shift()
		binding := p.cmndlist()
		defs := p.defaultsList()
		p.expect(tNewline)
		p.addDefaults(t.kind, binding, defs)
	case tALIAS, tALL, tNETGROUP, tUSERGROUP, tWORD, tBang:
		users := p.userlist()
		privs := p.privileges()
		p.expect(tNewline)
		// We already parsed the newline so sudolineno is off by one.
		p.userspecs = append(p.userspecs, &userspec{
			users: users, privs: privs, file: p.lex.buf.file,
			line: p.lex.buf.lineno - 1, column: p.column(),
		})
	default:
		p.syntaxError()
	}
	return true
}

// skipLine discards tokens through the next newline (entry: error '\n').
func (p *parser) skipLine() bool {
	for {
		switch p.peek().kind {
		case tNewline:
			p.shift()
			return true
		case tEOF:
			return false
		}
		p.shift()
	}
}

func (p *parser) include() {
	isDir := p.shift().kind == tINCLUDEDIR
	word := p.expect(tWORD)
	file, line, column := p.lex.buf.file, p.lineno(), p.column()
	if p.peek().kind != tNewline {
		// include: INCLUDE WORD error '\n'
		p.yyerror("syntax error")
		if !p.skipLine() {
			panic(parseAbort{})
		}
	} else {
		p.shift()
	}
	p.pushInclude(word.str, isDir, file, line, column)
}

func (p *parser) defaultsList() []*defaultsEntry {
	defs := []*defaultsEntry{p.defaultsEntry()}
	for p.peek().kind == tComma {
		p.shift()
		defs = append(defs, p.defaultsEntry())
	}
	return defs
}

func (p *parser) defaultsEntry() *defaultsEntry {
	switch p.peek().kind {
	case tBang:
		p.shift()
		v := p.expect(tDEFVAR)
		return p.newDefault(v.str, "", false, opFalse)
	case tDEFVAR:
		v := p.shift()
		var op int
		switch p.peek().kind {
		case tEquals:
			op = opTrue
		case tPlus:
			op = opAdd
		case tMinus:
			op = opRemove
		default:
			return p.newDefault(v.str, "", false, opTrue)
		}
		p.shift()
		w := p.expect(tWORD)
		return p.newDefault(v.str, w.str, true, op)
	}
	p.syntaxError()
	return nil
}

func (p *parser) newDefault(variable, value string, hasValue bool, op int) *defaultsEntry {
	return &defaultsEntry{
		variable: variable, value: value, hasValue: hasValue, op: op,
		file: p.lex.buf.file, line: p.lineno(), column: p.column(),
	}
}

func (p *parser) addDefaults(kind tokKind, binding []member, defs []*defaultsEntry) {
	for _, d := range defs {
		d.kind = kind
		d.binding = binding
		p.defaults = append(p.defaults, d)
	}
}

func (p *parser) privileges() []privilege {
	privs := []privilege{p.privilege()}
	for p.peek().kind == tColon {
		p.shift()
		if pr, ok := p.privilegeAfterColon(); ok {
			privs = append(privs, pr)
		}
	}
	return privs
}

// privilegeAfterColon parses a privilege following ':'. On error the
// privilege is dropped (privileges: privileges ':' error) and parsing
// resumes with the same lookahead token.
func (p *parser) privilegeAfterColon() (pr privilege, ok bool) {
	defer func() {
		if r := recover(); r != nil {
			if _, isAbort := r.(parseAbort); !isAbort {
				panic(r)
			}
			ok = false
		}
	}()
	return p.privilege(), true
}

func (p *parser) privilege() privilege {
	hosts := p.hostlist()
	p.expect(tEquals)
	return privilege{hosts: hosts, cmnds: p.cmndspeclist()}
}

func (p *parser) hostlist() []member {
	list := []member{p.ophost()}
	for p.peek().kind == tComma {
		p.shift()
		list = append(list, p.ophost())
	}
	return list
}

func (p *parser) ophost() member {
	negated := false
	if p.peek().kind == tBang {
		p.shift()
		negated = true
	}
	var m member
	switch t := p.peek(); t.kind {
	case tALIAS:
		m = member{typ: mALIAS, name: t.str}
	case tALL:
		m = member{typ: mALL}
	case tNETGROUP:
		m = member{typ: mNETGROUP, name: t.str}
	case tNTWKADDR:
		m = member{typ: mNTWKADDR, name: t.str}
	case tWORD:
		m = member{typ: mWORD, name: t.str}
	default:
		p.syntaxError()
	}
	p.shift()
	m.negated = negated
	return m
}

func (p *parser) userlist() []member {
	list := []member{p.opuser()}
	for p.peek().kind == tComma {
		p.shift()
		list = append(list, p.opuser())
	}
	return list
}

func (p *parser) opuser() member {
	negated := false
	if p.peek().kind == tBang {
		p.shift()
		negated = true
	}
	var m member
	switch t := p.peek(); t.kind {
	case tALIAS:
		m = member{typ: mALIAS, name: t.str}
	case tALL:
		m = member{typ: mALL}
	case tNETGROUP:
		m = member{typ: mNETGROUP, name: t.str}
	case tUSERGROUP:
		m = member{typ: mUSERGROUP, name: t.str}
	case tWORD:
		m = member{typ: mWORD, name: t.str}
	default:
		p.syntaxError()
	}
	p.shift()
	m.negated = negated
	return m
}

func (p *parser) grouplist() []member {
	list := []member{p.opgroup()}
	for p.peek().kind == tComma {
		p.shift()
		list = append(list, p.opgroup())
	}
	return list
}

func (p *parser) opgroup() member {
	negated := false
	if p.peek().kind == tBang {
		p.shift()
		negated = true
	}
	var m member
	switch t := p.peek(); t.kind {
	case tALIAS:
		m = member{typ: mALIAS, name: t.str}
	case tALL:
		m = member{typ: mALL}
	case tWORD:
		m = member{typ: mWORD, name: t.str}
	default:
		p.syntaxError()
	}
	p.shift()
	m.negated = negated
	return m
}

func isUserStart(k tokKind) bool {
	switch k {
	case tALIAS, tALL, tNETGROUP, tUSERGROUP, tWORD, tBang:
		return true
	}
	return false
}

func isGroupStart(k tokKind) bool {
	switch k {
	case tALIAS, tALL, tWORD, tBang:
		return true
	}
	return false
}

func (p *parser) cmndspeclist() []cmndspec {
	specs := []cmndspec{p.cmndspec()}
	for p.peek().kind == tComma {
		p.shift()
		cs := p.cmndspec()
		// propagate_cmndspec: an empty runas list inherits the previous one.
		if prev := specs[len(specs)-1]; cs.runasUsers == nil && cs.runasGroups == nil {
			cs.runasUsers, cs.runasGroups = prev.runasUsers, prev.runasGroups
		}
		specs = append(specs, cs)
	}
	return specs
}

func (p *parser) cmndspec() cmndspec {
	var cs cmndspec
	if p.peek().kind == tLParen {
		p.shift()
		cs.runasUsers, cs.runasGroups = p.runaslist()
		p.expect(tRParen)
	}
	p.options()
	for isTag(p.peek().kind) {
		p.shift()
	}
	cs.cmnd = p.digcmnd()
	return cs
}

func (p *parser) runaslist() (users, groups []member) {
	myself := []member{{typ: mMYSELF}}
	switch t := p.peek(); {
	case t.kind == tColon:
		p.shift()
		if isGroupStart(p.peek().kind) {
			return myself, p.grouplist()
		}
		return myself, nil
	case isUserStart(t.kind):
		users = p.userlist()
		if p.peek().kind == tColon {
			p.shift()
			groups = p.grouplist()
		}
		return users, groups
	}
	return myself, nil
}

func isTag(k tokKind) bool {
	return k >= tNOPASSWD && k <= tNOINTERCEPT
}

func (p *parser) options() {
	for {
		kind := p.peek().kind
		switch kind {
		case tCWD, tCHROOT, tCMND_TIMEOUT, tNOTBEFORE, tNOTAFTER,
			tROLE, tTYPE, tAPPARMOR_PROFILE, tPRIVS, tLIMITPRIVS:
		default:
			return
		}
		p.shift()
		p.expect(tEquals)
		val := p.expect(tWORD).str

		switch kind {
		case tCWD, tCHROOT:
			name := "CWD"
			if kind == tCHROOT {
				name = "CHROOT"
			}
			if val[0] != '/' && val[0] != '~' && val != "*" {
				p.fail(fmt.Sprintf(`values for "%s" must start with a '/', '~', or '*'`, name))
			}
			if len(val) >= pathMax {
				p.fail(fmt.Sprintf(`"%s" path too long`, name))
			}
			if kind == tCHROOT {
				p.add(SeverityWarning, p.lex.buf.file, p.lineno(), p.column(), `"CHROOT" is deprecated`)
			}
		case tCMND_TIMEOUT:
			if _, err := parseTimeout(val); err != nil {
				p.fail(err.Error())
			}
		case tNOTBEFORE:
			if !validGentime(val) {
				p.fail("invalid notbefore value")
			}
		case tNOTAFTER:
			if !validGentime(val) {
				p.fail("invalid notafter value")
			}
		}
	}
}

func (p *parser) digcmnd() member {
	if !isDigestTok(p.peek().kind) {
		return p.opcmnd()
	}
	for {
		p.shift()
		p.expect(tColon)
		p.expect(tDIGEST)
		if p.peek().kind != tComma {
			break
		}
		p.shift()
		if !isDigestTok(p.peek().kind) {
			p.syntaxError()
		}
	}
	m := p.opcmnd()
	if m.typ != mCOMMAND && m.typ != mALL {
		p.fail("a digest requires a path name")
	}
	return m
}

func isDigestTok(k tokKind) bool {
	return k >= tSHA224 && k <= tSHA512
}

func (p *parser) opcmnd() member {
	negated := false
	if p.peek().kind == tBang {
		p.shift()
		negated = true
	}
	var m member
	switch t := p.peek(); t.kind {
	case tALL:
		p.shift()
		m = member{typ: mALL}
	case tALIAS:
		p.shift()
		m = member{typ: mALIAS, name: t.str}
	case tCOMMAND:
		p.shift()
		if len(t.cmnd) >= pathMax {
			p.fail("command too long")
		}
		m = member{typ: mCOMMAND, name: t.cmnd}
	case tWORD:
		p.shift()
		if t.str != "list" {
			p.fail("expected a fully-qualified path name")
		}
		m = member{typ: mCOMMAND, name: t.str}
	default:
		p.syntaxError()
	}
	m.negated = negated
	return m
}

func (p *parser) cmndlist() []member {
	list := []member{p.digcmnd()}
	for p.peek().kind == tComma {
		p.shift()
		list = append(list, p.digcmnd())
	}
	return list
}

var reservedWords = map[tokKind]string{
	tALL: "ALL", tCHROOT: "CHROOT", tCWD: "CWD", tCMND_TIMEOUT: "CMND_TIMEOUT",
	tNOTBEFORE: "NOTBEFORE", tNOTAFTER: "NOTAFTER", tROLE: "ROLE", tTYPE: "TYPE",
	tPRIVS: "PRIVS", tLIMITPRIVS: "LIMITPRIVS", tAPPARMOR_PROFILE: "APPARMOR_PROFILE",
}

func (p *parser) aliasDefs(typ aliasType) {
	p.aliasDef(typ)
	for p.peek().kind == tColon {
		p.shift()
		p.aliasDef(typ)
	}
}

func (p *parser) aliasDef(typ aliasType) {
	t := p.peek()
	if word, ok := reservedWords[t.kind]; ok {
		p.shift()
		p.report(fmt.Sprintf("syntax error, reserved word %s used as an alias name", word))
		panic(parseAbort{})
	}
	if t.kind != tALIAS {
		p.syntaxError()
	}
	p.shift()
	file, line, column := p.lex.buf.file, p.lineno(), p.column()
	p.expect(tEquals)

	var members []member
	switch typ {
	case aHost:
		members = p.hostlist()
	case aCmnd:
		members = p.cmndlist()
	default:
		members = p.userlist()
	}

	key := aliasKey{t.str, typ}
	if prev, dup := p.aliases[key]; dup {
		p.report(fmt.Sprintf(`duplicate %s "%s", previously defined at %s:%d:%d`,
			typ, t.str, prev.file, prev.line, prev.column))
		panic(parseAbort{})
	}
	p.aliases[key] = &alias{
		name: t.str, typ: typ, members: members,
		file: file, line: line, column: column,
	}
}

// pushInclude opens an @include/@includedir target from opts.FS and
// switches the lexer to it (push_include).
func (p *parser) pushInclude(src string, isDir bool, file string, line, column int) {
	if p.opts.FS == nil {
		return
	}
	target := p.expandInclude(src)
	if target == "" {
		return
	}
	if len(p.lex.stack) >= maxIncludeDepth {
		p.add(SeverityError, file, line, column, target+": too many levels of includes")
		p.parseError = true
		return
	}
	if isDir {
		// The first directory found in the colon-separated path is used.
		for _, dir := range strings.Split(target, ":") {
			if fi, err := fs.Stat(p.opts.FS, fsPath(dir)); err != nil || !fi.IsDir() {
				continue
			}
			files := p.readIncludedir(dir)
			for len(files) > 0 {
				b := p.openIncludedirFile(files[0])
				files = files[1:]
				if b != nil {
					b.more = files
					p.lex.stack = append(p.lex.stack, p.lex.buf)
					p.lex.buf = b
					return
				}
			}
			return
		}
		return
	}

	// Open the first file found in the colon-separated path; errors are
	// reported against the first file.
	components := strings.Split(target, ":")
	var firstErr error
	for _, name := range components {
		var data []byte
		err := fs.ErrNotExist
		if name != "" {
			data, err = fs.ReadFile(p.opts.FS, fsPath(name))
		}
		if err == nil {
			p.lex.stack = append(p.lex.stack, p.lex.buf)
			p.lex.buf = newBuffer(name, data)
			return
		}
		if firstErr == nil {
			firstErr = err
		}
		if !errors.Is(err, fs.ErrNotExist) {
			break
		}
	}
	msg := components[0] + ": " + describeFSError(firstErr)
	if fi, err := fs.Stat(p.opts.FS, fsPath(components[0])); components[0] != "" && err == nil && !fi.Mode().IsRegular() {
		msg = components[0] + " is not a regular file"
	}
	p.add(SeverityError, file, line, column, msg)
	p.parseError = true
}

// expandInclude expands %h and makes a relative path relative to the
// directory of the current file (expand_include).
func (p *parser) expandInclude(src string) string {
	if len(src) > 1 && src[0] == '"' && src[len(src)-1] == '"' {
		src = src[1 : len(src)-1]
	}
	if src == "" {
		return ""
	}
	if strings.Contains(src, "%h") {
		host := p.opts.Hostname
		if host == "" {
			host = "localhost"
		}
		src = strings.ReplaceAll(src, "%h", strings.ReplaceAll(host, "/", "_"))
	}
	if src[0] == '/' {
		return src
	}
	if i := strings.LastIndexByte(p.lex.buf.file, '/'); i >= 0 {
		return p.lex.buf.file[:i+1] + src
	}
	return src
}

// readIncludedir lists the regular files in dir that do not end in
// '~' or contain a '.', sorted by name. A missing directory is not an
// error.
func (p *parser) readIncludedir(dir string) []string {
	entries, err := fs.ReadDir(p.opts.FS, fsPath(dir))
	if err != nil {
		return nil
	}
	var files []string
	for _, e := range entries {
		name := e.Name()
		if name == "" || strings.HasSuffix(name, "~") || strings.Contains(name, ".") {
			continue
		}
		full := strings.TrimSuffix(dir, "/") + "/" + name
		if fi, err := fs.Stat(p.opts.FS, fsPath(full)); err != nil || !fi.Mode().IsRegular() {
			continue
		}
		files = append(files, full)
	}
	sort.Strings(files)
	return files
}

func (p *parser) openIncludedirFile(file string) *buffer {
	data, err := fs.ReadFile(p.opts.FS, fsPath(file))
	if err != nil {
		return nil
	}
	return newBuffer(file, data)
}

// popInclude resumes the including file, or moves on to the next file
// of an @includedir (pop_include). It returns false at the outermost
// file.
func (l *lexer) popInclude() bool {
	if len(l.stack) == 0 {
		return false
	}
	for len(l.buf.more) > 0 {
		next := l.buf.more[0]
		rest := l.buf.more[1:]
		if b := l.openNext(next); b != nil {
			b.more = rest
			l.buf = b
			return true
		}
		l.buf.more = rest
	}
	l.buf = l.stack[len(l.stack)-1]
	l.stack = l.stack[:len(l.stack)-1]
	return true
}

func fsPath(p string) string {
	p = strings.TrimPrefix(path.Clean(p), "/")
	if p == "" {
		return "."
	}
	return p
}

func describeFSError(err error) string {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "No such file or directory"
	case errors.Is(err, fs.ErrPermission):
		return "Permission denied"
	}
	return err.Error()
}
