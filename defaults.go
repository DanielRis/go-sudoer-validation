package sudoers

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// Defaults validation, ported from plugins/sudoers/defaults.c.

//go:generate sh -c "go run internal/gen/gendefaults.go internal/gen/def_data.in > defaults_table.go"

// defFlags is a sudo_defs_types type: a base type (T_MASK) plus
// modifier bits.
type defFlags int

const (
	dINT defFlags = iota + 1
	dUINT
	dSTR
	dFLAG
	dMODE
	dLIST
	dLOGFAC
	dLOGPRI
	dTUPLE
	dTIMESPEC
	dTIMEOUT
	dRLIMIT
	dPLUGIN
	dMASK defFlags = 0xff

	dBOOL   defFlags = 0x100
	dPATH   defFlags = 0x200
	dCHPATH defFlags = 0x400
	dSPACE  defFlags = 0x800
)

type defType struct {
	name   string
	typ    defFlags
	values []string // tuple values; [0] is boolean false, [1] true
}

var defaultsByName = func() map[string]*defType {
	m := make(map[string]*defType, len(defaultsTable))
	for i := range defaultsTable {
		m[defaultsTable[i].name] = &defaultsTable[i]
	}
	return m
}()

var syslogFacilities = map[string]bool{
	"authpriv": true, "auth": true, "daemon": true, "user": true,
	"local0": true, "local1": true, "local2": true, "local3": true,
	"local4": true, "local5": true, "local6": true, "local7": true,
}

var syslogPriorities = map[string]bool{
	"alert": true, "crit": true, "debug": true, "emerg": true, "err": true,
	"info": true, "notice": true, "warning": true, "none": true,
}

// checkDefault validates one Defaults entry (find_default followed by
// parse_default_entry) and returns the messages sudo would print.
func checkDefault(d *defaultsEntry) []string {
	def, ok := defaultsByName[d.variable]
	if !ok {
		return []string{fmt.Sprintf(`unknown defaults entry "%s"`, d.variable)}
	}
	base := def.typ & dMASK

	// If no value specified, the boolean flag must be set for non-flags.
	// Only flags and tuples support boolean "true".
	if !d.hasValue {
		switch {
		case base == dLOGFAC, base == dFLAG:
		case base == dTUPLE && def.typ&dBOOL != 0:
		default:
			if def.typ&dBOOL == 0 || d.op != opFalse {
				return []string{fmt.Sprintf(`no value specified for "%s"`, def.name)}
			}
		}
	}

	// Only lists support append/remove.
	if (d.op == opAdd || d.op == opRemove) && base != dLIST {
		return []string{fmt.Sprintf(`invalid operator "%c=" for "%s"`, d.op, def.name)}
	}

	val := d.value
	valid := true
	switch base {
	case dLOGFAC:
		valid = !d.hasValue || syslogFacilities[val]
	case dLOGPRI:
		valid = !d.hasValue || syslogPriorities[val]
	case dSTR:
		if d.hasValue && def.typ&(dPATH|dCHPATH) != 0 {
			if msgs := checkPath(def, val); len(msgs) > 0 {
				return msgs
			}
		}
	case dINT:
		valid = !d.hasValue || validStrtonum(val, math.MinInt32, math.MaxInt32)
	case dUINT:
		valid = !d.hasValue || validStrtonum(val, 0, math.MaxUint32)
	case dMODE:
		valid = !d.hasValue || validMode(val)
	case dFLAG:
		if d.hasValue {
			return []string{fmt.Sprintf(`option "%s" does not take a value`, def.name)}
		}
	case dLIST, dPLUGIN:
	case dTIMEOUT:
		if d.hasValue {
			_, err := parseTimeout(val)
			valid = err == nil
		}
	case dTUPLE:
		if d.hasValue {
			valid = false
			for _, v := range def.values {
				if v == val {
					valid = true
				}
			}
		}
	case dTIMESPEC:
		valid = !d.hasValue || validTimespec(val)
	case dRLIMIT:
		valid = !d.hasValue || validRlimit(val)
	}
	if !valid {
		v := val
		if !d.hasValue {
			v = "(null)"
		}
		return []string{fmt.Sprintf(`value "%s" is invalid for option "%s"`, v, def.name)}
	}
	return nil
}

// checkPath is valid_path.
func checkPath(def *defType, val string) []string {
	var msgs []string
	if len(val) >= pathMax {
		msgs = append(msgs, fmt.Sprintf(`path name for "%s" too long`, def.name))
	}
	if def.typ&dCHPATH != 0 {
		if val[0] != '/' && val[0] != '~' && val != "*" {
			msgs = append(msgs, fmt.Sprintf(`values for "%s" must begin with a '/' or '~', or be '*'`, def.name))
		}
	} else if val[0] != '/' {
		msgs = append(msgs, fmt.Sprintf(`values for "%s" must start with a '/'`, def.name))
	}
	return msgs
}

func isCSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r'
}

// validStrtonum is sudo_strtonum: optional leading space and sign,
// at least one digit, nothing after the digits, within [min, max].
func validStrtonum(s string, min, max int64) bool {
	i := 0
	for i < len(s) && isCSpace(s[i]) {
		i++
	}
	neg := false
	if i < len(s) && (s[i] == '-' || s[i] == '+') {
		neg = s[i] == '-'
		i++
	}
	start := i
	for i < len(s) && isDigit(s[i]) {
		i++
	}
	if i == start || i != len(s) {
		return false
	}
	n, err := strconv.ParseUint(s[start:], 10, 64)
	if err != nil {
		return false
	}
	if neg {
		return n <= uint64(-min)
	}
	return n <= uint64(max)
}

// validMode is sudo_strtomode: an octal number between 0 and 0777.
func validMode(s string) bool {
	n, rest, ok := strtol(s, 8)
	return ok && rest == "" && n >= 0 && n <= 0o777
}

// strtol parses like strtol(3): optional leading space and sign, then
// digits in base. ok is false if no digits were found or the value
// overflows a long.
func strtol(s string, base int) (n int64, rest string, ok bool) {
	i := 0
	for i < len(s) && isCSpace(s[i]) {
		i++
	}
	neg := false
	if i < len(s) && (s[i] == '-' || s[i] == '+') {
		neg = s[i] == '-'
		i++
	}
	start := i
	for i < len(s) && s[i] >= '0' && int(s[i]-'0') < base && s[i] <= '9' {
		i++
	}
	if i == start {
		return 0, s, false
	}
	u, err := strconv.ParseInt(s[start:i], base, 64)
	if err != nil {
		return 0, s[i:], false
	}
	if neg {
		u = -u
	}
	return u, s[i:], true
}

var (
	errInvalidTimeout  = errors.New("invalid timeout value")
	errTimeoutTooLarge = errors.New("timeout value too large")
)

// parseTimeout parses a timeout such as "1d2h3m4s" or a number of
// seconds (plugins/sudoers/timeout.c).
func parseTimeout(s string) (int, error) {
	const suffixes = "dhms"
	const maxInt = math.MaxInt32
	timeout, idx := 0, 0
	cp := s
	for {
		l, rest, ok := strtol(cp, 10)
		if !ok {
			if rest == cp {
				return 0, errInvalidTimeout // missing timeout
			}
			return 0, errTimeoutTooLarge
		}
		if l < 0 || l > maxInt {
			return 0, errTimeoutTooLarge
		}
		if rest != "" {
			ch := rest[0]
			if ch >= 'A' && ch <= 'Z' {
				ch += 'a' - 'A'
			}
			rest = rest[1:]
			for idx < len(suffixes) && suffixes[idx] != ch {
				idx++
			}
			if idx == len(suffixes) {
				return 0, errInvalidTimeout
			}
			mult := map[byte]int64{'d': 24 * 60 * 60, 'h': 60 * 60, 'm': 60, 's': 1}[ch]
			if l > maxInt/mult {
				return 0, errTimeoutTooLarge
			}
			l *= mult
		}
		cp = rest
		if l > int64(maxInt-timeout) {
			return 0, errTimeoutTooLarge
		}
		timeout += int(l)
		if cp == "" {
			return timeout, nil
		}
	}
}

// validGentime checks a Generalized Time string as accepted by
// parse_gentime: yyyymmddHH[MM[SS]][.f][Z|+hh[mm]|-hh[mm]].
func validGentime(s string) bool {
	n := 0
	for n < len(s) && isDigit(s[n]) {
		n++
	}
	if n >= len("yyyymmddHHMMSS")+1 || n < len("yyyymmddHH") || n&1 == 1 {
		return false
	}
	cp := s[n:]
	if len(cp) >= 2 && (cp[0] == '.' || cp[0] == ',') && isDigit(cp[1]) {
		cp = cp[2:]
	}
	if cp == "" {
		return true
	}
	switch cp[0] {
	case '-', '+':
		m := 0
		for 1+m < len(cp) && isDigit(cp[1+m]) {
			m++
		}
		if m != 2 && m != 4 {
			return false
		}
		cp = cp[1+m:]
	case 'Z':
		cp = cp[1:]
	default:
		return false
	}
	return cp == ""
}

// validTimespec is store_timespec: a number of minutes with an optional
// sign and fraction.
func validTimespec(s string) bool {
	const timeMax = math.MaxInt64
	if s != "" && (s[0] == '+' || s[0] == '-') {
		s = s[1:]
	}
	var sec int64
	i := 0
	for i < len(s) && s[i] != '.' {
		if !isDigit(s[i]) {
			return false
		}
		d := int64(s[i]-'0') * 60
		if sec > (timeMax-d)/10 {
			return false // overflow
		}
		sec = sec*10 + d
		i++
	}
	if i < len(s) { // s[i] == '.'
		i++
		var nsec int64
		for mult := int64(100000000); mult > 0 && i < len(s); mult /= 10 {
			if !isDigit(s[i]) {
				return false
			}
			nsec += mult * int64(s[i]-'0') * 60
			i++
		}
		for nsec >= 1000000000 {
			if sec == timeMax {
				return false
			}
			sec++
			nsec -= 1000000000
		}
	}
	return true
}

// validRlimit is store_rlimit: "user", "default", or "soft[,hard]"
// where each limit is a number or "infinity".
func validRlimit(s string) bool {
	if s == "user" || s == "default" {
		return true
	}
	hard := s
	if i := strings.IndexByte(s, ','); i >= 0 {
		hard = s[i+1:]
	}
	return checkRlimit(s, true) && checkRlimit(hard, false)
}

func checkRlimit(s string, soft bool) bool {
	end := func(rest string) bool {
		return rest == "" || (soft && rest[0] == ',')
	}
	if s != "" && isDigit(s[0]) {
		i := 0
		for i < len(s) && isDigit(s[i]) {
			i++
		}
		if _, err := strconv.ParseUint(s[:i], 10, 64); err != nil {
			return false
		}
		return end(s[i:])
	}
	if strings.HasPrefix(s, "infinity") {
		return end(s[len("infinity"):])
	}
	return false
}
