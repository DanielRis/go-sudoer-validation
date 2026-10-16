package sudoers

import (
	"regexp/syntax"
	"strings"
)

// compileRegex mirrors sudo_regex_compile (lib/util/regex.c): it reports
// why pattern is not a valid POSIX extended regular expression, or "" if
// it is. Error strings follow the BSD regerror(3) wording that visudo
// prints on macOS and the BSDs; glibc systems word them differently.
func compileRegex(pattern string) string {
	if len(pattern) > 1024 {
		return "regular expression too large"
	}

	// Check for (?i) to enable case-insensitive matching.
	cp := pattern
	if strings.HasPrefix(cp, "^") {
		cp = cp[1:]
	}
	if strings.HasPrefix(cp, "(?i)") {
		if pattern[0] == '^' {
			pattern = "^" + pattern[5:]
		} else {
			pattern = pattern[4:]
		}
	}

	if msg := checkPattern(pattern); msg != "" {
		return msg
	}
	if _, err := syntax.Parse(pattern, syntax.POSIX); err != nil {
		return regerror(err)
	}
	return ""
}

func regerror(err error) string {
	se, ok := err.(*syntax.Error)
	if !ok {
		return err.Error()
	}
	switch se.Code {
	case syntax.ErrMissingParen, syntax.ErrUnexpectedParen:
		return "parentheses not balanced"
	case syntax.ErrMissingBracket:
		return "brackets ([ ]) not balanced"
	case syntax.ErrInvalidCharRange:
		return "invalid character range"
	case syntax.ErrInvalidCharClass:
		return "invalid character class"
	case syntax.ErrTrailingBackslash:
		return "trailing backslash (\\)"
	case syntax.ErrMissingRepeatArgument, syntax.ErrInvalidRepeatOp:
		return "repetition-operator operand invalid"
	case syntax.ErrInvalidRepeatSize:
		return "invalid repetition count(s)"
	}
	return se.Code.String()
}

// parseNum parses a number between 0 and INT_MAX, handling escaped
// digits. It returns -1 on overflow and the index of the first
// non-matching character.
func parseNum(s string, i int) (int, int) {
	const maxInt = 1<<31 - 1
	result := 0
	for i < len(s) {
		ch := s[i]
		if ch == '\\' && i+1 < len(s) && isDigit(s[i+1]) {
			i++
			ch = s[i]
		} else if !isDigit(ch) {
			break
		}
		d := int(ch - '0')
		if result > maxInt/10 || (result == maxInt/10 && d > maxInt%10) {
			return -1, i
		}
		result = result*10 + d
		i++
	}
	return result, i
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// checkPattern rejects repetition sequences that some regcomp(3)
// implementations accept (sudo's check_pattern).
func checkPattern(p string) string {
	var prev byte
	b2 := 0
	isRepeat := func(c byte) bool { return c == '?' || c == '*' || c == '+' || c == '{' }
	for i := 0; i < len(p); {
		ch := p[i]
		i++
		switch ch {
		case '\\':
			if i < len(p) {
				i++
				prev = 0
				continue
			}
		case '?', '*', '+':
			if isRepeat(prev) {
				return "repetition-operator operand invalid"
			}
		case '{':
			b1, ep := parseNum(p, i)
			if ep < len(p) {
				switch {
				case p[ep] == '\\' && ep+1 < len(p) && p[ep+1] == ',':
					b2, ep = parseNum(p, ep+2)
				case p[ep] == ',':
					b2, ep = parseNum(p, ep+1)
				}
			}
			i = ep
			if i < len(p) && p[i] == '}' {
				if b1 < 0 || b1 > 255 || b2 < 0 || b2 > 255 {
					return "invalid repetition count(s)"
				}
				if isRepeat(prev) {
					return "repetition-operator operand invalid"
				}
				i++
				break
			}
			prev = 0
			continue
		}
		prev = ch
	}
	return ""
}
