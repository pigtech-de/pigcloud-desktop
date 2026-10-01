package cmdutil

import (
	"path/filepath"
	"regexp"
	"strings"
)

type MatchMode int

const (
	MatchGlob  MatchMode = iota
	MatchRegex
	MatchFixed
)

type Matcher struct {
	mode       MatchMode
	re         *regexp.Regexp
	pattern    string
	ignoreCase bool
}

func CompileMatcher(pattern string, mode MatchMode, ignoreCase bool) (*Matcher, error) {
	m := &Matcher{mode: mode, ignoreCase: ignoreCase}

	switch mode {
	case MatchRegex:
		p := pattern
		if ignoreCase {
			p = "(?i)" + p
		}
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, err
		}
		m.re = re
	case MatchGlob:
		if ignoreCase {
			m.pattern = strings.ToLower(pattern)
		} else {
			m.pattern = pattern
		}
		if _, err := filepath.Match(m.pattern, ""); err != nil {
			return nil, err
		}
	case MatchFixed:
		if ignoreCase {
			m.pattern = strings.ToLower(pattern)
		} else {
			m.pattern = pattern
		}
	}

	return m, nil
}

func (m *Matcher) MatchString(s string) bool {
	switch m.mode {
	case MatchRegex:
		return m.re.MatchString(s)
	case MatchGlob:
		target := s
		if m.ignoreCase {
			target = strings.ToLower(s)
		}
		matched, err := filepath.Match(m.pattern, target)
		if err != nil {
			return false
		}
		return matched
	case MatchFixed:
		target := s
		if m.ignoreCase {
			target = strings.ToLower(s)
		}
		return strings.Contains(target, m.pattern)
	}
	return false
}

func (m *Matcher) HighlightRegex() *regexp.Regexp {
	if m.re != nil {
		return m.re
	}
	if m.mode == MatchFixed {
		p := regexp.QuoteMeta(m.pattern)
		if m.ignoreCase {
			p = "(?i)" + p
		}
		if re, err := regexp.Compile(p); err == nil {
			return re
		}
	}
	return nil
}
