package config

import (
	"fmt"
	"strings"
)

// rdl's config uses a small, strict subset of YAML so the binary needs no
// third-party parser:
//
//	key: scalar
//	key: []                # empty list
//	key: [a, b]            # flow list of scalars
//	key:                   # block list
//	  - item
//	key:                   # one level of nested scalars
//	  sub: scalar
//
// Comments start with '#' at line start or after whitespace. Scalars may be
// unquoted, 'single quoted' ('' escapes ') or "double quoted" (\" and \\).
// Anything else is a parse error, never silently ignored.

type yamlValue struct {
	scalar string
	isList bool
	list   []string
	isMap  bool
	m      map[string]string
	line   int
}

func stripComment(s string) string {
	inS, inD := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\'' && !inD:
			inS = !inS
		case c == '"' && !inS:
			if i == 0 || s[i-1] != '\\' {
				inD = !inD
			}
		case c == '#' && !inS && !inD && (i == 0 || s[i-1] == ' ' || s[i-1] == '\t'):
			return s[:i]
		}
	}
	return s
}

func unquote(s string, line int) (string, error) {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		return strings.ReplaceAll(s[1:len(s)-1], "''", "'"), nil
	}
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		var b strings.Builder
		in := s[1 : len(s)-1]
		for i := 0; i < len(in); i++ {
			if in[i] == '\\' && i+1 < len(in) {
				i++
				switch in[i] {
				case 'n':
					b.WriteByte('\n')
				case 't':
					b.WriteByte('\t')
				default:
					b.WriteByte(in[i])
				}
				continue
			}
			b.WriteByte(in[i])
		}
		return b.String(), nil
	}
	if strings.HasPrefix(s, "'") || strings.HasPrefix(s, "\"") {
		return "", fmt.Errorf("line %d: unterminated quote", line)
	}
	return s, nil
}

func splitKey(s string, line int) (string, string, error) {
	i := strings.Index(s, ":")
	// A Windows drive letter in a key is not supported; keys are plain words.
	if i <= 0 {
		return "", "", fmt.Errorf("line %d: expected 'key: value'", line)
	}
	key := strings.TrimSpace(s[:i])
	for _, r := range key {
		if !(r == '_' || r == '-' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return "", "", fmt.Errorf("line %d: invalid key %q", line, key)
		}
	}
	rest := s[i+1:]
	if rest != "" && rest[0] != ' ' && rest[0] != '\t' {
		return "", "", fmt.Errorf("line %d: expected a space after ':'", line)
	}
	return key, strings.TrimSpace(rest), nil
}

func parseFlowList(s string, line int) ([]string, error) {
	in := strings.TrimSpace(s[1 : len(s)-1])
	if in == "" {
		return []string{}, nil
	}
	var out []string
	for _, part := range strings.Split(in, ",") {
		v, err := unquote(part, line)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func parseYAML(src string) (map[string]*yamlValue, error) {
	out := map[string]*yamlValue{}
	var cur *yamlValue
	var curKey string
	lines := strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n")
	for n, raw := range lines {
		ln := n + 1
		if strings.Contains(raw, "\t") && strings.TrimLeft(raw, " \t") != strings.TrimLeft(raw, " ") {
			return nil, fmt.Errorf("line %d: tabs are not allowed for indentation", ln)
		}
		s := strings.TrimRight(stripComment(raw), " \t")
		if strings.TrimSpace(s) == "" {
			continue
		}
		indent := len(s) - len(strings.TrimLeft(s, " "))
		body := strings.TrimSpace(s)
		if indent == 0 {
			key, val, err := splitKey(body, ln)
			if err != nil {
				return nil, err
			}
			if _, dup := out[key]; dup {
				return nil, fmt.Errorf("line %d: duplicate key %q", ln, key)
			}
			v := &yamlValue{line: ln}
			switch {
			case val == "":
				cur, curKey = v, key
			case strings.HasPrefix(val, "[") && strings.HasSuffix(val, "]"):
				l, err := parseFlowList(val, ln)
				if err != nil {
					return nil, err
				}
				v.isList, v.list = true, l
				cur = nil
			default:
				u, err := unquote(val, ln)
				if err != nil {
					return nil, err
				}
				v.scalar = u
				cur = nil
			}
			out[key] = v
			continue
		}
		if cur == nil {
			return nil, fmt.Errorf("line %d: unexpected indentation", ln)
		}
		if strings.HasPrefix(body, "- ") || body == "-" {
			if cur.isMap {
				return nil, fmt.Errorf("line %d: mixing list and map under %q", ln, curKey)
			}
			item, err := unquote(strings.TrimSpace(strings.TrimPrefix(body, "-")), ln)
			if err != nil {
				return nil, err
			}
			cur.isList = true
			cur.list = append(cur.list, item)
			continue
		}
		if cur.isList {
			return nil, fmt.Errorf("line %d: mixing list and map under %q", ln, curKey)
		}
		k, v, err := splitKey(body, ln)
		if err != nil {
			return nil, err
		}
		u, err := unquote(v, ln)
		if err != nil {
			return nil, err
		}
		if cur.m == nil {
			cur.m = map[string]string{}
		}
		cur.isMap = true
		cur.m[k] = u
	}
	return out, nil
}

// quoteYAML returns s as a YAML scalar, single-quoting when needed.
func quoteYAML(s string) string {
	if s == "" {
		return "''"
	}
	needs := strings.ContainsAny(s, ":#'\"[]{},&*!|>%@`") ||
		strings.TrimSpace(s) != s || strings.HasPrefix(s, "-") || strings.HasPrefix(s, "?")
	if !needs {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
