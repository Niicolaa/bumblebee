// Package toml implements a small, dependency-free reader for the subset
// of TOML used by lockfiles and developer-tool configs.
//
// Bumblebee ships zero non-stdlib dependencies, and the standard library
// has no TOML support. That single gap blocks a large share of the
// remaining ecosystem coverage: Cargo (`Cargo.lock`), Poetry
// (`poetry.lock`), uv (`uv.lock`), PEP 751 (`pylock.toml`), Julia
// (`Manifest.toml`), and the Codex MCP host config (`config.toml`). This
// package exists so those parsers can share one reader instead of each
// hand-rolling a line scanner.
//
// Scope and deliberate limits:
//
//   - Supported: bare/quoted/dotted keys, `[table]`, `[[array of tables]]`,
//     basic and literal strings (including multi-line forms), integers,
//     floats, booleans, arrays (nested, multi-line, trailing commas), and
//     inline tables.
//   - Dates and times are returned as their raw string text rather than
//     being typed. No consumer here needs temporal comparison, and
//     avoiding time parsing keeps the reader small.
//   - Validation is intentionally lenient: this reads files produced by
//     package managers, it is not a conformance-checking parser. Malformed
//     input yields an error rather than a panic, which is the only
//     guarantee the scanners rely on.
//
// The reader is allocation-modest and operates on an in-memory buffer that
// callers have already size-bounded via their own readBounded helper.
package toml

import (
	"fmt"
	"strconv"
	"strings"
)

// Parse reads TOML text and returns the root table.
//
// Tables are map[string]any. Arrays of tables are []any whose elements are
// map[string]any. Scalars are string, int64, float64, or bool.
func Parse(data []byte) (map[string]any, error) {
	p := &parser{s: string(data), line: 1}
	return p.parse()
}

// Table returns v as a table when it is one.
func Table(v any) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	return m, ok
}

// Tables returns v as a list of tables. It accepts both an array of tables
// and a single table, so callers can treat `[[package]]` and a lone
// `[package]` uniformly.
func Tables(v any) []map[string]any {
	switch t := v.(type) {
	case []any:
		out := make([]map[string]any, 0, len(t))
		for _, e := range t {
			if m, ok := e.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	case map[string]any:
		return []map[string]any{t}
	}
	return nil
}

// String returns v as a string when it is one.
func String(v any) (string, bool) {
	s, ok := v.(string)
	return s, ok
}

// Strings returns the string elements of an array value, skipping any
// element that is not a string.
func Strings(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// Get resolves a dotted path (e.g. "metadata.lock-version") against a
// table, returning nil when any segment is missing.
func Get(root map[string]any, path string) any {
	cur := any(root)
	for _, seg := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur, ok = m[seg]
		if !ok {
			return nil
		}
	}
	return cur
}

type parser struct {
	s    string
	i    int
	line int
}

func (p *parser) parse() (map[string]any, error) {
	root := map[string]any{}
	cur := root
	for {
		p.skipSpaceAndComments()
		if p.i >= len(p.s) {
			return root, nil
		}
		if p.s[p.i] == '[' {
			tbl, err := p.parseTableHeader(root)
			if err != nil {
				return nil, err
			}
			cur = tbl
			continue
		}
		if err := p.parseKeyValue(cur); err != nil {
			return nil, err
		}
	}
}

// parseTableHeader consumes a `[table]` or `[[array of tables]]` header and
// returns the table that subsequent key/value pairs belong to.
func (p *parser) parseTableHeader(root map[string]any) (map[string]any, error) {
	array := false
	p.i++ // consume '['
	if p.i < len(p.s) && p.s[p.i] == '[' {
		array = true
		p.i++
	}
	path, err := p.parseKeyPath()
	if err != nil {
		return nil, err
	}
	p.skipInlineSpace()
	if p.i >= len(p.s) || p.s[p.i] != ']' {
		return nil, p.errf("unterminated table header")
	}
	p.i++
	if array {
		if p.i >= len(p.s) || p.s[p.i] != ']' {
			return nil, p.errf("unterminated array-of-tables header")
		}
		p.i++
	}
	if len(path) == 0 {
		return nil, p.errf("empty table header")
	}
	if array {
		return p.appendArrayTable(root, path)
	}
	return p.ensureTable(root, path)
}

// ensureTable walks (creating as needed) the nested tables named by path.
// When an intermediate segment is an array of tables, the most recently
// appended element is used, which is what TOML's scoping rules require.
func (p *parser) ensureTable(root map[string]any, path []string) (map[string]any, error) {
	cur := root
	for _, seg := range path {
		existing, ok := cur[seg]
		if !ok {
			next := map[string]any{}
			cur[seg] = next
			cur = next
			continue
		}
		switch t := existing.(type) {
		case map[string]any:
			cur = t
		case []any:
			if len(t) == 0 {
				return nil, p.errf("cannot descend into empty array %q", seg)
			}
			last, ok := t[len(t)-1].(map[string]any)
			if !ok {
				return nil, p.errf("cannot descend into non-table array %q", seg)
			}
			cur = last
		default:
			return nil, p.errf("key %q is not a table", seg)
		}
	}
	return cur, nil
}

func (p *parser) appendArrayTable(root map[string]any, path []string) (map[string]any, error) {
	parent := root
	if len(path) > 1 {
		var err error
		parent, err = p.ensureTable(root, path[:len(path)-1])
		if err != nil {
			return nil, err
		}
	}
	key := path[len(path)-1]
	entry := map[string]any{}
	switch existing := parent[key].(type) {
	case nil:
		parent[key] = []any{entry}
	case []any:
		parent[key] = append(existing, entry)
	default:
		return nil, p.errf("key %q already set to a non-array value", key)
	}
	return entry, nil
}

func (p *parser) parseKeyValue(cur map[string]any) error {
	path, err := p.parseKeyPath()
	if err != nil {
		return err
	}
	if len(path) == 0 {
		return p.errf("expected key")
	}
	p.skipInlineSpace()
	if p.i >= len(p.s) || p.s[p.i] != '=' {
		return p.errf("expected '=' after key")
	}
	p.i++
	p.skipInlineSpace()
	val, err := p.parseValue()
	if err != nil {
		return err
	}
	target := cur
	if len(path) > 1 {
		target, err = p.ensureTable(cur, path[:len(path)-1])
		if err != nil {
			return err
		}
	}
	target[path[len(path)-1]] = val
	return nil
}

// parseKeyPath reads a dotted key sequence, accepting bare, basic-string,
// and literal-string segments.
func (p *parser) parseKeyPath() ([]string, error) {
	var path []string
	for {
		p.skipInlineSpace()
		if p.i >= len(p.s) {
			return nil, p.errf("unexpected end of input in key")
		}
		var seg string
		switch c := p.s[p.i]; {
		case c == '"':
			s, err := p.parseBasicString()
			if err != nil {
				return nil, err
			}
			seg = s
		case c == '\'':
			s, err := p.parseLiteralString()
			if err != nil {
				return nil, err
			}
			seg = s
		default:
			start := p.i
			for p.i < len(p.s) && isBareKeyChar(p.s[p.i]) {
				p.i++
			}
			if p.i == start {
				return nil, p.errf("invalid key character %q", string(p.s[p.i]))
			}
			seg = p.s[start:p.i]
		}
		path = append(path, seg)
		p.skipInlineSpace()
		if p.i < len(p.s) && p.s[p.i] == '.' {
			p.i++
			continue
		}
		return path, nil
	}
}

func (p *parser) parseValue() (any, error) {
	if p.i >= len(p.s) {
		return nil, p.errf("expected value")
	}
	switch c := p.s[p.i]; {
	case c == '"':
		if strings.HasPrefix(p.s[p.i:], `"""`) {
			return p.parseMultilineBasicString()
		}
		return p.parseBasicString()
	case c == '\'':
		if strings.HasPrefix(p.s[p.i:], `'''`) {
			return p.parseMultilineLiteralString()
		}
		return p.parseLiteralString()
	case c == '[':
		return p.parseArray()
	case c == '{':
		return p.parseInlineTable()
	default:
		return p.parseScalar()
	}
}

// parseScalar handles numbers, booleans, and any other bare token. Values
// that are not recognised as a number or boolean (dates, times, and the
// like) are returned as their raw text.
func (p *parser) parseScalar() (any, error) {
	start := p.i
	for p.i < len(p.s) {
		c := p.s[p.i]
		if c == '\n' || c == '\r' || c == ',' || c == ']' || c == '}' || c == '#' {
			break
		}
		p.i++
	}
	raw := strings.TrimSpace(p.s[start:p.i])
	if raw == "" {
		return nil, p.errf("empty value")
	}
	switch raw {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	// TOML permits underscores as digit separators.
	cleaned := strings.ReplaceAll(raw, "_", "")
	if n, err := strconv.ParseInt(cleaned, 0, 64); err == nil {
		return n, nil
	}
	if f, err := strconv.ParseFloat(cleaned, 64); err == nil {
		return f, nil
	}
	return raw, nil
}

func (p *parser) parseArray() (any, error) {
	p.i++ // consume '['
	out := []any{}
	for {
		p.skipSpaceAndComments()
		if p.i >= len(p.s) {
			return nil, p.errf("unterminated array")
		}
		if p.s[p.i] == ']' {
			p.i++
			return out, nil
		}
		v, err := p.parseValue()
		if err != nil {
			return nil, err
		}
		out = append(out, v)
		p.skipSpaceAndComments()
		if p.i < len(p.s) && p.s[p.i] == ',' {
			p.i++
			continue
		}
	}
}

func (p *parser) parseInlineTable() (any, error) {
	p.i++ // consume '{'
	out := map[string]any{}
	for {
		p.skipInlineSpace()
		if p.i >= len(p.s) {
			return nil, p.errf("unterminated inline table")
		}
		if p.s[p.i] == '}' {
			p.i++
			return out, nil
		}
		if err := p.parseKeyValue(out); err != nil {
			return nil, err
		}
		p.skipInlineSpace()
		if p.i < len(p.s) && p.s[p.i] == ',' {
			p.i++
			continue
		}
	}
}

func (p *parser) parseBasicString() (string, error) {
	p.i++ // consume opening quote
	var b strings.Builder
	for p.i < len(p.s) {
		c := p.s[p.i]
		switch c {
		case '"':
			p.i++
			return b.String(), nil
		case '\\':
			p.i++
			s, err := p.parseEscape()
			if err != nil {
				return "", err
			}
			b.WriteString(s)
		case '\n':
			return "", p.errf("newline in basic string")
		default:
			b.WriteByte(c)
			p.i++
		}
	}
	return "", p.errf("unterminated basic string")
}

func (p *parser) parseMultilineBasicString() (string, error) {
	p.i += 3
	// A newline immediately after the opening delimiter is trimmed.
	p.i += trimLeadingNewline(p.s[p.i:])
	var b strings.Builder
	for p.i < len(p.s) {
		if strings.HasPrefix(p.s[p.i:], `"""`) {
			p.i += 3
			return b.String(), nil
		}
		c := p.s[p.i]
		if c == '\\' {
			// A backslash before a newline trims the newline and all
			// following whitespace.
			rest := p.s[p.i+1:]
			if t := len(rest) - len(strings.TrimLeft(rest, " \t")); t < len(rest) && (strings.HasPrefix(rest[t:], "\n") || strings.HasPrefix(rest[t:], "\r\n")) {
				p.i++
				for p.i < len(p.s) && (p.s[p.i] == ' ' || p.s[p.i] == '\t' || p.s[p.i] == '\n' || p.s[p.i] == '\r') {
					if p.s[p.i] == '\n' {
						p.line++
					}
					p.i++
				}
				continue
			}
			p.i++
			s, err := p.parseEscape()
			if err != nil {
				return "", err
			}
			b.WriteString(s)
			continue
		}
		if c == '\n' {
			p.line++
		}
		b.WriteByte(c)
		p.i++
	}
	return "", p.errf("unterminated multi-line basic string")
}

func (p *parser) parseLiteralString() (string, error) {
	p.i++ // consume opening quote
	start := p.i
	for p.i < len(p.s) {
		switch p.s[p.i] {
		case '\'':
			out := p.s[start:p.i]
			p.i++
			return out, nil
		case '\n':
			return "", p.errf("newline in literal string")
		}
		p.i++
	}
	return "", p.errf("unterminated literal string")
}

func (p *parser) parseMultilineLiteralString() (string, error) {
	p.i += 3
	p.i += trimLeadingNewline(p.s[p.i:])
	start := p.i
	for p.i < len(p.s) {
		if strings.HasPrefix(p.s[p.i:], `'''`) {
			out := p.s[start:p.i]
			p.i += 3
			return out, nil
		}
		if p.s[p.i] == '\n' {
			p.line++
		}
		p.i++
	}
	return "", p.errf("unterminated multi-line literal string")
}

func (p *parser) parseEscape() (string, error) {
	if p.i >= len(p.s) {
		return "", p.errf("unterminated escape")
	}
	c := p.s[p.i]
	p.i++
	switch c {
	case 'b':
		return "\b", nil
	case 't':
		return "\t", nil
	case 'n':
		return "\n", nil
	case 'f':
		return "\f", nil
	case 'r':
		return "\r", nil
	case '"':
		return `"`, nil
	case '\\':
		return `\`, nil
	case 'u':
		return p.parseUnicodeEscape(4)
	case 'U':
		return p.parseUnicodeEscape(8)
	}
	return "", p.errf("unknown escape %q", string(c))
}

func (p *parser) parseUnicodeEscape(width int) (string, error) {
	if p.i+width > len(p.s) {
		return "", p.errf("truncated unicode escape")
	}
	hex := p.s[p.i : p.i+width]
	n, err := strconv.ParseUint(hex, 16, 32)
	if err != nil {
		return "", p.errf("invalid unicode escape %q", hex)
	}
	p.i += width
	return string(rune(n)), nil
}

// skipInlineSpace advances past spaces and tabs only, stopping at a newline.
func (p *parser) skipInlineSpace() {
	for p.i < len(p.s) && (p.s[p.i] == ' ' || p.s[p.i] == '\t') {
		p.i++
	}
}

// skipSpaceAndComments advances past whitespace (including newlines) and
// whole-line or trailing comments.
func (p *parser) skipSpaceAndComments() {
	for p.i < len(p.s) {
		switch p.s[p.i] {
		case ' ', '\t', '\r':
			p.i++
		case '\n':
			p.line++
			p.i++
		case '#':
			for p.i < len(p.s) && p.s[p.i] != '\n' {
				p.i++
			}
		default:
			return
		}
	}
}

func (p *parser) errf(format string, args ...any) error {
	return fmt.Errorf("toml: line %d: %s", p.line, fmt.Sprintf(format, args...))
}

func isBareKeyChar(c byte) bool {
	return c >= 'a' && c <= 'z' ||
		c >= 'A' && c <= 'Z' ||
		c >= '0' && c <= '9' ||
		c == '_' || c == '-'
}

func trimLeadingNewline(s string) int {
	switch {
	case strings.HasPrefix(s, "\r\n"):
		return 2
	case strings.HasPrefix(s, "\n"):
		return 1
	}
	return 0
}
