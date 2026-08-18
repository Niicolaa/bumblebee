// Package toml provides a deliberately restricted TOML reader for the
// subset of the format that dependency lockfiles actually use.
//
// Why not a full TOML parser: bumblebee has zero non-stdlib dependencies
// and the stdlib has no TOML support. Every lockfile this package needs
// to read (Cargo.lock, poetry.lock, uv.lock, pylock.toml) uses the same
// narrow shape — arrays of tables holding flat scalar and string-array
// values:
//
//	[[package]]
//	name = "serde"
//	version = "1.0.203"
//	dependencies = ["serde_derive"]
//
// The reader therefore supports: comments, bare and quoted keys, basic
// and literal strings (single-line, with standard escapes), integers,
// booleans, inline arrays of strings (single- and multi-line), tables,
// and arrays of tables. It does NOT support inline tables, multi-line
// basic strings, dotted keys in assignments, dates, or floats.
//
// Constructs outside the subset are never silently dropped: structural
// damage (a malformed header, an assignment with no `=`) is a hard
// error, and an unmodelled *value* is recorded as KindUnsupported with
// its raw text so a caller that needs that key can fail loudly while a
// caller that does not is unaffected. A parser that quietly skipped
// either would turn into a missed package, which in an exposure scan
// reads as "this machine is clean".
package toml

import (
	"bufio"
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

// Value is a parsed scalar or string array. Exactly one of the fields is
// meaningful, per Kind. KindUnsupported carries the raw source text of a
// construct outside the supported subset.
type Value struct {
	Kind    Kind
	Str     string
	Int     int64
	Bool    bool
	Strings []string
	Raw     string
}

type Kind int

const (
	KindString Kind = iota
	KindInt
	KindBool
	KindStrings
	// KindUnsupported marks a value whose syntax is outside the subset
	// (inline tables, arrays of inline tables, multi-line strings).
	// These are recorded rather than dropped or fatal: poetry.lock's
	// per-package `files = [{file = ..., hash = ...}]` would otherwise
	// make every poetry.lock unreadable, when the `name` and `version`
	// on the same table parse perfectly well. A caller that needs an
	// unsupported key sees KindUnsupported and can fail loudly; a caller
	// that does not is unaffected. What never happens is a value being
	// silently discarded as if the key were absent.
	KindUnsupported
)

// Table is one [table] or [[array of tables]] entry: a flat key/value map
// plus the header name it appeared under.
type Table struct {
	Name   string
	Values map[string]Value
}

// String returns the string value for key, or "" if absent or not a string.
func (t Table) String(key string) string {
	v, ok := t.Values[key]
	if !ok || v.Kind != KindString {
		return ""
	}
	return v.Str
}

// Document is the parsed file: the root table plus every [table] and
// [[array-of-tables]] entry in source order.
type Document struct {
	Root   map[string]Value
	Tables []Table
}

// TablesNamed returns every table whose header matches name, in source
// order. Array-of-table entries share a name by definition.
func (d *Document) TablesNamed(name string) []Table {
	var out []Table
	for _, t := range d.Tables {
		if t.Name == name {
			out = append(out, t)
		}
	}
	return out
}

// Parse reads a restricted-TOML document. It returns an error on any
// construct outside the documented subset.
func Parse(data []byte) (*Document, error) {
	doc := &Document{Root: map[string]Value{}}
	cur := doc.Root

	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(stripComment(sc.Text()))
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "[") {
			name, err := parseHeader(line)
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", lineNo, err)
			}
			doc.Tables = append(doc.Tables, Table{Name: name, Values: map[string]Value{}})
			cur = doc.Tables[len(doc.Tables)-1].Values
			continue
		}

		key, rest, quoted, ok := splitKeyValue(line)
		if !ok {
			return nil, fmt.Errorf("line %d: not a key/value assignment: %q", lineNo, line)
		}
		// Only BARE keys may not contain dots. A quoted key is a single
		// literal key even when it contains them, and Cargo.lock v1 relies
		// on that in its [metadata] table:
		//
		//   "checksum foo 1.0.1 (registry+https://...)" = "<sha256>"
		//
		// Rejecting those dropped every v1 Cargo.lock outright.
		if !quoted && strings.Contains(key, ".") {
			return nil, fmt.Errorf("line %d: dotted keys are not supported: %q", lineNo, key)
		}

		// A multi-line array continues until the bracket that opened it
		// is closed. Depth has to be tracked rather than stopping at the
		// first "]": uv.lock writes
		//
		//	dependencies = [
		//	    { name = "pydantic", extra = ["email"] },
		//	    { name = "httpx" },
		//	]
		//
		// where the first entry closes an INNER bracket. Stopping there
		// left the remaining entries to be parsed as top-level
		// assignments, which failed on `{ name` and rejected the whole
		// lockfile — silently dropping every package in it.
		if depth := bracketDepth(rest); depth > 0 {
			var b strings.Builder
			b.WriteString(rest)
			closed := false
			for sc.Scan() {
				lineNo++
				chunk := strings.TrimSpace(stripComment(sc.Text()))
				b.WriteString(" ")
				b.WriteString(chunk)
				depth += bracketDepth(chunk)
				if depth <= 0 {
					closed = true
					break
				}
			}
			if !closed {
				return nil, fmt.Errorf("line %d: unterminated array for key %q", lineNo, key)
			}
			rest = b.String()
		}

		v, err := parseValue(rest)
		if err != nil {
			return nil, fmt.Errorf("line %d: key %q: %w", lineNo, key, err)
		}
		cur[key] = v
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return doc, nil
}

// parseHeader reads a [table] or [[array of tables]] header and returns
// its name. Dotted headers keep their literal dotted name ("package.
// dependencies" stays distinct from "package"), so TablesNamed("package")
// returns only the real package tables and never their sub-tables.
func parseHeader(line string) (string, error) {
	switch {
	case strings.HasPrefix(line, "[["):
		if !strings.HasSuffix(line, "]]") {
			return "", fmt.Errorf("malformed array-of-tables header: %q", line)
		}
		return strings.TrimSpace(line[2 : len(line)-2]), nil
	case strings.HasSuffix(line, "]"):
		return strings.TrimSpace(line[1 : len(line)-1]), nil
	default:
		return "", fmt.Errorf("malformed table header: %q", line)
	}
}

func splitKeyValue(line string) (key, rest string, quoted, ok bool) {
	i := indexUnquoted(line, '=')
	if i < 0 {
		return "", "", false, false
	}
	key = strings.TrimSpace(line[:i])
	rest = strings.TrimSpace(line[i+1:])
	if key == "" || rest == "" {
		return "", "", false, false
	}
	if unq, wasQuoted := unquote(key); wasQuoted {
		return unq, rest, true, true
	}
	return key, rest, false, true
}

func parseValue(s string) (Value, error) {
	switch {
	case strings.HasPrefix(s, `"""`), strings.HasPrefix(s, "'''"):
		return Value{Kind: KindUnsupported, Raw: s}, nil
	case strings.HasPrefix(s, "{"):
		return Value{Kind: KindUnsupported, Raw: s}, nil
	case strings.HasPrefix(s, "["):
		items, err := parseStringArray(s)
		if err != nil {
			// Arrays of inline tables and other shapes we do not model.
			return Value{Kind: KindUnsupported, Raw: s}, nil
		}
		return Value{Kind: KindStrings, Strings: items}, nil
	case strings.HasPrefix(s, `"`), strings.HasPrefix(s, "'"):
		str, ok := unquote(s)
		if !ok {
			return Value{}, fmt.Errorf("unterminated string: %q", s)
		}
		return Value{Kind: KindString, Str: str}, nil
	case s == "true", s == "false":
		return Value{Kind: KindBool, Bool: s == "true"}, nil
	default:
		n, err := strconv.ParseInt(strings.ReplaceAll(s, "_", ""), 10, 64)
		if err != nil {
			// Dates, floats, and anything else we do not model. Recorded,
			// not dropped.
			return Value{Kind: KindUnsupported, Raw: s}, nil
		}
		return Value{Kind: KindInt, Int: n}, nil
	}
}

// parseStringArray reads an array of strings. Arrays of inline tables
// (poetry's `files = [{file = "...", hash = "..."}]`) are rejected
// rather than guessed at; callers that do not need the key can ignore
// the error for that key alone.
func parseStringArray(s string) ([]string, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "[") {
		return nil, fmt.Errorf("not an array: %q", s)
	}
	end := strings.LastIndex(s, "]")
	if end < 0 {
		return nil, fmt.Errorf("unterminated array: %q", s)
	}
	body := strings.TrimSpace(s[1:end])
	if body == "" {
		return nil, nil
	}
	if strings.Contains(body, "{") {
		return nil, fmt.Errorf("arrays of inline tables are not supported")
	}
	var out []string
	for _, part := range splitTopLevel(body, ',') {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		str, ok := unquote(part)
		if !ok {
			return nil, fmt.Errorf("array element is not a string: %q", part)
		}
		out = append(out, str)
	}
	return out, nil
}

// splitTopLevel splits on sep, ignoring separators inside quotes.
func splitTopLevel(s string, sep rune) []string {
	var out []string
	var cur strings.Builder
	var quote rune
	escaped := false
	for _, r := range s {
		switch {
		case escaped:
			escaped = false
			cur.WriteRune(r)
		case quote == '"' && r == '\\':
			escaped = true
			cur.WriteRune(r)
		case quote != 0:
			if r == quote {
				quote = 0
			}
			cur.WriteRune(r)
		case r == '"' || r == '\'':
			quote = r
			cur.WriteRune(r)
		case r == sep:
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	out = append(out, cur.String())
	return out
}

// indexUnquoted returns the index of the first c outside a quoted span.
func indexUnquoted(s string, c byte) int {
	var quote byte
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case quote == '"' && ch == '\\':
			i++
		case quote != 0:
			if ch == quote {
				quote = 0
			}
		case ch == '"' || ch == '\'':
			quote = ch
		case ch == c:
			return i
		}
	}
	return -1
}

// bracketDepth returns the net change in [ ] nesting across s, ignoring
// brackets inside quoted strings. A positive result means the line left
// an array open.
func bracketDepth(s string) int {
	depth := 0
	var quote byte
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case quote == '"' && ch == '\\':
			i++
		case quote != 0:
			if ch == quote {
				quote = 0
			}
		case ch == '"' || ch == '\'':
			quote = ch
		case ch == '[':
			depth++
		case ch == ']':
			depth--
		}
	}
	return depth
}

// stripComment removes a trailing # comment that is not inside a string.
func stripComment(line string) string {
	if i := indexUnquoted(line, '#'); i >= 0 {
		return line[:i]
	}
	return line
}

// unquote reads a basic ("...") or literal ('...') single-line string.
// Literal strings take no escapes, which is what makes them the safe way
// to write Windows paths in TOML.
func unquote(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if len(s) < 2 {
		return s, false
	}
	switch s[0] {
	case '\'':
		if s[len(s)-1] != '\'' {
			return s, false
		}
		return s[1 : len(s)-1], true
	case '"':
		if s[len(s)-1] != '"' {
			return s, false
		}
		return unescape(s[1 : len(s)-1]), true
	}
	return s, false
}

func unescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		i++
		switch s[i] {
		case 'n':
			b.WriteByte('\n')
		case 't':
			b.WriteByte('\t')
		case 'r':
			b.WriteByte('\r')
		case '"':
			b.WriteByte('"')
		case '\\':
			b.WriteByte('\\')
		default:
			// Leave unknown escapes (including \uXXXX) as written. Package
			// names and versions are ASCII in every ecosystem here, so this
			// only affects fields we do not emit.
			b.WriteByte('\\')
			b.WriteByte(s[i])
		}
	}
	return b.String()
}
