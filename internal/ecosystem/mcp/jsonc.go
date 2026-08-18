package mcp

// JSONC support.
//
// VS Code and every editor that inherited its config format write MCP
// configs as JSON with comments: `.vscode/mcp.json`, Kiro's
// `.kiro/settings/mcp.json`, GitLab Duo's `.gitlab/duo/mcp.json`. The
// files are commented by default — the templates those tools generate
// ship with `//` lines in them — so strict encoding/json rejects them
// and the MCP server inventory silently comes back empty on exactly the
// machines that have the most MCP servers configured.
//
// Trailing commas are accepted for the same reason: they are legal in
// JSONC, editors write them, and a human editing one of these files by
// hand leaves them behind.

// stripJSONC rewrites JSONC into JSON that encoding/json will accept:
// comments and trailing commas are replaced with spaces.
//
// Comment bytes are overwritten with spaces rather than deleted, and
// newlines inside block comments are preserved, so byte offsets and line
// numbers in any resulting parse error still point at the original file.
//
// String contents are never touched. That is the whole difficulty here:
// an MCP config is full of URLs, and a naive scan for "//" would corrupt
// every "https://..." in the file.
func stripJSONC(data []byte) []byte {
	out := make([]byte, len(data))
	copy(out, data)

	const (
		normal = iota
		inString
		inLine
		inBlock
	)
	state := normal
	escaped := false

	for i := 0; i < len(out); i++ {
		c := out[i]
		switch state {
		case normal:
			switch {
			case c == '"':
				state = inString
			case c == '/' && i+1 < len(out) && out[i+1] == '/':
				out[i], out[i+1] = ' ', ' '
				i++
				state = inLine
			case c == '/' && i+1 < len(out) && out[i+1] == '*':
				out[i], out[i+1] = ' ', ' '
				i++
				state = inBlock
			}
		case inString:
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				state = normal
			}
		case inLine:
			if c == '\n' {
				state = normal
			} else {
				out[i] = ' '
			}
		case inBlock:
			if c == '*' && i+1 < len(out) && out[i+1] == '/' {
				out[i], out[i+1] = ' ', ' '
				i++
				state = normal
			} else if c != '\n' {
				// Keep newlines so line numbers survive.
				out[i] = ' '
			}
		}
	}

	return stripTrailingCommas(out)
}

// stripTrailingCommas blanks any comma whose next non-space character
// closes an object or array. Run after comment removal, so a comma
// separated from its brace only by a comment is still caught.
func stripTrailingCommas(data []byte) []byte {
	inStr := false
	escaped := false
	for i := 0; i < len(data); i++ {
		c := data[i]
		switch {
		case inStr:
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inStr = false
			}
		case c == '"':
			inStr = true
		case c == ',':
			for j := i + 1; j < len(data); j++ {
				switch data[j] {
				case ' ', '\t', '\r', '\n':
					continue
				case '}', ']':
					data[i] = ' '
				}
				break
			}
		}
	}
	return data
}
