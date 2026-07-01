// Package xmlparse implements a lenient XML parser for FortiGate server
// responses, which may contain malformed XML that strict parsers reject.
package xmlparse

import (
	"fmt"
	"strings"
)

// Find searches buf for a tag (t='<') or attribute (t=' ') named needle,
// respecting up to nest levels of nesting. Returns the string immediately
// following needle, or "" if not found.
//
// This mirrors the C xml_find() function: it intentionally ignores CDATA and
// does not handle strings containing '<' or '/', matching FortiGate behavior.
func Find(t byte, needle, buf string, nest int) string {
	if buf == "" {
		return ""
	}
	for i := 0; i < len(buf); i++ {
		if buf[i] == '<' && i+1 < len(buf) && buf[i+1] != '/' {
			nest++
		}
		if buf[i] == '/' {
			nest--
		}
		if nest <= 0 {
			return ""
		}
		search := string(t) + needle
		if strings.HasPrefix(buf[i:], search) {
			return buf[i+len(search):]
		}
	}
	return ""
}

// Get extracts a quoted attribute value from buf. The first character of buf
// is used as the quote character. Returns the value and nil on success, or
// an error if the value cannot be extracted. Values longer than 255 characters
// are truncated to match the C implementation's MAX_DOMAIN_LENGTH behavior.
func Get(buf string) (string, error) {
	if buf == "" {
		return "", fmt.Errorf("xmlparse: empty buffer")
	}
	quote := buf[0]
	if quote == 0 {
		return "", fmt.Errorf("xmlparse: short read getting attribute value")
	}
	end := strings.IndexByte(buf[1:], quote)
	if end == -1 {
		return "", fmt.Errorf("xmlparse: could not find closing quote %q", quote)
	}
	val := buf[1 : 1+end]
	if len(val) > 255 {
		val = val[:255]
	}
	return val, nil
}
