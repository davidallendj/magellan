package util

import "strings"

func TidyJSON(s string) string {
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\t", "")
	s = strings.ReplaceAll(s, "  ", "")
	return strings.ReplaceAll(s, "\"", "'")
}
