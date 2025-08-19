package router_info

import (
	"strconv"
	"strings"
	"unicode"
)

// bytesToString converts a byte slice into a string like [1, 2, 3] -> "1, 2, 3"
func bytesToString(bytes []byte) string {
	str := "["
	for i, b := range bytes {
		str += strconv.Itoa(int(b))
		if i < len(bytes)-1 {
			str += ", "
		}
	}
	str += "]"
	return str
}

// cleanString removes non-printable characters from a string.
func cleanString(str string) string {
	text := str
	text = strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return -1
	}, text)
	return strings.TrimSpace(text)
}
