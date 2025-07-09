package router_info

import (
	"strconv"
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
