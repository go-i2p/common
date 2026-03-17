package data

import (
	"testing"
)

func FuzzI2PString(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00})                          // zero-length string
	f.Add([]byte{0x05, 'h', 'e', 'l', 'l', 'o'}) // valid 5-byte string
	f.Add([]byte{0xff})                          // max length byte, no data

	f.Fuzz(func(t *testing.T, data []byte) {
		str := I2PString(data)
		str.Data()
		str.Length()
	})
}

func FuzzToI2PString(f *testing.F) {
	f.Add("")
	f.Add("hello")
	f.Add("a]b")

	f.Fuzz(func(t *testing.T, input string) {
		str, err := ToI2PString(input)
		if err == nil {
			str.Data()
			str.Length()
		}
	})
}
