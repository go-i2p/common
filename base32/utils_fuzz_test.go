package base32

import (
	"testing"
)

// Fuzz tests for utils.go

func FuzzDecodeString(f *testing.F) {
	f.Add("jbswy3dp")
	f.Add("jbswy3dp====")
	f.Add("")
	f.Add("aaaa")
	f.Add("4oymiquy7qobjgx36tejs35zeqt24qpemsnzgtfeswmrw6csxbkq")
	f.Add("4oymiquy7qobjgx36tejs35zeqt24qpemsnzgtfeswmrw6csxbkq====")
	f.Add("JBSWY3DP")
	f.Add("0189!@#$")

	f.Fuzz(func(t *testing.T, input string) {
		decoded, err := DecodeString(input)
		if err == nil && len(decoded) > 0 {
			reencoded := EncodeToString(decoded)
			redecoded, err2 := DecodeString(reencoded)
			if err2 != nil {
				t.Errorf("round-trip encode→decode failed: %v", err2)
			}
			if len(decoded) != len(redecoded) {
				t.Errorf("round-trip length mismatch: %d != %d",
					len(decoded), len(redecoded))
			}
		}
	})
}

func FuzzDecodeStringNoPadding(f *testing.F) {
	f.Add("jbswy3dp")
	f.Add("")
	f.Add("4oymiquy7qobjgx36tejs35zeqt24qpemsnzgtfeswmrw6csxbkq")
	f.Add("JBSWY3DP")

	f.Fuzz(func(t *testing.T, input string) {
		decoded, err := DecodeStringNoPadding(input)
		if err == nil && len(decoded) > 0 {
			reencoded := EncodeToStringNoPadding(decoded)
			redecoded, err2 := DecodeStringNoPadding(reencoded)
			if err2 != nil {
				t.Errorf("round-trip encode→decode failed: %v", err2)
			}
			if len(decoded) != len(redecoded) {
				t.Errorf("round-trip length mismatch: %d != %d",
					len(decoded), len(redecoded))
			}
		}
	})
}
