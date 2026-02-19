package signature

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func FuzzReadSignature(f *testing.F) {
	sigTypes := []int{
		SIGNATURE_TYPE_DSA_SHA1, SIGNATURE_TYPE_ECDSA_SHA256_P256,
		SIGNATURE_TYPE_ECDSA_SHA384_P384, SIGNATURE_TYPE_ECDSA_SHA512_P521,
		SIGNATURE_TYPE_RSA_SHA256_2048, SIGNATURE_TYPE_RSA_SHA384_3072,
		SIGNATURE_TYPE_RSA_SHA512_4096, SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
		SIGNATURE_TYPE_EDDSA_SHA512_ED25519PH, SIGNATURE_TYPE_REDDSA_SHA512_ED25519,
	}

	for _, st := range sigTypes {
		size, _ := getSignatureLength(st)
		data := make([]byte, size)
		f.Add(data, st)
		if size > 0 {
			f.Add(data[:size/2], st)
		}
	}
	f.Add([]byte{}, 0)
	f.Add([]byte{}, -1)
	f.Add([]byte{}, 1000)
	f.Add([]byte(nil), 7)

	f.Fuzz(func(t *testing.T, data []byte, sigType int) {
		sig, remainder, err := ReadSignature(data, sigType)
		if err != nil {
			assert.Equal(t, 0, sig.Len())
			return
		}

		assert.Equal(t, len(data), sig.Len()+len(remainder),
			fmt.Sprintf("sig.Len()=%d + remainder=%d should equal input=%d",
				sig.Len(), len(remainder), len(data)))
		assert.Equal(t, sigType, sig.Type())

		err = sig.Validate()
		assert.NoError(t, err)
	})
}
