package router_identity

import (
	"testing"

	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/keys_and_cert"
	"github.com/stretchr/testify/assert"
)

// FuzzNewRouterIdentityFromKeysAndCert fuzzes the constructor via KeysAndCert
func FuzzNewRouterIdentityFromKeysAndCert(f *testing.F) {
	seed := buildRouterIdentityBytes(&testing.T{},
		key_certificate.KEYCERT_SIGN_ED25519,
		key_certificate.KEYCERT_CRYPTO_X25519,
	)
	f.Add(seed)

	f.Fuzz(func(t *testing.T, data []byte) {
		kac, _, err := keys_and_cert.ReadKeysAndCert(data)
		if err != nil {
			return
		}
		ri, err := NewRouterIdentityFromKeysAndCert(kac)
		if err != nil {
			return
		}
		assert.True(t, ri.IsValid())
		assert.NotNil(t, ri.KeysAndCert)
	})
}

// FuzzNewRouterIdentityFromBytes fuzzes the byte parser
func FuzzNewRouterIdentityFromBytes(f *testing.F) {
	seed := buildRouterIdentityBytes(&testing.T{},
		key_certificate.KEYCERT_SIGN_ED25519,
		key_certificate.KEYCERT_CRYPTO_X25519,
	)
	f.Add(seed)

	f.Fuzz(func(t *testing.T, data []byte) {
		ri, _, err := NewRouterIdentityFromBytes(data)
		if err != nil {
			return
		}
		assert.True(t, ri.IsValid())
		assert.NotNil(t, ri.KeysAndCert)
	})
}
