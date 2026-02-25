package router_identity

import (
	"testing"

	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/keys_and_cert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//
// Key type restriction validation tests
//

// TestDisallowedSigningKeyTypes verifies that disallowed signing types are rejected
func TestDisallowedSigningKeyTypes(t *testing.T) {
	t.Run("RedDSA via ReadRouterIdentity", func(t *testing.T) {
		wireData := buildRouterIdentityBytes(t,
			key_certificate.KEYCERT_SIGN_REDDSA_ED25519,
			key_certificate.KEYCERT_CRYPTO_X25519,
		)
		ri, _, err := ReadRouterIdentity(wireData)
		require.Error(t, err)
		assert.Nil(t, ri)
		assert.Contains(t, err.Error(), "not permitted for Router Identities")
	})

	t.Run("RedDSA via NewRouterIdentityFromKeysAndCert", func(t *testing.T) {
		kac := buildKeysAndCertForTypes(t,
			key_certificate.KEYCERT_SIGN_REDDSA_ED25519,
			key_certificate.KEYCERT_CRYPTO_X25519,
		)
		ri, err := NewRouterIdentityFromKeysAndCert(kac)
		require.Error(t, err)
		assert.Nil(t, ri)
		assert.Contains(t, err.Error(), "not permitted for Router Identities")
	})

	t.Run("RSA-2048 via NewRouterIdentityFromKeysAndCert", func(t *testing.T) {
		kac := buildKeysAndCertForTypes(t,
			key_certificate.KEYCERT_SIGN_RSA2048,
			key_certificate.KEYCERT_CRYPTO_X25519,
		)
		ri, err := NewRouterIdentityFromKeysAndCert(kac)
		require.Error(t, err)
		assert.Nil(t, ri)
		assert.Contains(t, err.Error(), "not permitted for Router Identities")
	})

	t.Run("RSA-3072 direct validation", func(t *testing.T) {
		err := validateRouterIdentityKeyTypes(
			buildMinimalKacWithTypes(t, key_certificate.KEYCERT_SIGN_RSA3072, key_certificate.KEYCERT_CRYPTO_ELG),
		)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not permitted for Router Identities")
	})

	t.Run("RSA-4096 direct validation", func(t *testing.T) {
		err := validateRouterIdentityKeyTypes(
			buildMinimalKacWithTypes(t, key_certificate.KEYCERT_SIGN_RSA4096, key_certificate.KEYCERT_CRYPTO_ELG),
		)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not permitted for Router Identities")
	})

	t.Run("Ed25519ph via ReadRouterIdentity", func(t *testing.T) {
		wireData := buildRouterIdentityBytes(t,
			key_certificate.KEYCERT_SIGN_ED25519PH,
			key_certificate.KEYCERT_CRYPTO_X25519,
		)
		ri, _, err := ReadRouterIdentity(wireData)
		require.Error(t, err)
		assert.Nil(t, ri)
		assert.Contains(t, err.Error(), "not permitted for Router Identities")
	})

	t.Run("Ed25519ph via NewRouterIdentityFromKeysAndCert", func(t *testing.T) {
		kac := buildKeysAndCertForTypes(t,
			key_certificate.KEYCERT_SIGN_ED25519PH,
			key_certificate.KEYCERT_CRYPTO_X25519,
		)
		ri, err := NewRouterIdentityFromKeysAndCert(kac)
		require.Error(t, err)
		assert.Nil(t, ri)
		assert.Contains(t, err.Error(), "not permitted for Router Identities")
	})

	t.Run("Ed25519ph direct validation", func(t *testing.T) {
		err := validateRouterIdentityKeyTypes(
			buildMinimalKacWithTypes(t,
				key_certificate.KEYCERT_SIGN_ED25519PH,
				key_certificate.KEYCERT_CRYPTO_X25519,
			),
		)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Ed25519ph")
	})
}

// TestDisallowedCryptoKeyTypes verifies that disallowed crypto types are rejected
func TestDisallowedCryptoKeyTypes(t *testing.T) {
	tests := []struct {
		name       string
		cryptoType int
	}{
		{"MLKEM512_X25519", key_certificate.KEYCERT_CRYPTO_MLKEM512_X25519},
		{"MLKEM768_X25519", key_certificate.KEYCERT_CRYPTO_MLKEM768_X25519},
		{"MLKEM1024_X25519", key_certificate.KEYCERT_CRYPTO_MLKEM1024_X25519},
	}
	for _, tt := range tests {
		t.Run(tt.name+"_via_ReadRouterIdentity", func(t *testing.T) {
			wireData := buildRouterIdentityBytes(t, key_certificate.KEYCERT_SIGN_ED25519, tt.cryptoType)
			ri, _, err := ReadRouterIdentity(wireData)
			require.Error(t, err, "crypto type %d must be rejected", tt.cryptoType)
			assert.Nil(t, ri)
		})
		t.Run(tt.name+"_via_direct_validation", func(t *testing.T) {
			kac := &keys_and_cert.KeysAndCert{}
			keyCert, err := key_certificate.NewKeyCertificateWithTypes(
				key_certificate.KEYCERT_SIGN_ED25519, tt.cryptoType,
			)
			require.NoError(t, err)
			kac.KeyCertificate = keyCert
			err = validateRouterIdentityKeyTypes(kac)
			require.Error(t, err, "crypto type %d must be rejected", tt.cryptoType)
			assert.Contains(t, err.Error(), "not permitted for Router Identities")
		})
	}
}

// TestValidateRejectsNilKeyCertificate verifies nil handling in validation
func TestValidateRejectsNilKeyCertificate(t *testing.T) {
	t.Run("nil kac rejected", func(t *testing.T) {
		err := validateRouterIdentityKeyTypes(nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot be nil")
	})

	t.Run("nil key certificate rejected", func(t *testing.T) {
		kac := &keys_and_cert.KeysAndCert{KeyCertificate: nil}
		err := validateRouterIdentityKeyTypes(kac)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "KeyCertificate is nil")
	})
}

// TestValidate_RejectsProhibitedKeyTypes verifies that Validate() enforces
// RouterIdentity-specific key type restrictions, not just KeysAndCert validity.
func TestValidate_RejectsProhibitedKeyTypes(t *testing.T) {
	t.Run("RedDSA signing type rejected by Validate", func(t *testing.T) {
		kac := buildKeysAndCertForTypes(t,
			key_certificate.KEYCERT_SIGN_REDDSA_ED25519,
			key_certificate.KEYCERT_CRYPTO_X25519,
		)
		ri := &RouterIdentity{KeysAndCert: kac}

		err := ri.Validate()
		require.Error(t, err, "Validate() must reject RedDSA signing type")
		assert.Contains(t, err.Error(), "not permitted for Router Identities")
	})

	t.Run("Ed25519ph signing type rejected by Validate", func(t *testing.T) {
		kac := buildKeysAndCertForTypes(t,
			key_certificate.KEYCERT_SIGN_ED25519PH,
			key_certificate.KEYCERT_CRYPTO_X25519,
		)
		ri := &RouterIdentity{KeysAndCert: kac}

		err := ri.Validate()
		require.Error(t, err, "Validate() must reject Ed25519ph signing type")
		assert.Contains(t, err.Error(), "not permitted for Router Identities")
	})

	t.Run("RSA-2048 signing type rejected by Validate", func(t *testing.T) {
		kac := buildKeysAndCertForTypes(t,
			key_certificate.KEYCERT_SIGN_RSA2048,
			key_certificate.KEYCERT_CRYPTO_X25519,
		)
		ri := &RouterIdentity{KeysAndCert: kac}

		err := ri.Validate()
		require.Error(t, err, "Validate() must reject RSA-2048 signing type")
		assert.Contains(t, err.Error(), "not permitted for Router Identities")
	})

	t.Run("MLKEM512_X25519 crypto type rejected by Validate", func(t *testing.T) {
		// Use buildKeysAndCertForTypes so padding is computed correctly (384-32-32=320)
		// and kac.Validate() passes; Validate() must then reject on type grounds.
		kac := buildKeysAndCertForTypes(t,
			key_certificate.KEYCERT_SIGN_ED25519,
			key_certificate.KEYCERT_CRYPTO_MLKEM512_X25519,
		)
		ri := &RouterIdentity{KeysAndCert: kac}

		err := ri.Validate()
		require.Error(t, err, "Validate() must reject MLKEM512_X25519 crypto type")
		assert.Contains(t, err.Error(), "not permitted for Router Identities")
	})

	t.Run("Ed25519/X25519 accepted by Validate", func(t *testing.T) {
		kac := buildKeysAndCertForTypes(t,
			key_certificate.KEYCERT_SIGN_ED25519,
			key_certificate.KEYCERT_CRYPTO_X25519,
		)
		ri := &RouterIdentity{KeysAndCert: kac}

		err := ri.Validate()
		assert.NoError(t, err, "Ed25519/X25519 should be accepted")
	})

	t.Run("DSA-SHA1/ElGamal accepted by Validate (deprecated but valid)", func(t *testing.T) {
		kac := createValidKeysAndCert(t) // uses DSA-SHA1/ElGamal
		ri := &RouterIdentity{KeysAndCert: kac}

		err := ri.Validate()
		assert.NoError(t, err, "Deprecated DSA-SHA1/ElGamal should still be accepted")
	})

	t.Run("IsValid reflects Validate key type enforcement", func(t *testing.T) {
		kac := buildKeysAndCertForTypes(t,
			key_certificate.KEYCERT_SIGN_REDDSA_ED25519,
			key_certificate.KEYCERT_CRYPTO_X25519,
		)
		ri := &RouterIdentity{KeysAndCert: kac}
		assert.False(t, ri.IsValid(), "IsValid must return false for prohibited key types")
	})
}

// TestAsDestination_DestinationKeyTypeValidation verifies that AsDestination
// returns a Destination that can be validated by the Destination's own Validate().
func TestAsDestination_DestinationKeyTypeValidation(t *testing.T) {
	t.Run("Ed25519/X25519 passes Destination validation", func(t *testing.T) {
		kac := buildKeysAndCertForTypes(t,
			key_certificate.KEYCERT_SIGN_ED25519,
			key_certificate.KEYCERT_CRYPTO_X25519,
		)
		ri, err := NewRouterIdentityFromKeysAndCert(kac)
		require.NoError(t, err)

		dest := ri.AsDestination()
		err = dest.Validate()
		assert.NoError(t, err, "Ed25519/X25519 should pass Destination validation")
	})

	t.Run("DSA-SHA1/ElGamal passes Destination validation", func(t *testing.T) {
		kac := createValidKeysAndCert(t) // DSA-SHA1/ElGamal
		ri, err := NewRouterIdentityFromKeysAndCert(kac)
		require.NoError(t, err)

		dest := ri.AsDestination()
		err = dest.Validate()
		assert.NoError(t, err, "DSA-SHA1/ElGamal should pass Destination validation")
	})
}
