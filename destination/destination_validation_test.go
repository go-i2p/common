package destination

import (
	"testing"

	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/keys_and_cert"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Prohibited crypto types
// ============================================================================

func TestProhibitedCryptoTypesRejected(t *testing.T) {
	prohibitedTypes := []struct {
		name       string
		cryptoType int
	}{
		{"MLKEM512_X25519", key_certificate.KEYCERT_CRYPTO_MLKEM512_X25519},
		{"MLKEM768_X25519", key_certificate.KEYCERT_CRYPTO_MLKEM768_X25519},
		{"MLKEM1024_X25519", key_certificate.KEYCERT_CRYPTO_MLKEM1024_X25519},
	}

	for _, tc := range prohibitedTypes {
		t.Run(tc.name+"_via_ReadDestination", func(t *testing.T) {
			data := createDestinationBytesWithCryptoType(t, tc.cryptoType)
			_, _, err := ReadDestination(data)
			require.Error(t, err,
				"ReadDestination should reject prohibited crypto type %d (%s)",
				tc.cryptoType, tc.name)
		})
	}
}

func TestAllowedCryptoTypesAccepted(t *testing.T) {
	allowedTypes := []struct {
		name       string
		cryptoType int
	}{
		{"ElGamal", key_certificate.KEYCERT_CRYPTO_ELG},
		{"X25519", key_certificate.KEYCERT_CRYPTO_X25519},
	}

	for _, tc := range allowedTypes {
		t.Run(tc.name+"_via_ReadDestination", func(t *testing.T) {
			data := createDestinationBytesWithCryptoType(t, tc.cryptoType)
			dest, _, err := ReadDestination(data)
			require.NoError(t, err)
			assert.NotNil(t, dest.KeysAndCert)
		})
	}
}

// ============================================================================
// Prohibited signing types
// ============================================================================

func TestProhibitedSigningTypesRejected(t *testing.T) {
	prohibitedTypes := []struct {
		name    string
		sigType int
	}{
		{"RSA_SHA256_2048", key_certificate.KEYCERT_SIGN_RSA2048},
		{"RSA_SHA384_3072", key_certificate.KEYCERT_SIGN_RSA3072},
		{"RSA_SHA512_4096", key_certificate.KEYCERT_SIGN_RSA4096},
		{"Ed25519ph", key_certificate.KEYCERT_SIGN_ED25519PH},
	}

	for _, tc := range prohibitedTypes {
		t.Run(tc.name+"_via_ReadDestination", func(t *testing.T) {
			data := createDestinationBytesWithSigningType(t, tc.sigType)
			_, _, err := ReadDestination(data)
			require.Error(t, err,
				"ReadDestination should reject prohibited signing type %d (%s)",
				tc.sigType, tc.name)
		})

		t.Run(tc.name+"_via_validateDestinationSigningType", func(t *testing.T) {
			kac := buildKACWithSigningType(t, tc.sigType)
			if kac == nil {
				t.Skipf("cannot construct KeyCertificate with signing type %d", tc.sigType)
			}
			err := validateDestinationKeyTypes(kac)
			require.Error(t, err,
				"validateDestinationKeyTypes should reject signing type %d (%s)",
				tc.sigType, tc.name)
			assert.Contains(t, err.Error(), "not permitted for Destinations")
		})
	}
}

func TestAllowedSigningTypesAccepted(t *testing.T) {
	allowedTypes := []struct {
		name    string
		sigType int
	}{
		{"DSA_SHA1", key_certificate.KEYCERT_SIGN_DSA_SHA1},
		{"ECDSA_P256", key_certificate.KEYCERT_SIGN_P256},
		{"ECDSA_P384", key_certificate.KEYCERT_SIGN_P384},
		{"Ed25519", key_certificate.KEYCERT_SIGN_ED25519},
		{"RedDSA_Ed25519", key_certificate.KEYCERT_SIGN_REDDSA_ED25519},
	}

	for _, tc := range allowedTypes {
		t.Run(tc.name+"_via_ReadDestination", func(t *testing.T) {
			data := createDestinationBytesWithSigningType(t, tc.sigType)
			dest, _, err := ReadDestination(data)
			require.NoError(t, err,
				"ReadDestination should accept signing type %d (%s)",
				tc.sigType, tc.name)
			assert.NotNil(t, dest.KeysAndCert)
		})
	}
}

// ============================================================================
// validateDestinationKeyTypes – direct tests
// ============================================================================

func TestValidateDestinationKeyTypesDirect(t *testing.T) {
	t.Run("nil KeysAndCert passes", func(t *testing.T) {
		err := validateDestinationKeyTypes(nil)
		assert.NoError(t, err)
	})

	t.Run("MLKEM types rejected", func(t *testing.T) {
		for _, ct := range []int{
			key_certificate.KEYCERT_CRYPTO_MLKEM512_X25519,
			key_certificate.KEYCERT_CRYPTO_MLKEM768_X25519,
			key_certificate.KEYCERT_CRYPTO_MLKEM1024_X25519,
		} {
			keyCert, err := key_certificate.NewKeyCertificateWithTypes(
				key_certificate.KEYCERT_SIGN_DSA_SHA1,
				ct,
			)
			if err != nil {
				t.Skipf("cannot construct KeyCertificate with crypto type %d: %v", ct, err)
			}
			kac := &keys_and_cert.KeysAndCert{KeyCertificate: keyCert}
			err = validateDestinationKeyTypes(kac)
			require.Error(t, err, "crypto type %d should be rejected", ct)
			assert.Contains(t, err.Error(), "not permitted for Destinations")
		}
	})
}

func TestValidateDestinationSigningTypeDirect(t *testing.T) {
	t.Run("RSA types rejected", func(t *testing.T) {
		for _, st := range []int{
			key_certificate.KEYCERT_SIGN_RSA2048,
			key_certificate.KEYCERT_SIGN_RSA3072,
			key_certificate.KEYCERT_SIGN_RSA4096,
		} {
			kac := buildKACWithSigningType(t, st)
			if kac == nil {
				continue
			}
			err := validateDestinationKeyTypes(kac)
			require.Error(t, err, "signing type %d should be rejected", st)
			assert.Contains(t, err.Error(), "RSA")
		}
	})

	t.Run("Ed25519ph rejected", func(t *testing.T) {
		kac := buildKACWithSigningType(t, key_certificate.KEYCERT_SIGN_ED25519PH)
		if kac == nil {
			t.Skip("cannot construct KeyCertificate with Ed25519ph")
		}
		err := validateDestinationKeyTypes(kac)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Ed25519ph")
	})

	t.Run("Ed25519 allowed", func(t *testing.T) {
		kac := buildKACWithSigningType(t, key_certificate.KEYCERT_SIGN_ED25519)
		if kac == nil {
			t.Skip("cannot construct KeyCertificate with Ed25519")
		}
		err := validateDestinationKeyTypes(kac)
		assert.NoError(t, err)
	})
}
