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
		// ECDSA_P521 (type 3) is omitted: its 132-byte signing key exceeds
		// the 128-byte inline SPK field in KeysAndCert, requiring excess key
		// data reconstruction not yet implemented upstream.
		// See TestAllowedSigningTypesAccepted_P521Excluded below.
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

func TestAllowedSigningTypesAccepted_P521Excluded(t *testing.T) {
	// ECDSA_P521 (type 3) signing keys are 132 bytes, which exceeds the
	// 128-byte inline SPK field in KeysAndCert. This requires excess signing
	// key data reconstruction in the certificate payload, which is not yet
	// implemented in keys_and_cert.ReadKeysAndCert(). The type is spec-valid
	// for destinations but cannot be parsed end-to-end.
	//
	// See also: TestExcessKeyDataInCertificate in destination_struct_unit_test.go
	data := createDestinationBytesWithExcessSigningKey(t,
		key_certificate.KEYCERT_SIGN_P521, 4)
	_, _, err := ReadDestination(data)
	if err == nil {
		t.Log("ECDSA_P521 parsing succeeded — upstream keys_and_cert may have been fixed; add to TestAllowedSigningTypesAccepted")
	} else {
		t.Skipf("ECDSA_P521 parsing still fails due to upstream keys_and_cert limitation: %v", err)
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

// ============================================================================
// Validate() enforces destination-specific key type constraints
// Regression test: a directly-constructed Destination with prohibited key types
// must fail Validate() and IsValid().
// ============================================================================

func TestValidate_RejectsProhibitedKeyTypes(t *testing.T) {
	t.Run("MLKEM512_X25519 crypto type rejected by Validate", func(t *testing.T) {
		keyCert, err := key_certificate.NewKeyCertificateWithTypes(
			key_certificate.KEYCERT_SIGN_DSA_SHA1,
			key_certificate.KEYCERT_CRYPTO_MLKEM512_X25519,
		)
		if err != nil {
			t.Skipf("cannot construct KeyCertificate with MLKEM512: %v", err)
		}
		kac := &keys_and_cert.KeysAndCert{KeyCertificate: keyCert}
		dest := &Destination{KeysAndCert: kac}

		err = dest.Validate()
		require.Error(t, err, "Validate() should reject MLKEM512_X25519 crypto type")
	})

	t.Run("MLKEM768_X25519 crypto type rejected by Validate", func(t *testing.T) {
		keyCert, err := key_certificate.NewKeyCertificateWithTypes(
			key_certificate.KEYCERT_SIGN_DSA_SHA1,
			key_certificate.KEYCERT_CRYPTO_MLKEM768_X25519,
		)
		if err != nil {
			t.Skipf("cannot construct KeyCertificate with MLKEM768: %v", err)
		}
		kac := &keys_and_cert.KeysAndCert{KeyCertificate: keyCert}
		dest := &Destination{KeysAndCert: kac}

		err = dest.Validate()
		require.Error(t, err, "Validate() should reject MLKEM768_X25519 crypto type")
	})

	t.Run("MLKEM1024_X25519 crypto type rejected by Validate", func(t *testing.T) {
		keyCert, err := key_certificate.NewKeyCertificateWithTypes(
			key_certificate.KEYCERT_SIGN_DSA_SHA1,
			key_certificate.KEYCERT_CRYPTO_MLKEM1024_X25519,
		)
		if err != nil {
			t.Skipf("cannot construct KeyCertificate with MLKEM1024: %v", err)
		}
		kac := &keys_and_cert.KeysAndCert{KeyCertificate: keyCert}
		dest := &Destination{KeysAndCert: kac}

		err = dest.Validate()
		require.Error(t, err, "Validate() should reject MLKEM1024_X25519 crypto type")
	})

	t.Run("RSA_SHA256_2048 signing type rejected by Validate", func(t *testing.T) {
		data := createDestinationBytesWithSigningType(t, key_certificate.KEYCERT_SIGN_RSA2048)
		kac, _, err := keys_and_cert.ReadKeysAndCert(data)
		if err != nil {
			t.Skipf("cannot parse RSA2048 KeysAndCert: %v", err)
		}
		dest := &Destination{KeysAndCert: kac}

		err = dest.Validate()
		require.Error(t, err, "Validate() should reject RSA_SHA256_2048 signing type")
		assert.Contains(t, err.Error(), "not permitted for Destinations")
	})

	t.Run("RSA_SHA384_3072 signing type rejected by Validate", func(t *testing.T) {
		data := createDestinationBytesWithSigningType(t, key_certificate.KEYCERT_SIGN_RSA3072)
		kac, _, err := keys_and_cert.ReadKeysAndCert(data)
		if err != nil {
			t.Skipf("cannot parse RSA3072 KeysAndCert: %v", err)
		}
		dest := &Destination{KeysAndCert: kac}

		err = dest.Validate()
		require.Error(t, err, "Validate() should reject RSA_SHA384_3072 signing type")
		assert.Contains(t, err.Error(), "not permitted for Destinations")
	})

	t.Run("RSA_SHA512_4096 signing type rejected by Validate", func(t *testing.T) {
		data := createDestinationBytesWithSigningType(t, key_certificate.KEYCERT_SIGN_RSA4096)
		kac, _, err := keys_and_cert.ReadKeysAndCert(data)
		if err != nil {
			t.Skipf("cannot parse RSA4096 KeysAndCert: %v", err)
		}
		dest := &Destination{KeysAndCert: kac}

		err = dest.Validate()
		require.Error(t, err, "Validate() should reject RSA_SHA512_4096 signing type")
		assert.Contains(t, err.Error(), "not permitted for Destinations")
	})

	t.Run("Ed25519ph signing type rejected by Validate", func(t *testing.T) {
		data := createDestinationBytesWithSigningType(t, key_certificate.KEYCERT_SIGN_ED25519PH)
		kac, _, err := keys_and_cert.ReadKeysAndCert(data)
		if err != nil {
			t.Skipf("cannot parse Ed25519ph KeysAndCert: %v", err)
		}
		dest := &Destination{KeysAndCert: kac}

		err = dest.Validate()
		require.Error(t, err, "Validate() should reject Ed25519ph signing type")
		assert.Contains(t, err.Error(), "not permitted for Destinations")
	})

	t.Run("valid Ed25519 type accepted by Validate", func(t *testing.T) {
		data := createEd25519X25519DestinationBytes(t)
		dest, _, err := ReadDestination(data)
		require.NoError(t, err)

		err = (&dest).Validate()
		assert.NoError(t, err, "Validate() should accept Ed25519/X25519 destinations")
		assert.True(t, (&dest).IsValid())
	})

	t.Run("valid DSA/ElGamal type accepted by Validate", func(t *testing.T) {
		data := createValidDestinationBytes(t)
		dest, _, err := ReadDestination(data)
		require.NoError(t, err)

		err = (&dest).Validate()
		assert.NoError(t, err, "Validate() should accept DSA/ElGamal destinations")
	})
}
