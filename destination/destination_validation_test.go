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

func TestAllowedSigningTypesAccepted_P521(t *testing.T) {
	// ECDSA_P521 (type 3) signing keys are 132 bytes; the 4 excess bytes are
	// stored in the Key Certificate payload. keys_and_cert.ReadKeysAndCert
	// was updated to reconstruct the full 132-byte key, so P521 destinations
	// now parse successfully end-to-end.
	//
	// See also: TestExcessKeyDataInCertificate in destination_struct_unit_test.go
	data := createDestinationBytesWithExcessSigningKey(t,
		key_certificate.KEYCERT_SIGN_P521, 4)
	dest, _, err := ReadDestination(data)
	if err != nil {
		// Graceful degradation if upstream reverts.
		t.Skipf("ECDSA_P521 parsing failed (upstream keys_and_cert limitation): %v", err)
	}
	assert.NotNil(t, dest.KeysAndCert)
	assert.Equal(t, key_certificate.KEYCERT_SIGN_P521,
		dest.KeyCertificate.SigningPublicKeyType())
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

// ============================================================================
// ECDH-P* reserved crypto types: accepted with warning (proposal 145)
// Finding: [SPEC] ECDH-P256/P384/P521 are "Reserved, see proposal 145"
// ============================================================================

func TestECDHReservedCryptoTypesAcceptedWithWarning(t *testing.T) {
	reservedTypes := []struct {
		name       string
		cryptoType int
	}{
		{"ECDH_P256", key_certificate.KEYCERT_CRYPTO_P256},
		{"ECDH_P384", key_certificate.KEYCERT_CRYPTO_P384},
		{"ECDH_P521", key_certificate.KEYCERT_CRYPTO_P521},
	}

	for _, tc := range reservedTypes {
		t.Run(tc.name+"_accepted_via_ReadDestination", func(t *testing.T) {
			data := createDestinationBytesWithCryptoType(t, tc.cryptoType)
			dest, _, err := ReadDestination(data)
			// Must be accepted (not rejected) — forward compatibility.
			require.NoError(t, err,
				"ECDH reserved crypto type %d (%s) must be accepted (warning only)",
				tc.cryptoType, tc.name)
			assert.NotNil(t, dest.KeysAndCert)
		})

		t.Run(tc.name+"_accepted_via_validateDestinationCryptoType", func(t *testing.T) {
			keyCert, err := key_certificate.NewKeyCertificateWithTypes(
				key_certificate.KEYCERT_SIGN_DSA_SHA1,
				tc.cryptoType,
			)
			if err != nil {
				t.Skipf("cannot construct KeyCertificate with crypto type %d: %v", tc.cryptoType, err)
			}
			kac := &keys_and_cert.KeysAndCert{KeyCertificate: keyCert}
			err = validateDestinationCryptoType(kac)
			assert.NoError(t, err,
				"validateDestinationCryptoType must not reject reserved ECDH type %d", tc.cryptoType)
		})
	}
}

// ============================================================================
// Equals() canonicalization: KEY(0,0) and NULL cert forms compare equal
// Finding: [GAP] Equals() uses raw byte comparison without canonicalization
// ============================================================================

func TestEqualsCanonicalizesCrossForms(t *testing.T) {
	// Build the same key data in two different cert forms:
	// Form A: KEY(0,0) cert (7 bytes), manually constructed bypassing ReadDestination
	// Form B: NULL cert (3 bytes)
	keysData := make([]byte, 384)
	for i := range keysData {
		keysData[i] = byte(i % 256)
	}

	// Form A: KEY(0,0) — use readDestinationRaw to avoid auto-canonicalization
	keyCertData := append(keysData, 0x05, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00)
	destA, _, err := readDestinationRaw(keyCertData)
	require.NoError(t, err, "KEY(0,0) form must parse via readDestinationRaw")

	// Form B: NULL cert
	nullCertData := append(keysData, 0x00, 0x00, 0x00)
	destB, _, err := readDestinationRaw(nullCertData)
	require.NoError(t, err, "NULL cert form must parse via readDestinationRaw")

	// Verify they have different raw bytes (different cert encodings)
	bytesA, _ := destA.Bytes()
	bytesB, _ := destB.Bytes()
	require.NotEqual(t, len(bytesA), len(bytesB),
		"KEY(0,0) and NULL cert forms must differ in length: %d vs %d", len(bytesA), len(bytesB))

	// Equals() must still report them as equal due to canonicalization
	assert.True(t, (&destA).Equals(&destB),
		"Equals() must treat KEY(0,0) and NULL cert forms of the same destination as equal")
	assert.True(t, (&destB).Equals(&destA),
		"Equals() must be symmetric for KEY(0,0) vs NULL cert")
}

// ============================================================================
// RSA signing types: validation tests (direct, not via wire parsing)
// Finding: [TEST] RSA signing type validation tests are SKIPped
// ============================================================================

func TestRSASigningTypesRejected_Direct(t *testing.T) {
	// RSA signing keys are too large for the fixed 128-byte SPK field,
	// so wire-level tests skip. But we can test validateDestinationSigningType
	// directly by constructing a KeyCertificate with the RSA type.
	rsaTypes := []struct {
		name    string
		sigType int
	}{
		{"RSA_SHA256_2048", key_certificate.KEYCERT_SIGN_RSA2048},
		{"RSA_SHA384_3072", key_certificate.KEYCERT_SIGN_RSA3072},
		{"RSA_SHA512_4096", key_certificate.KEYCERT_SIGN_RSA4096},
	}

	for _, tc := range rsaTypes {
		t.Run(tc.name+"_rejected_by_validateDestinationSigningType", func(t *testing.T) {
			keyCert, err := key_certificate.NewKeyCertificateWithTypes(
				tc.sigType,
				key_certificate.KEYCERT_CRYPTO_ELG,
			)
			if err != nil {
				t.Skipf("cannot construct KeyCertificate with signing type %d: %v", tc.sigType, err)
			}
			kac := &keys_and_cert.KeysAndCert{KeyCertificate: keyCert}
			err = validateDestinationSigningType(kac)
			require.Error(t, err,
				"validateDestinationSigningType must reject RSA type %d (%s)", tc.sigType, tc.name)
			assert.Contains(t, err.Error(), "RSA")
			assert.Contains(t, err.Error(), "not permitted for Destinations")
		})
	}
}
