package encrypted_leaseset

import (
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/binary"
	"testing"
	"time"

	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/offline_signature"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Audit Finding #12: TestVerifyEncryptedLeaseSet
// No test for Verify() method. Signature verification is the most
// security-critical method in the package.
// ============================================================================

func TestVerifyEncryptedLeaseSet(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	encData := make([]byte, 80)
	for i := range encData {
		encData[i] = byte(i)
	}

	els, err := NewEncryptedLeaseSet(
		uint16(key_certificate.KEYCERT_SIGN_ED25519),
		pub,
		uint32(time.Now().Unix()),
		600,
		0,
		nil,
		encData,
		priv,
	)
	require.NoError(t, err)

	t.Run("valid signature passes verification", func(t *testing.T) {
		err := els.Verify()
		assert.NoError(t, err)
	})

	t.Run("corrupted signature fails verification", func(t *testing.T) {
		// Make a copy and corrupt the signature
		serialized, err := els.Bytes()
		require.NoError(t, err)

		// Corrupt the last byte of the serialized data (in the signature area)
		serialized[len(serialized)-1] ^= 0xFF

		// Re-parse
		corrupted, _, err := ReadEncryptedLeaseSet(serialized)
		require.NoError(t, err) // parse should succeed (it doesn't verify yet)

		err = corrupted.Verify()
		assert.Error(t, err, "corrupted signature should fail verification")
		assert.Contains(t, err.Error(), "signature verification failed")
	})

	t.Run("corrupted data fails verification", func(t *testing.T) {
		serialized, err := els.Bytes()
		require.NoError(t, err)

		// Corrupt a byte in the middle of the content (blinded public key area)
		serialized[10] ^= 0xFF

		corrupted, _, err := ReadEncryptedLeaseSet(serialized)
		require.NoError(t, err)

		err = corrupted.Verify()
		assert.Error(t, err, "corrupted content should fail verification")
	})
}

// ============================================================================
// Audit Finding #13: TestOfflineSignatureParsingPath
// No test for offline signature parsing path in ReadEncryptedLeaseSet.
// ============================================================================

func TestOfflineSignatureParsingPath(t *testing.T) {
	// Generate two keypairs: one for the "destination" (blinded) key,
	// one for the "transient" key used with offline signatures.
	destPub, destPriv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	transientPub, transientPriv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	offlineExpires := uint32(time.Now().Add(24 * time.Hour).Unix())

	// Build the offline signature payload:
	// The offline signature's own signature covers: expires(4) || transient_sigtype(2) || transient_public_key
	offlineSigData := make([]byte, 0, 4+2+ed25519.PublicKeySize)
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, offlineExpires)
	offlineSigData = append(offlineSigData, buf...)
	buf = make([]byte, 2)
	binary.BigEndian.PutUint16(buf, uint16(key_certificate.KEYCERT_SIGN_ED25519))
	offlineSigData = append(offlineSigData, buf...)
	offlineSigData = append(offlineSigData, transientPub...)

	// Sign with the destination's private key
	offlineSigBytes := ed25519.Sign(destPriv, offlineSigData)

	// Create the OfflineSignature object
	offlineSig, err := offline_signature.NewOfflineSignature(
		offlineExpires,
		uint16(key_certificate.KEYCERT_SIGN_ED25519),
		transientPub,
		offlineSigBytes,
		uint16(key_certificate.KEYCERT_SIGN_ED25519),
	)
	require.NoError(t, err)

	encData := make([]byte, 80)
	for i := range encData {
		encData[i] = byte(i)
	}

	// Create EncryptedLeaseSet with offline keys flag and transient private key
	els, err := NewEncryptedLeaseSet(
		uint16(key_certificate.KEYCERT_SIGN_ED25519),
		destPub, // blinded key is the destination pub
		uint32(time.Now().Unix()),
		600,
		ENCRYPTED_LEASESET_FLAG_OFFLINE_KEYS,
		&offlineSig,
		encData,
		transientPriv, // sign with transient key
	)
	require.NoError(t, err)

	t.Run("has offline keys flag", func(t *testing.T) {
		assert.True(t, els.HasOfflineKeys())
	})

	t.Run("offline signature is present", func(t *testing.T) {
		assert.NotNil(t, els.OfflineSignature())
	})

	t.Run("round-trip preserves offline signature", func(t *testing.T) {
		serialized, err := els.Bytes()
		require.NoError(t, err)

		parsed, _, err := ReadEncryptedLeaseSet(serialized)
		require.NoError(t, err)

		assert.True(t, parsed.HasOfflineKeys())
		assert.NotNil(t, parsed.OfflineSignature())
		assert.Equal(t, els.InnerLength(), parsed.InnerLength())
		assert.Equal(t, els.EncryptedInnerData(), parsed.EncryptedInnerData())
	})

	t.Run("verify uses transient key", func(t *testing.T) {
		err := els.Verify()
		assert.NoError(t, err, "Verify should use the transient key from the offline signature")
	})
}

// ============================================================================
// Audit Finding #14: FuzzReadEncryptedLeaseSet
// No fuzz test target for EncryptedLeaseSet parsing.
// ============================================================================

func FuzzReadEncryptedLeaseSet(f *testing.F) {
	// Seed 1: valid minimal EncryptedLeaseSet
	seed1 := buildMinimalELS(f)
	f.Add(seed1)

	// Seed 2: empty data
	f.Add([]byte{})

	// Seed 3: just under minimum length
	f.Add(make([]byte, ENCRYPTED_LEASESET_MIN_SIZE-1))

	// Seed 4: exactly minimum length with random data
	f.Add(make([]byte, ENCRYPTED_LEASESET_MIN_SIZE))

	// Seed 5: offline keys flag set in data with valid-looking structure
	seed5 := buildMinimalELSWithOfflineFlag(f)
	f.Add(seed5)

	f.Fuzz(func(t *testing.T, data []byte) {
		// Fuzz target: the parser must not panic regardless of input.
		// It may return an error, but must never crash.
		els, _, err := ReadEncryptedLeaseSet(data)
		if err != nil {
			return
		}

		// If parsing succeeded, validate internal consistency
		_ = els.Validate()

		// If parsing succeeded, serialization must not panic
		if serialized, sErr := els.Bytes(); sErr == nil {
			// Optional: round-trip check
			_, _, _ = ReadEncryptedLeaseSet(serialized)
		}
	})
}

// buildMinimalELS builds a valid minimal EncryptedLeaseSet wire format for fuzz seeding.
func buildMinimalELS(tb testing.TB) []byte {
	tb.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		tb.Fatal(err)
	}

	encData := make([]byte, 80)
	els, err := NewEncryptedLeaseSet(
		uint16(key_certificate.KEYCERT_SIGN_ED25519),
		pub,
		uint32(time.Now().Unix()),
		600,
		0,
		nil,
		encData,
		priv,
	)
	if err != nil {
		tb.Fatal(err)
	}

	serialized, err := els.Bytes()
	if err != nil {
		tb.Fatal(err)
	}
	return serialized
}

// buildMinimalELSWithOfflineFlag builds an EncryptedLeaseSet with offline keys for fuzz seeding.
func buildMinimalELSWithOfflineFlag(tb testing.TB) []byte {
	tb.Helper()
	destPub, destPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		tb.Fatal(err)
	}
	transientPub, transientPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		tb.Fatal(err)
	}

	offlineExpires := uint32(time.Now().Add(24 * time.Hour).Unix())
	offlineSigData := make([]byte, 0, 4+2+ed25519.PublicKeySize)
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, offlineExpires)
	offlineSigData = append(offlineSigData, buf...)
	buf = make([]byte, 2)
	binary.BigEndian.PutUint16(buf, uint16(key_certificate.KEYCERT_SIGN_ED25519))
	offlineSigData = append(offlineSigData, buf...)
	offlineSigData = append(offlineSigData, transientPub...)

	offlineSigBytes := ed25519.Sign(destPriv, offlineSigData)

	offlineSig, err := offline_signature.NewOfflineSignature(
		offlineExpires,
		uint16(key_certificate.KEYCERT_SIGN_ED25519),
		transientPub,
		offlineSigBytes,
		uint16(key_certificate.KEYCERT_SIGN_ED25519),
	)
	if err != nil {
		tb.Fatal(err)
	}

	encData := make([]byte, 80)
	els, err := NewEncryptedLeaseSet(
		uint16(key_certificate.KEYCERT_SIGN_ED25519),
		destPub,
		uint32(time.Now().Unix()),
		600,
		ENCRYPTED_LEASESET_FLAG_OFFLINE_KEYS,
		&offlineSig,
		encData,
		transientPriv,
	)
	if err != nil {
		tb.Fatal(err)
	}

	serialized, err := els.Bytes()
	if err != nil {
		tb.Fatal(err)
	}
	return serialized
}

// ============================================================================
// Audit Finding #16b: TestSigningPublicKeyForVerificationOffline
// No test for signingPublicKeyForVerification() with offline keys.
// ============================================================================

func TestSigningPublicKeyForVerificationOffline(t *testing.T) {
	destPub, destPriv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	transientPub, transientPriv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	offlineExpires := uint32(time.Now().Add(24 * time.Hour).Unix())

	// Build offline sig data
	offlineSigData := make([]byte, 0, 4+2+ed25519.PublicKeySize)
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, offlineExpires)
	offlineSigData = append(offlineSigData, buf...)
	buf = make([]byte, 2)
	binary.BigEndian.PutUint16(buf, uint16(key_certificate.KEYCERT_SIGN_ED25519))
	offlineSigData = append(offlineSigData, buf...)
	offlineSigData = append(offlineSigData, transientPub...)

	offlineSigBytes := ed25519.Sign(destPriv, offlineSigData)

	offlineSig, err := offline_signature.NewOfflineSignature(
		offlineExpires,
		uint16(key_certificate.KEYCERT_SIGN_ED25519),
		transientPub,
		offlineSigBytes,
		uint16(key_certificate.KEYCERT_SIGN_ED25519),
	)
	require.NoError(t, err)

	encData := make([]byte, 80)
	els, err := NewEncryptedLeaseSet(
		uint16(key_certificate.KEYCERT_SIGN_ED25519),
		destPub,
		uint32(time.Now().Unix()),
		600,
		ENCRYPTED_LEASESET_FLAG_OFFLINE_KEYS,
		&offlineSig,
		encData,
		transientPriv,
	)
	require.NoError(t, err)

	t.Run("returns transient key when offline keys present", func(t *testing.T) {
		spk, err := els.signingPublicKeyForVerification()
		require.NoError(t, err)

		// The key should be the transient public key, not the blinded one
		assert.Equal(t, []byte(transientPub), spk.Bytes(),
			"signingPublicKeyForVerification should return the transient key")
	})

	t.Run("returns blinded key when no offline keys", func(t *testing.T) {
		noOfflineELS, err := NewEncryptedLeaseSet(
			uint16(key_certificate.KEYCERT_SIGN_ED25519),
			destPub,
			uint32(time.Now().Unix()),
			600,
			0,
			nil,
			encData,
			destPriv,
		)
		require.NoError(t, err)

		spk, err := noOfflineELS.signingPublicKeyForVerification()
		require.NoError(t, err)

		assert.Equal(t, []byte(destPub), spk.Bytes(),
			"signingPublicKeyForVerification should return the blinded key")
	})
}

// ============================================================================
// Additional audit-targeted tests for spec compliance
// ============================================================================

// TestConstructorRejectsReservedFlags verifies finding #9: reserved flag bits
// must be rejected during construction.
func TestConstructorRejectsReservedFlags(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	encData := make([]byte, 80)

	reservedFlags := []uint16{0x0004, 0x0008, 0x0010, 0x8000, 0xFFFC}
	for _, flags := range reservedFlags {
		_, err := NewEncryptedLeaseSet(
			uint16(key_certificate.KEYCERT_SIGN_ED25519),
			pub,
			uint32(time.Now().Unix()),
			600,
			flags,
			nil,
			encData,
			pub, // wrong key type but will fail on flags first
		)
		assert.Error(t, err, "flags 0x%04x should be rejected", flags)
		assert.Contains(t, err.Error(), "reserved flag bits")
	}
}

// TestEncryptedInnerDataMinimumCryptoOverhead verifies finding #11:
// Validate() checks minimum crypto overhead size.
func TestEncryptedInnerDataMinimumCryptoOverhead(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	// Try to create with data smaller than minimum crypto overhead (61 bytes)
	smallData := make([]byte, 60)
	_, err = NewEncryptedLeaseSet(
		uint16(key_certificate.KEYCERT_SIGN_ED25519),
		pub,
		uint32(time.Now().Unix()),
		600,
		0,
		nil,
		smallData,
		priv,
	)
	assert.Error(t, err, "encrypted data below minimum crypto overhead should be rejected")
	assert.Contains(t, err.Error(), "encrypted inner data size")
}

// TestNoBlindedflag verifies finding #5: FLAG_BLINDED is removed.
// EncryptedLeaseSet is always blinded by definition; no such flag exists.
func TestNoBlindedflag(t *testing.T) {
	// Verify the constant ENCRYPTED_LEASESET_FLAG_BLINDED does not exist
	// by ensuring bits 15-2 are all reserved (mask = 0xFFFC).
	assert.Equal(t, uint16(0xFFFC), ENCRYPTED_LEASESET_RESERVED_FLAGS_MASK,
		"all bits except 0 and 1 should be reserved")

	// Only offline keys (bit 0) and unpublished (bit 1) are valid
	assert.Equal(t, uint16(0x0001), ENCRYPTED_LEASESET_FLAG_OFFLINE_KEYS)
	assert.Equal(t, uint16(0x0002), ENCRYPTED_LEASESET_FLAG_UNPUBLISHED)
}

// TestEd25519SigningMatchesCryptoLibrary verifies finding #4: signing uses
// SHA-512 pre-hashing to match the go-i2p/crypto library's convention.
// We verify by constructing and verifying with the same SHA-512 convention.
func TestEd25519SigningMatchesCryptoLibrary(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	encData := make([]byte, 80)
	els, err := NewEncryptedLeaseSet(
		uint16(key_certificate.KEYCERT_SIGN_ED25519),
		pub,
		uint32(time.Now().Unix()),
		600,
		0,
		nil,
		encData,
		priv,
	)
	require.NoError(t, err)

	// Manually verify with go-i2p's SHA-512 pre-hash convention
	dataToVerify, err := els.dataForSigning()
	require.NoError(t, err)

	h := sha512.Sum512(dataToVerify)
	assert.True(t, ed25519.Verify(pub, h[:], els.Signature().Bytes()),
		"signature must be valid under SHA-512 pre-hash convention (go-i2p/crypto)")
}
