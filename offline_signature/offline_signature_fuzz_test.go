package offline_signature

import (
	"crypto/ed25519"
	"encoding/binary"
	"testing"

	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/signature"
	"github.com/stretchr/testify/assert"
)

func FuzzReadOfflineSignature(f *testing.F) {
	// Seed with valid Ed25519 OfflineSignature
	validData := make([]byte, 102)
	binary.BigEndian.PutUint32(validData[0:4], 1735689600)
	binary.BigEndian.PutUint16(validData[4:6], key_certificate.KEYCERT_SIGN_ED25519)
	f.Add(validData, uint16(signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519))

	// Empty data
	f.Add([]byte{}, uint16(signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519))

	// Only header
	header := make([]byte, 6)
	binary.BigEndian.PutUint16(header[4:6], key_certificate.KEYCERT_SIGN_ED25519)
	f.Add(header, uint16(signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519))

	// Truncated after transient key
	truncated := make([]byte, 38) // 4+2+32
	binary.BigEndian.PutUint16(truncated[4:6], key_certificate.KEYCERT_SIGN_ED25519)
	f.Add(truncated, uint16(signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519))

	// Unknown transient type
	unknownType := make([]byte, 200)
	binary.BigEndian.PutUint16(unknownType[4:6], 999)
	f.Add(unknownType, uint16(signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519))

	// Unknown destination type
	f.Add(validData, uint16(999))

	// Very large data
	large := make([]byte, 1024)
	binary.BigEndian.PutUint16(large[4:6], key_certificate.KEYCERT_SIGN_ED25519)
	f.Add(large, uint16(signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519))

	// RedDSA type
	redDSAData := make([]byte, 102)
	binary.BigEndian.PutUint32(redDSAData[0:4], 1735689600)
	binary.BigEndian.PutUint16(redDSAData[4:6], key_certificate.KEYCERT_SIGN_REDDSA_ED25519)
	f.Add(redDSAData, uint16(signature.SIGNATURE_TYPE_REDDSA_SHA512_ED25519))

	// Ed25519ph type
	phData := make([]byte, 102)
	binary.BigEndian.PutUint32(phData[0:4], 1735689600)
	binary.BigEndian.PutUint16(phData[4:6], key_certificate.KEYCERT_SIGN_ED25519PH)
	f.Add(phData, uint16(signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519PH))

	// P384 transient
	p384Data := make([]byte, EXPIRES_SIZE+SIGTYPE_SIZE+key_certificate.KEYCERT_SIGN_P384_SIZE+signature.ECDSA_SHA384_P384_SIZE)
	binary.BigEndian.PutUint16(p384Data[4:6], key_certificate.KEYCERT_SIGN_P384)
	f.Add(p384Data, uint16(signature.SIGNATURE_TYPE_ECDSA_SHA384_P384))

	f.Fuzz(func(t *testing.T, data []byte, destSigType uint16) {
		offlineSig, remainder, err := ReadOfflineSignature(data, destSigType)
		if err != nil {
			return
		}

		assert.Greater(t, offlineSig.Len(), 0, "Len should be positive")
		assert.NotNil(t, offlineSig.TransientPublicKey(), "transient key should not be nil")
		assert.NotNil(t, offlineSig.Signature(), "signature should not be nil")

		// Verify round-trip serialization
		serialized := offlineSig.Bytes()
		parsed, _, err2 := ReadOfflineSignature(serialized, destSigType)
		if err2 == nil {
			assert.Equal(t, offlineSig.Expires(), parsed.Expires())
			assert.Equal(t, offlineSig.TransientSigType(), parsed.TransientSigType())
			assert.Equal(t, offlineSig.TransientPublicKey(), parsed.TransientPublicKey())
			assert.Equal(t, offlineSig.Signature(), parsed.Signature())
		}

		expectedConsumed := EXPIRES_SIZE + SIGTYPE_SIZE + len(offlineSig.TransientPublicKey()) + len(offlineSig.Signature())
		assert.Equal(t, len(data)-expectedConsumed, len(remainder))
	})
}

// FuzzNewOfflineSignature exercises the NewOfflineSignature constructor with
// arbitrary input to detect panics or silent data corruption in validation logic.
func FuzzNewOfflineSignature(f *testing.F) {
	// Seed: valid Ed25519 parameters.
	transientKey := make([]byte, key_certificate.KEYCERT_SIGN_ED25519_SIZE)
	sig := make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)
	f.Add(uint32(1735689600), uint16(key_certificate.KEYCERT_SIGN_ED25519), transientKey,
		sig, uint16(signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519))

	// Seed: zero expires (should return error from constructor).
	f.Add(uint32(0), uint16(key_certificate.KEYCERT_SIGN_ED25519), transientKey,
		sig, uint16(signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519))

	// Seed: unknown transient type.
	f.Add(uint32(1735689600), uint16(999), transientKey,
		sig, uint16(signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519))

	// Seed: P256 parameters.
	p256Key := make([]byte, key_certificate.KEYCERT_SIGN_P256_SIZE)
	p256Sig := make([]byte, signature.ECDSA_SHA256_P256_SIZE)
	f.Add(uint32(1735689600), uint16(key_certificate.KEYCERT_SIGN_P256), p256Key,
		p256Sig, uint16(signature.SIGNATURE_TYPE_ECDSA_SHA256_P256))

	f.Fuzz(func(t *testing.T, expires uint32, transientSigType uint16,
		transientPublicKey []byte, sig []byte, destinationSigType uint16,
	) {
		offlineSig, err := NewOfflineSignature(expires, transientSigType,
			transientPublicKey, sig, destinationSigType)
		if err != nil {
			return // errors are expected for invalid inputs; no panic is the goal
		}
		// If construction succeeded, the object must round-trip losslessly.
		serialized := offlineSig.Bytes()
		parsed, _, parseErr := ReadOfflineSignature(serialized, destinationSigType)
		if parseErr != nil {
			return
		}
		if offlineSig.Expires() != parsed.Expires() ||
			offlineSig.TransientSigType() != parsed.TransientSigType() {
			t.Errorf("round-trip produced different expires/sigtype")
		}
	})
}

// FuzzCreateOfflineSignature exercises the CreateOfflineSignature construction path with
// a fixed Ed25519 signer to detect panics on unexpected type/size combinations.
func FuzzCreateOfflineSignature(f *testing.F) {
	// Use a deterministic key seed so the corpus is reproducible.
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	privKey := ed25519.NewKeyFromSeed(seed)

	// Seed: valid Ed25519 destination.
	transientKey := make([]byte, key_certificate.KEYCERT_SIGN_ED25519_SIZE)
	f.Add(uint32(1735689600), uint16(key_certificate.KEYCERT_SIGN_ED25519),
		transientKey, uint16(signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519))

	// Seed: zero expires (must error).
	f.Add(uint32(0), uint16(key_certificate.KEYCERT_SIGN_ED25519),
		transientKey, uint16(signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519))

	// Seed: Ed25519ph destination.
	f.Add(uint32(1735689600), uint16(key_certificate.KEYCERT_SIGN_ED25519),
		transientKey, uint16(signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519PH))

	// Seed: RedDSA destination (must error — not implemented).
	f.Add(uint32(1735689600), uint16(key_certificate.KEYCERT_SIGN_REDDSA_ED25519),
		transientKey, uint16(signature.SIGNATURE_TYPE_REDDSA_SHA512_ED25519))

	// Seed: unknown types.
	f.Add(uint32(1735689600), uint16(999), transientKey, uint16(999))

	f.Fuzz(func(t *testing.T, expires uint32, transientSigType uint16,
		transientPublicKey []byte, destinationSigType uint16,
	) {
		offlineSig, err := CreateOfflineSignature(expires, transientSigType,
			transientPublicKey, privKey, destinationSigType)
		if err != nil {
			return
		}
		// A successfully created signature must pass structural validation.
		if structErr := offlineSig.ValidateStructure(); structErr != nil {
			t.Errorf("CreateOfflineSignature returned object failing ValidateStructure: %v", structErr)
		}
		// Ed25519/Ed25519ph signatures must verify against the public key.
		switch destinationSigType {
		case signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
			signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519PH:
			pubKey := privKey.Public().(ed25519.PublicKey)
			valid, vErr := offlineSig.VerifySignature(pubKey)
			if vErr != nil {
				t.Errorf("VerifySignature error for valid sig: %v", vErr)
			}
			if !valid {
				t.Errorf("VerifySignature returned false for freshly created signature")
			}
		}
	})
}
