package offline_signature

import (
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
