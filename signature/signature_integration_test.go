package signature

// Integration tests for the signature package.
// These tests exercise signature parsing in the context of realistic I2P
// protocol byte streams, simulating the signature fields that appear at the
// end of RouterInfo, LeaseSet, and Destination structures.
//
// Reference: https://geti2p.net/spec/common-structures#signature

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildRouterInfoPayload constructs a minimal synthetic RouterInfo-like byte
// stream: [header bytes][signature bytes][trailing bytes].  This mirrors the
// on-wire layout where a RouterInfo ends with a Signature field.
func buildRouterInfoPayload(headerLen, sigType int) (payload, sigData []byte) {
	sigLen, err := getSignatureLength(sigType)
	if err != nil {
		panic(err)
	}
	header := make([]byte, headerLen)
	for i := range header {
		header[i] = byte(i ^ 0xAA)
	}
	sig := make([]byte, sigLen)
	for i := range sig {
		sig[i] = byte((i * 31) ^ 0x5F)
	}
	trailing := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	payload = append(header, sig...)
	payload = append(payload, trailing...)
	return payload, sig
}

// TestSignatureIntegration_RouterInfoTrailingSignature simulates extracting the
// signature from the end of a RouterInfo-like byte stream.  The caller splits
// the stream at the known header boundary and passes only the signature+remainder
// slice to ReadSignature, which is the typical real-world call pattern.
func TestSignatureIntegration_RouterInfoTrailingSignature(t *testing.T) {
	headerLen := 128

	activeSigTypes := []struct {
		sigType int
		name    string
		sigSize int
	}{
		{SIGNATURE_TYPE_EDDSA_SHA512_ED25519, "EdDSA-Ed25519", EdDSA_SHA512_Ed25519_SIZE},
		{SIGNATURE_TYPE_EDDSA_SHA512_ED25519PH, "EdDSA-Ed25519ph", EdDSA_SHA512_Ed25519ph_SIZE},
		{SIGNATURE_TYPE_REDDSA_SHA512_ED25519, "RedDSA-Ed25519", RedDSA_SHA512_Ed25519_SIZE},
		{SIGNATURE_TYPE_ECDSA_SHA256_P256, "ECDSA-P256", ECDSA_SHA256_P256_SIZE},
		{SIGNATURE_TYPE_ECDSA_SHA384_P384, "ECDSA-P384", ECDSA_SHA384_P384_SIZE},
		{SIGNATURE_TYPE_ECDSA_SHA512_P521, "ECDSA-P521", ECDSA_SHA512_P521_SIZE},
		{SIGNATURE_TYPE_RSA_SHA256_2048, "RSA-2048", RSA_SHA256_2048_SIZE},
		{SIGNATURE_TYPE_RSA_SHA384_3072, "RSA-3072", RSA_SHA384_3072_SIZE},
		{SIGNATURE_TYPE_RSA_SHA512_4096, "RSA-4096", RSA_SHA512_4096_SIZE},
	}

	for _, tc := range activeSigTypes {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			payload, expectedSig := buildRouterInfoPayload(headerLen, tc.sigType)

			// Simulate the caller advancing past the header
			rest := payload[headerLen:]

			sig, remainder, err := ReadSignature(rest, tc.sigType)
			require.NoError(t, err, "ReadSignature should succeed for type %d", tc.sigType)

			assert.Equal(t, tc.sigType, sig.Type())
			assert.Equal(t, tc.sigSize, sig.Len())
			assert.Equal(t, expectedSig, sig.Bytes(),
				"extracted signature bytes must match the original signature data")

			// Remainder must be exactly the 4 trailing bytes
			assert.Equal(t, []byte{0xDE, 0xAD, 0xBE, 0xEF}, remainder,
				"ReadSignature must leave trailing bytes in remainder")
		})
	}
}

// TestSignatureIntegration_PartialRead verifies that ReadSignature returns a
// clean error (not a panic) when presented with a truncated byte stream — a
// normal condition for streaming parsers reading incomplete frames.
func TestSignatureIntegration_PartialRead(t *testing.T) {
	sigType := SIGNATURE_TYPE_EDDSA_SHA512_ED25519
	expectedLen := EdDSA_SHA512_Ed25519_SIZE

	// Truncate by one byte
	partial := make([]byte, expectedLen-1)

	_, _, err := ReadSignature(partial, sigType)
	require.Error(t, err, "ReadSignature must error on insufficient data")
	assert.Contains(t, err.Error(), "insufficient data to read signature")
}

// TestSignatureIntegration_SerializeRoundTrip verifies that a Signature
// serialized via Serialize() can be re-parsed by ReadSignature to produce
// an identical Signature — the fundamental wire-format round-trip.
func TestSignatureIntegration_SerializeRoundTrip(t *testing.T) {
	for _, tc := range supportedSigTypes() {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			// Build original
			raw := make([]byte, tc.Size)
			for i := range raw {
				raw[i] = byte((i * 17) ^ 0x7B)
			}
			original, err := NewSignatureFromBytes(raw, tc.SigType)
			require.NoError(t, err)

			// Serialize and re-parse
			wire := original.Serialize()
			parsed, remainder, err := ReadSignature(wire, tc.SigType)
			require.NoError(t, err)
			assert.Empty(t, remainder)
			assert.True(t, original.Equal(&parsed),
				"round-trip Serialize→ReadSignature must produce equal signatures")
		})
	}
}

// TestSignatureIntegration_ConcatenatedSignatures simulates a protocol structure
// that embeds two signatures back-to-back (e.g., a signed-with-two-keys message).
// Verifies that ReadSignature correctly splits at the first boundary and the
// second ReadSignature call consumes the remainder.
func TestSignatureIntegration_ConcatenatedSignatures(t *testing.T) {
	sigType := SIGNATURE_TYPE_EDDSA_SHA512_ED25519
	size := EdDSA_SHA512_Ed25519_SIZE

	sig1Data := make([]byte, size)
	sig2Data := make([]byte, size)
	for i := range sig1Data {
		sig1Data[i] = byte(i)
		sig2Data[i] = byte(i ^ 0xFF)
	}

	// Concatenate two signatures
	combined := append(sig1Data, sig2Data...)

	sig1, rest, err := ReadSignature(combined, sigType)
	require.NoError(t, err)
	assert.Equal(t, sig1Data, sig1.Bytes())

	sig2, rest2, err := ReadSignature(rest, sigType)
	require.NoError(t, err)
	assert.Equal(t, sig2Data, sig2.Bytes())
	assert.Empty(t, rest2)

	assert.False(t, sig1.Equal(&sig2),
		"two distinct signatures in the same stream must not compare as equal")
}

// TestSignatureIntegration_SigTypeFromUint16 verifies that signature type
// integers derived from a 2-byte big-endian network field (as used in the
// I2P Key Certificate) are correctly handled by ReadSignature.
func TestSignatureIntegration_SigTypeFromUint16(t *testing.T) {
	// Encode sig type 7 (EdDSA) as a 2-byte big-endian field, as it appears
	// in an I2P Key Certificate structure.
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, 7)
	sigTypeFromNet := int(binary.BigEndian.Uint16(buf))

	assert.Equal(t, SIGNATURE_TYPE_EDDSA_SHA512_ED25519, sigTypeFromNet)

	data := make([]byte, EdDSA_SHA512_Ed25519_SIZE+4)
	for i := range data {
		data[i] = byte(i)
	}

	sig, remainder, err := ReadSignature(data, sigTypeFromNet)
	require.NoError(t, err)
	assert.Equal(t, SIGNATURE_TYPE_EDDSA_SHA512_ED25519, sig.Type())
	assert.Equal(t, EdDSA_SHA512_Ed25519_SIZE, sig.Len())
	assert.Len(t, remainder, 4)
}
