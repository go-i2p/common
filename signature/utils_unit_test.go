package signature

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadSignature(t *testing.T) {
	assert := assert.New(t)

	sigTypes := []int{
		SIGNATURE_TYPE_DSA_SHA1, SIGNATURE_TYPE_ECDSA_SHA256_P256,
		SIGNATURE_TYPE_ECDSA_SHA384_P384, SIGNATURE_TYPE_ECDSA_SHA512_P521,
		SIGNATURE_TYPE_RSA_SHA256_2048, SIGNATURE_TYPE_RSA_SHA384_3072,
		SIGNATURE_TYPE_RSA_SHA512_4096, SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
		SIGNATURE_TYPE_EDDSA_SHA512_ED25519PH, SIGNATURE_TYPE_REDDSA_SHA512_ED25519,
	}
	sigLengths := []int{
		DSA_SHA1_SIZE, ECDSA_SHA256_P256_SIZE,
		ECDSA_SHA384_P384_SIZE, ECDSA_SHA512_P521_SIZE,
		RSA_SHA256_2048_SIZE, RSA_SHA384_3072_SIZE,
		RSA_SHA512_4096_SIZE, EdDSA_SHA512_Ed25519_SIZE,
		EdDSA_SHA512_Ed25519ph_SIZE, RedDSA_SHA512_Ed25519_SIZE,
	}

	dataLen := 1024
	data := []byte{}
	for i := 0; i < dataLen; i++ {
		data = append(data, byte(i%10))
	}

	for i, sigType := range sigTypes {
		sig, rem, err := ReadSignature(data, sigType)
		assert.Nil(err, "no errors should be returned")
		assert.Equal(sig.Bytes(), data[:sigLengths[i]], "signature bytes should be sliced from data")
		assert.Equal(sig.Type(), sigType, "signature type should match input")
		assert.Equal(rem, data[sigLengths[i]:], "remainder should be sliced from data")
	}
}

func TestNewSignature(t *testing.T) {
	assert := assert.New(t)

	data := []byte{}
	sigLength := EdDSA_SHA512_Ed25519_SIZE
	remLength := 20
	for i := 0; i < sigLength+remLength; i++ {
		data = append(data, byte(i%10))
	}
	sigType := SIGNATURE_TYPE_EDDSA_SHA512_ED25519

	sig, rem, err := NewSignature(data, sigType)
	assert.Nil(err, "no errors should be returned")
	assert.Equal(sig.Bytes(), data[:sigLength], "signature bytes should be sliced from data")
	assert.Equal(sig.Type(), sigType, "signature type should match input")
	assert.Equal(rem, data[sigLength:], "remainder should be sliced from data")
}

func TestSignatureSizeExported(t *testing.T) {
	for _, tc := range supportedSigTypes() {
		size, err := SignatureSize(tc.SigType)
		assert.NoError(t, err)
		assert.Equal(t, tc.Size, size, "SignatureSize(%d)", tc.SigType)
	}

	// Unknown type returns error
	_, err := SignatureSize(9999)
	assert.Error(t, err)

	// Negative type returns error
	_, err = SignatureSize(-1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "out of valid range")

	// > 65535 returns error
	_, err = SignatureSize(70000)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "out of valid range")
}

func TestSignatureSizeIsExported(t *testing.T) {
	tests := []struct {
		sigType int
		size    int
	}{
		{SIGNATURE_TYPE_DSA_SHA1, 40},
		{SIGNATURE_TYPE_ECDSA_SHA256_P256, 64},
		{SIGNATURE_TYPE_ECDSA_SHA384_P384, 96},
		{SIGNATURE_TYPE_ECDSA_SHA512_P521, 132},
		{SIGNATURE_TYPE_RSA_SHA256_2048, 256},
		{SIGNATURE_TYPE_RSA_SHA384_3072, 384},
		{SIGNATURE_TYPE_RSA_SHA512_4096, 512},
		{SIGNATURE_TYPE_EDDSA_SHA512_ED25519, 64},
		{SIGNATURE_TYPE_EDDSA_SHA512_ED25519PH, 64},
		{SIGNATURE_TYPE_REDDSA_SHA512_ED25519, 64},
	}

	for _, tt := range tests {
		size, err := SignatureSize(tt.sigType)
		require.NoError(t, err, "SignatureSize(%d)", tt.sigType)
		assert.Equal(t, tt.size, size, "SignatureSize(%d)", tt.sigType)
	}
}

func TestTypeName_AllImplementedTypes(t *testing.T) {
	tests := []struct {
		sigType  int
		expected string
	}{
		{SIGNATURE_TYPE_DSA_SHA1, "DSA_SHA1"},
		{SIGNATURE_TYPE_ECDSA_SHA256_P256, "ECDSA_SHA256_P256"},
		{SIGNATURE_TYPE_ECDSA_SHA384_P384, "ECDSA_SHA384_P384"},
		{SIGNATURE_TYPE_ECDSA_SHA512_P521, "ECDSA_SHA512_P521"},
		{SIGNATURE_TYPE_RSA_SHA256_2048, "RSA_SHA256_2048"},
		{SIGNATURE_TYPE_RSA_SHA384_3072, "RSA_SHA384_3072"},
		{SIGNATURE_TYPE_RSA_SHA512_4096, "RSA_SHA512_4096"},
		{SIGNATURE_TYPE_EDDSA_SHA512_ED25519, "EdDSA_SHA512_Ed25519"},
		{SIGNATURE_TYPE_EDDSA_SHA512_ED25519PH, "EdDSA_SHA512_Ed25519ph"},
		{SIGNATURE_TYPE_REDDSA_SHA512_ED25519, "RedDSA_SHA512_Ed25519"},
	}
	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, TypeName(tt.sigType))
		})
	}
}

func TestTypeName_ReservedTypes(t *testing.T) {
	// GOST reserved
	assert.Equal(t, "GOST_R3410_2012_512 (reserved)", TypeName(SIGNATURE_TYPE_GOST_R3410_2012_512))
	assert.Equal(t, "GOST_R3410_2012_1024 (reserved)", TypeName(SIGNATURE_TYPE_GOST_R3410_2012_1024))

	// MLDSA reserved range 12-20
	for sigType := SIGNATURE_TYPE_MLDSA_RESERVED_START; sigType <= SIGNATURE_TYPE_MLDSA_RESERVED_END; sigType++ {
		assert.Equal(t, "MLDSA (reserved)", TypeName(sigType), "type %d", sigType)
	}

	// Experimental range
	assert.Equal(t, "Experimental", TypeName(SIGNATURE_TYPE_EXPERIMENTAL_START))
	assert.Equal(t, "Experimental", TypeName(SIGNATURE_TYPE_EXPERIMENTAL_END))
	assert.Equal(t, "Experimental", TypeName(65400))
}

func TestTypeName_Unknown(t *testing.T) {
	assert.Equal(t, "Unknown", TypeName(100))
	assert.Equal(t, "Unknown", TypeName(30000))
	assert.Equal(t, "Unknown", TypeName(65535))
	assert.Equal(t, "Unknown", TypeName(-1))
}

func TestTypeName_UsedInString(t *testing.T) {
	data := make([]byte, EdDSA_SHA512_Ed25519_SIZE)
	sig, err := NewSignatureFromBytes(data, SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
	require.NoError(t, err)
	s := sig.String()
	assert.Contains(t, s, "EdDSA_SHA512_Ed25519")
	assert.Contains(t, s, "type: 7")
	assert.Contains(t, s, "length: 64")
}

func TestNewSignature_ExactLengthInput(t *testing.T) {
	for _, tc := range supportedSigTypes() {
		t.Run(tc.Name, func(t *testing.T) {
			// Create data with EXACTLY the signature length — no extra bytes
			data := makeSignatureData(tc.Size)

			sig, remainder, err := NewSignature(data, tc.SigType)
			require.NoError(t, err)
			require.NotNil(t, sig)
			assert.Equal(t, tc.SigType, sig.Type())
			assert.Equal(t, tc.Size, sig.Len())
			assert.Equal(t, data, sig.Bytes())
			assert.Empty(t, remainder, "remainder should be empty when input is exact length")
			assert.Len(t, remainder, 0)
		})
	}
}

func TestReadSignature_ExactLengthInput(t *testing.T) {
	for _, tc := range supportedSigTypes() {
		t.Run(tc.Name, func(t *testing.T) {
			data := makeSignatureData(tc.Size)

			sig, remainder, err := ReadSignature(data, tc.SigType)
			require.NoError(t, err)
			assert.Equal(t, tc.SigType, sig.Type())
			assert.Equal(t, tc.Size, sig.Len())
			assert.Equal(t, data, sig.Bytes())
			assert.Empty(t, remainder)
		})
	}
}
