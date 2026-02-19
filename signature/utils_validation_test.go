package signature

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadSignatureErrors(t *testing.T) {
	assert := assert.New(t)

	data := []byte{0xbe, 0xef}
	unsupportedSigType := 1000
	_, _, err := ReadSignature(data, unsupportedSigType)
	assert.NotNil(err, "unsupported signature error should be reported")

	sigType := SIGNATURE_TYPE_DSA_SHA1
	_, _, err = ReadSignature(data, sigType)
	assert.NotNil(err, "insufficient data error should be reported")
}

func TestReadSignatureNilInput(t *testing.T) {
	sigTypes := []int{
		SIGNATURE_TYPE_DSA_SHA1,
		SIGNATURE_TYPE_ECDSA_SHA256_P256,
		SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
		SIGNATURE_TYPE_REDDSA_SHA512_ED25519,
	}

	for _, sigType := range sigTypes {
		t.Run("nil_input", func(t *testing.T) {
			sig, remainder, err := ReadSignature(nil, sigType)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "insufficient data")
			assert.Equal(t, 0, sig.Len())
			assert.Nil(t, remainder)
		})

		t.Run("empty_input", func(t *testing.T) {
			sig, remainder, err := ReadSignature([]byte{}, sigType)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "insufficient data")
			assert.Equal(t, 0, sig.Len())
			assert.Nil(t, remainder)
		})
	}
}

func TestNewSignatureError(t *testing.T) {
	assert := assert.New(t)

	data := []byte{0xbe, 0xef}
	unsupportedSigType := 1000
	_, _, err := NewSignature(data, unsupportedSigType)
	assert.NotNil(err, "NewSignature error should be reported")
}

func TestGOSTReservedTypes(t *testing.T) {
	// Type 9: GOST R 3410-2012-512
	_, err := SignatureSize(SIGNATURE_TYPE_GOST_R3410_2012_512)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reserved")
	assert.Contains(t, err.Error(), "GOST")

	// Type 10: GOST R 3410-2012-1024
	_, err = SignatureSize(SIGNATURE_TYPE_GOST_R3410_2012_1024)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reserved")
	assert.Contains(t, err.Error(), "GOST")

	// NewSignatureFromBytes should also reject GOST types
	_, err = NewSignatureFromBytes(make([]byte, GOST_R3410_2012_512_SIZE), SIGNATURE_TYPE_GOST_R3410_2012_512)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reserved")

	_, err = NewSignatureFromBytes(make([]byte, GOST_R3410_2012_1024_SIZE), SIGNATURE_TYPE_GOST_R3410_2012_1024)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reserved")
}

func TestSigTypeRangeValidation(t *testing.T) {
	t.Run("negative sigType rejected by SignatureSize", func(t *testing.T) {
		_, err := SignatureSize(-1)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "out of valid range")
	})

	t.Run("negative sigType rejected by NewSignatureFromBytes", func(t *testing.T) {
		_, err := NewSignatureFromBytes(make([]byte, 40), -1)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "out of valid range")
	})

	t.Run("sigType > 65535 rejected by SignatureSize", func(t *testing.T) {
		_, err := SignatureSize(65536)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "out of valid range")
	})

	t.Run("sigType > 65535 rejected by NewSignatureFromBytes", func(t *testing.T) {
		_, err := NewSignatureFromBytes(make([]byte, 40), 65536)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "out of valid range")
	})

	t.Run("sigType 0 is valid (DSA_SHA1)", func(t *testing.T) {
		size, err := SignatureSize(0)
		require.NoError(t, err)
		assert.Equal(t, DSA_SHA1_SIZE, size)
	})

	t.Run("sigType 65535 is reserved future", func(t *testing.T) {
		_, err := SignatureSize(65535)
		require.Error(t, err)
	})

	t.Run("MLDSA range 12-20 reserved", func(t *testing.T) {
		for sigType := 12; sigType <= 20; sigType++ {
			_, err := SignatureSize(sigType)
			require.Error(t, err, "type %d should be reserved", sigType)
			assert.Contains(t, err.Error(), "reserved", "type %d", sigType)
		}
	})

	t.Run("experimental range 65280-65534", func(t *testing.T) {
		_, err := SignatureSize(65280)
		require.Error(t, err)
	})
}
