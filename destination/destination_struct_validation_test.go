package destination

import (
	"testing"

	"github.com/go-i2p/common/keys_and_cert"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// ReadDestination – error paths
// ============================================================================

func TestReadDestinationReturnsZeroOnError(t *testing.T) {
	t.Run("short data returns error and zero Destination", func(t *testing.T) {
		dest, _, err := ReadDestination([]byte{0x00, 0x01, 0x02})
		require.Error(t, err)
		assert.Nil(t, dest.KeysAndCert, "Destination should have nil KeysAndCert on error")
	})

	t.Run("empty data returns error and zero Destination", func(t *testing.T) {
		dest, _, err := ReadDestination([]byte{})
		require.Error(t, err)
		assert.Nil(t, dest.KeysAndCert)
	})

	t.Run("nil data returns error and zero Destination", func(t *testing.T) {
		dest, _, err := ReadDestination(nil)
		require.Error(t, err)
		assert.Nil(t, dest.KeysAndCert)
	})
}

func TestReadDestinationInvalidCertType(t *testing.T) {
	data := make([]byte, keys_and_cert.KEYS_AND_CERT_MIN_SIZE)
	for i := range data {
		data[i] = byte(i % 256)
	}
	data[384] = 0xFF
	data[385] = 0x00
	data[386] = 0x00

	_, _, err := ReadDestination(data)
	require.Error(t, err, "ReadDestination should propagate error for invalid certificate type")
}

func TestReadDestinationErrorDoesNotPanic(t *testing.T) {
	invalidData := make([]byte, keys_and_cert.KEYS_AND_CERT_MIN_SIZE)
	for i := range invalidData {
		invalidData[i] = byte(i % 256)
	}
	invalidData[384] = 0xFF
	invalidData[385] = 0x00
	invalidData[386] = 0x00

	// Should not panic
	_, _, err := ReadDestination(invalidData)
	_ = err
}

// ============================================================================
// Bytes() / Base32Address() / Base64() – nil KeysAndCert
// ============================================================================

func TestBytesNilKeysAndCert(t *testing.T) {
	dest := Destination{KeysAndCert: nil}
	_, err := dest.Bytes()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not initialized")
}

func TestBase32AddressNilKeysAndCert(t *testing.T) {
	dest := Destination{KeysAndCert: nil}
	_, err := dest.Base32Address()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not initialized")
}

func TestBase64NilKeysAndCert(t *testing.T) {
	dest := Destination{KeysAndCert: nil}
	_, err := dest.Base64()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not initialized")
}

// ============================================================================
// Pointer receiver consistency (nil safety for value & pointer methods)
// ============================================================================

func TestPointerReceiverConsistency(t *testing.T) {
	t.Run("pointer receiver methods work on value from ReadDestination", func(t *testing.T) {
		data := createValidDestinationBytes(t)
		dest, _, err := ReadDestination(data)
		require.NoError(t, err)

		assert.NoError(t, dest.Validate())
		assert.True(t, dest.IsValid())

		_, err = dest.Bytes()
		assert.NoError(t, err)

		_, err = dest.Base32Address()
		assert.NoError(t, err)

		_, err = dest.Base64()
		assert.NoError(t, err)

		_, err = dest.Hash()
		assert.NoError(t, err)

		assert.True(t, (&dest).Equals(&dest))
	})

	t.Run("nil receiver safety for pointer methods", func(t *testing.T) {
		var dest *Destination

		err := dest.Validate()
		assert.Error(t, err)

		assert.False(t, dest.IsValid())

		_, err = dest.Hash()
		assert.Error(t, err)
	})

	t.Run("nil KeysAndCert safety for value methods", func(t *testing.T) {
		dest := Destination{KeysAndCert: nil}

		_, err := dest.Bytes()
		assert.Error(t, err)

		_, err = dest.Base32Address()
		assert.Error(t, err)

		_, err = dest.Base64()
		assert.Error(t, err)
	})
}
