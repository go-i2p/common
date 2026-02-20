package destination

import (
	"fmt"
	"testing"

	"github.com/go-i2p/common/keys_and_cert"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// NewDestination
// ============================================================================

func TestNewDestination(t *testing.T) {
	t.Run("valid KeysAndCert creates destination", func(t *testing.T) {
		keysAndCert := createValidKeysAndCert(t)

		dest, err := NewDestination(keysAndCert)
		require.NoError(t, err)
		require.NotNil(t, dest)
		assert.Equal(t, keysAndCert, dest.KeysAndCert)
		assert.True(t, dest.IsValid())
	})

	t.Run("nil KeysAndCert returns error", func(t *testing.T) {
		dest, err := NewDestination(nil)
		require.Error(t, err)
		assert.Nil(t, dest)
		assert.Contains(t, err.Error(), "cannot be nil")
	})

	t.Run("invalid KeysAndCert returns error", func(t *testing.T) {
		invalidKeysAndCert := &keys_and_cert.KeysAndCert{}

		dest, err := NewDestination(invalidKeysAndCert)
		require.Error(t, err)
		assert.Nil(t, dest)
		assert.Contains(t, err.Error(), "invalid KeysAndCert")
	})
}

// ============================================================================
// NewDestinationFromBytes
// ============================================================================

func TestNewDestinationFromBytes(t *testing.T) {
	t.Run("valid bytes create destination", func(t *testing.T) {
		originalData := createValidDestinationBytes(t)

		dest, remainder, err := NewDestinationFromBytes(originalData)
		require.NoError(t, err)
		require.NotNil(t, dest)
		assert.Empty(t, remainder)
		assert.True(t, dest.IsValid())
	})

	t.Run("invalid bytes return error", func(t *testing.T) {
		invalidData := []byte{0x00, 0x01, 0x02}

		dest, _, err := NewDestinationFromBytes(invalidData)
		require.Error(t, err)
		assert.Nil(t, dest)
	})

	t.Run("empty bytes return error", func(t *testing.T) {
		dest, _, err := NewDestinationFromBytes([]byte{})
		require.Error(t, err)
		assert.Nil(t, dest)
	})

	t.Run("extra bytes returned as remainder", func(t *testing.T) {
		originalData := createValidDestinationBytes(t)
		extraBytes := []byte{0xDE, 0xAD, 0xBE, 0xEF}
		dataWithExtra := append(originalData, extraBytes...)

		dest, remainder, err := NewDestinationFromBytes(dataWithExtra)
		require.NoError(t, err)
		require.NotNil(t, dest)
		assert.Equal(t, extraBytes, remainder)
	})
}

// ============================================================================
// Validate
// ============================================================================

func TestDestinationValidate(t *testing.T) {
	t.Run("valid destination passes validation", func(t *testing.T) {
		keysAndCert := createValidKeysAndCert(t)
		dest, err := NewDestination(keysAndCert)
		require.NoError(t, err)

		err = dest.Validate()
		assert.NoError(t, err)
	})

	t.Run("nil destination fails validation", func(t *testing.T) {
		var dest *Destination
		err := dest.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "destination is nil")
	})

	t.Run("destination with nil KeysAndCert fails validation", func(t *testing.T) {
		dest := &Destination{KeysAndCert: nil}
		err := dest.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "KeysAndCert is nil")
	})

	t.Run("destination with invalid KeysAndCert fails validation", func(t *testing.T) {
		invalidKeysAndCert := &keys_and_cert.KeysAndCert{}
		dest := &Destination{KeysAndCert: invalidKeysAndCert}

		err := dest.Validate()
		require.Error(t, err)
	})
}

// ============================================================================
// IsValid
// ============================================================================

func TestDestinationIsValid(t *testing.T) {
	t.Run("valid destination returns true", func(t *testing.T) {
		keysAndCert := createValidKeysAndCert(t)
		dest, err := NewDestination(keysAndCert)
		require.NoError(t, err)

		assert.True(t, dest.IsValid())
	})

	t.Run("nil destination returns false", func(t *testing.T) {
		var dest *Destination
		assert.False(t, dest.IsValid())
	})

	t.Run("destination with nil KeysAndCert returns false", func(t *testing.T) {
		dest := &Destination{KeysAndCert: nil}
		assert.False(t, dest.IsValid())
	})

	t.Run("destination with invalid KeysAndCert returns false", func(t *testing.T) {
		invalidKeysAndCert := &keys_and_cert.KeysAndCert{}
		dest := &Destination{KeysAndCert: invalidKeysAndCert}

		assert.False(t, dest.IsValid())
	})
}

// ============================================================================
// Hash
// ============================================================================

func TestHashMethod(t *testing.T) {
	t.Run("valid destination returns consistent hash", func(t *testing.T) {
		destBytes := createValidDestinationBytes(t)
		dest, _, err := ReadDestination(destBytes)
		require.NoError(t, err)

		hash1, err := dest.Hash()
		require.NoError(t, err)
		hash2, err := dest.Hash()
		require.NoError(t, err)

		assert.Equal(t, hash1, hash2, "Same destination should produce same hash")
		assert.NotEqual(t, [32]byte{}, hash1, "Hash should not be zero")
	})

	t.Run("nil destination returns error", func(t *testing.T) {
		var dest *Destination
		_, err := dest.Hash()
		require.Error(t, err)
	})

	t.Run("destination with nil KeysAndCert returns error", func(t *testing.T) {
		dest := &Destination{KeysAndCert: nil}
		_, err := dest.Hash()
		require.Error(t, err)
	})
}

// ============================================================================
// Equals
// ============================================================================

func TestEqualsMethod(t *testing.T) {
	t.Run("same destination equals itself", func(t *testing.T) {
		destBytes := createValidDestinationBytes(t)
		dest, _, err := ReadDestination(destBytes)
		require.NoError(t, err)
		destPtr := &dest

		assert.True(t, destPtr.Equals(destPtr))
	})

	t.Run("identical destinations are equal", func(t *testing.T) {
		destBytes := createValidDestinationBytes(t)
		dest1, _, err := ReadDestination(destBytes)
		require.NoError(t, err)
		dest2, _, err := ReadDestination(destBytes)
		require.NoError(t, err)

		assert.True(t, (&dest1).Equals(&dest2))
	})

	t.Run("nil destination not equal", func(t *testing.T) {
		destBytes := createValidDestinationBytes(t)
		dest, _, err := ReadDestination(destBytes)
		require.NoError(t, err)

		assert.False(t, (&dest).Equals(nil))
	})

	t.Run("nil receiver not equal", func(t *testing.T) {
		var dest *Destination
		other := &Destination{}
		assert.False(t, dest.Equals(other))
	})

	t.Run("destination with nil KeysAndCert not equal", func(t *testing.T) {
		dest1 := &Destination{KeysAndCert: nil}
		dest2 := &Destination{KeysAndCert: nil}
		assert.False(t, dest1.Equals(dest2))
	})

	t.Run("different key data produces non-equal destinations", func(t *testing.T) {
		data1 := createValidDestinationBytes(t)
		dest1, _, err := ReadDestination(data1)
		require.NoError(t, err)

		data2 := createEd25519X25519DestinationBytes(t)
		dest2, _, err := ReadDestination(data2)
		require.NoError(t, err)

		assert.False(t, (&dest1).Equals(&dest2),
			"Destinations with different key data should not be equal")
		assert.False(t, (&dest2).Equals(&dest1),
			"Equals should be symmetric")
	})

	t.Run("same type but different random keys produces non-equal", func(t *testing.T) {
		data1 := createEd25519X25519DestinationBytes(t)
		dest1, _, err := ReadDestination(data1)
		require.NoError(t, err)

		data2 := createEd25519X25519DestinationBytes(t)
		dest2, _, err := ReadDestination(data2)
		require.NoError(t, err)

		assert.False(t, (&dest1).Equals(&dest2),
			"Destinations with different random keys should not be equal")
	})

	t.Run("different hashes for different destinations", func(t *testing.T) {
		data1 := createEd25519X25519DestinationBytes(t)
		dest1, _, err := ReadDestination(data1)
		require.NoError(t, err)

		data2 := createEd25519X25519DestinationBytes(t)
		dest2, _, err := ReadDestination(data2)
		require.NoError(t, err)

		hash1, err := (&dest1).Hash()
		require.NoError(t, err)
		hash2, err := (&dest2).Hash()
		require.NoError(t, err)

		assert.NotEqual(t, hash1, hash2,
			"Different destinations should produce different hashes")
	})
}

// ============================================================================
// String (fmt.Stringer)
// ============================================================================

func TestDestinationString(t *testing.T) {
	t.Run("valid destination returns base32 address", func(t *testing.T) {
		data := createValidDestinationBytes(t)
		dest, _, err := ReadDestination(data)
		require.NoError(t, err)

		str := dest.String()
		assert.Contains(t, str, ".b32.i2p",
			"String() should return a .b32.i2p address")
		assert.Len(t, str, testBase32AddressLength,
			"String() should return a 60-char base32 address")

		addr, err := dest.Base32Address()
		require.NoError(t, err)
		assert.Equal(t, addr, str,
			"String() should return the same value as Base32Address()")
	})

	t.Run("nil KeysAndCert returns sentinel string", func(t *testing.T) {
		dest := Destination{KeysAndCert: nil}
		str := dest.String()
		assert.Equal(t, "<nil Destination>", str)
	})

	t.Run("implements fmt.Stringer", func(t *testing.T) {
		data := createValidDestinationBytes(t)
		dest, _, err := ReadDestination(data)
		require.NoError(t, err)

		formatted := fmt.Sprintf("%s", dest)
		assert.Contains(t, formatted, ".b32.i2p")
	})

	t.Run("consistent with Base32Address", func(t *testing.T) {
		data := createEd25519X25519DestinationBytes(t)
		dest, _, err := ReadDestination(data)
		require.NoError(t, err)

		addr, err := dest.Base32Address()
		require.NoError(t, err)
		assert.Equal(t, addr, dest.String())
	})
}
