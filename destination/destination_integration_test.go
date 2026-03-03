package destination

import (
	"testing"

	"github.com/go-i2p/common/keys_and_cert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// NewDestination -> Bytes -> NewDestinationFromBytes round-trip
// ============================================================================

func TestDestinationRoundTrip(t *testing.T) {
	t.Run("NewDestination -> Bytes -> NewDestinationFromBytes", func(t *testing.T) {
		// Use Ed25519+X25519 to avoid canonicalization side-effects on byte comparison.
		data := createEd25519X25519DestinationBytes(t)
		kac, _, err := keys_and_cert.ReadKeysAndCert(data)
		require.NoError(t, err)

		dest1, err := NewDestination(kac)
		require.NoError(t, err)

		b, err := dest1.Bytes()
		require.NoError(t, err)

		dest2, remainder, err := NewDestinationFromBytes(b)
		require.NoError(t, err)
		assert.Empty(t, remainder)

		assert.True(t, dest1.IsValid())
		assert.True(t, dest2.IsValid())

		addr1, err := dest1.Base32Address()
		require.NoError(t, err)
		addr2, err := dest2.Base32Address()
		require.NoError(t, err)
		assert.Equal(t, addr1, addr2)

		b64_1, err := dest1.Base64()
		require.NoError(t, err)
		b64_2, err := dest2.Base64()
		require.NoError(t, err)
		assert.Equal(t, b64_1, b64_2)
	})

	t.Run("validation after construction", func(t *testing.T) {
		keysAndCert := createValidKeysAndCert(t)
		dest, err := NewDestination(keysAndCert)
		require.NoError(t, err)

		assert.NoError(t, dest.Validate())
		assert.True(t, dest.IsValid())

		_, err = dest.Base32Address()
		assert.NoError(t, err)
		_, err = dest.Base64()
		assert.NoError(t, err)
	})
}
