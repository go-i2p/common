package router_identity

import (
	"crypto/rand"
	"testing"

	"github.com/go-i2p/common/certificate"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/keys_and_cert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//
// Integration / Round-trip tests
//

// TestRouterIdentityRoundTrip verifies constructor and serialization work together
func TestRouterIdentityRoundTrip(t *testing.T) {
	t.Run("NewRouterIdentityFromKeysAndCert round trip", func(t *testing.T) {
		keysAndCert := createValidKeysAndCert(t)
		ri1, err := NewRouterIdentityFromKeysAndCert(keysAndCert)
		require.NoError(t, err)

		bytes1, err := ri1.KeysAndCert.Bytes()
		require.NoError(t, err)

		ri2, remainder, err := NewRouterIdentityFromBytes(bytes1)
		require.NoError(t, err)
		assert.Empty(t, remainder)

		assert.True(t, ri1.IsValid())
		assert.True(t, ri2.IsValid())

		bytes2, err := ri2.KeysAndCert.Bytes()
		require.NoError(t, err)
		assert.Equal(t, bytes1, bytes2, "round-trip bytes must be identical")
	})

	t.Run("validation after construction", func(t *testing.T) {
		keysAndCert := createValidKeysAndCert(t)
		ri, err := NewRouterIdentityFromKeysAndCert(keysAndCert)
		require.NoError(t, err)

		assert.NoError(t, ri.Validate())
		assert.True(t, ri.IsValid())
	})
}

// TestRoundTripByteEquality verifies byte-level round-trip equality
func TestRoundTripByteEquality(t *testing.T) {
	kac := createValidKeysAndCert(t)
	ri1, err := NewRouterIdentityFromKeysAndCert(kac)
	require.NoError(t, err)

	bytes1, err := ri1.KeysAndCert.Bytes()
	require.NoError(t, err)

	ri2, remainder, err := NewRouterIdentityFromBytes(bytes1)
	require.NoError(t, err)
	assert.Empty(t, remainder)

	bytes2, err := ri2.KeysAndCert.Bytes()
	require.NoError(t, err)

	assert.Equal(t, bytes1, bytes2, "round-trip bytes must be identical")
	assert.True(t, ri1.Equal(ri2), "round-trip identities must be Equal()")
}

// TestBuilderIntegration tests the certificate builder integration
func TestBuilderIntegration(t *testing.T) {
	t.Run("build with certificate builder", func(t *testing.T) {
		builder := certificate.NewCertificateBuilder()
		builder, err := builder.WithKeyTypes(key_certificate.KEYCERT_SIGN_ED25519, key_certificate.KEYCERT_CRYPTO_X25519)
		require.NoError(t, err)
		cert, err := builder.Build()
		if err != nil {
			t.Skip("certificate builder not available:", err)
		}

		pubKey := make([]byte, 32)
		_, _ = rand.Read(pubKey)
		sigKey := make([]byte, 32)
		_, _ = rand.Read(sigKey)

		paddingSize := keys_and_cert.KEYS_AND_CERT_DATA_SIZE - 32 - 32
		padding, err := keys_and_cert.GenerateCompressiblePadding(paddingSize)
		require.NoError(t, err)

		ri, err := NewRouterIdentity(
			mockPublicKey(pubKey),
			mockSigningPublicKey(sigKey),
			cert,
			padding,
		)
		require.NoError(t, err)
		require.NotNil(t, ri)
		assert.True(t, ri.IsValid())
	})
}
