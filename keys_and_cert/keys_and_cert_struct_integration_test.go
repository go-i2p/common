package keys_and_cert

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Concurrent access safety
// ============================================================================

func TestKeysAndCertConcurrentAccess(t *testing.T) {
	kac := createValidKeyAndCert(t)

	var wg sync.WaitGroup
	const goroutines = 20

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = kac.IsValid()
			_, _ = kac.PublicKey()
			_, _ = kac.SigningPublicKey()
			_, _ = kac.Bytes()
			_ = kac.Certificate()
		}()
	}
	wg.Wait()
}

// ============================================================================
// Padding consistency between generic and specialized read paths
// ============================================================================

func TestPaddingConsistencyBetweenReadPaths(t *testing.T) {
	wireData := buildElgEd25519Data(t)

	kac1, _, err := ReadKeysAndCert(wireData)
	require.NoError(t, err)

	kac2, _, err := ReadKeysAndCertElgAndEd25519(wireData)
	require.NoError(t, err)

	assert.Equal(t, kac1.Padding, kac2.Padding,
		"generic and specialized read paths should produce identical padding")
}
