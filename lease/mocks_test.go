package lease

import (
	"testing"

	"github.com/go-i2p/common/data"
	"github.com/stretchr/testify/require"
)

// createTestHash creates a test hash from a string (must be 32 bytes)
func createTestHash(t *testing.T, s string) data.Hash {
	t.Helper()
	if len(s) != 32 {
		t.Fatalf("test hash string must be exactly 32 bytes, got %d", len(s))
	}
	hash, err := data.NewHashFromSlice([]byte(s))
	require.NoError(t, err)
	return hash
}
