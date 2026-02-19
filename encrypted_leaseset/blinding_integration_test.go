package encrypted_leaseset

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/go-i2p/common/destination"
	"github.com/go-i2p/crypto/kdf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ————————————————————————————————————————————————
// Integration tests and benchmarks for blinding round-trips
// Source: blinding.go
// ————————————————————————————————————————————————

func TestBlindingRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		date time.Time
	}{
		{"Date 2025-11-24", time.Date(2025, 11, 24, 12, 0, 0, 0, time.UTC)},
		{"Date 2025-12-01", time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC)},
		{"Date 2026-01-01", time.Date(2026, 1, 1, 23, 59, 59, 0, time.UTC)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := createTestEd25519Destination(t)

			secret := make([]byte, 32)
			_, _ = rand.Read(secret)

			blinded, err := CreateBlindedDestination(original, secret, tt.date)
			require.NoError(t, err, "Blinding should succeed")

			dateStr := tt.date.UTC().Format("2006-01-02")
			alpha, err := kdf.DeriveBlindingFactor(secret, dateStr)
			require.NoError(t, err, "Alpha derivation should succeed")

			valid := VerifyBlindedSignature(blinded, original, alpha)
			assert.True(t, valid, "Round-trip verification should succeed")

			origKey, err := original.SigningPublicKey()
			require.NoError(t, err)
			blindedKey, err := blinded.SigningPublicKey()
			require.NoError(t, err)
			assert.NotEqual(t, origKey.Bytes(), blindedKey.Bytes(),
				"Blinded key must differ from original")
		})
	}
}

func TestBlindingPreservesEncryptionKey(t *testing.T) {
	original := createTestEd25519Destination(t)
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	date := time.Now()

	blinded, err := CreateBlindedDestination(original, secret, date)
	require.NoError(t, err, "Blinding should succeed")

	assert.Equal(t, original.ReceivingPublic, blinded.ReceivingPublic,
		"Encryption key should remain unchanged")
}

func BenchmarkCreateBlindedDestination(b *testing.B) {
	var dest destination.Destination
	var secret []byte

	b.Run("setup", func(b *testing.B) {
		b.StopTimer()
		t := &testing.T{}
		dest = createTestEd25519Destination(t)
		secret = make([]byte, 32)
		_, _ = rand.Read(secret)
		b.StartTimer()
	})

	if len(secret) == 0 {
		destBytes := make([]byte, 391)
		rand.Read(destBytes[:384])
		destBytes[384] = 0x05
		destBytes[385] = 0x00
		destBytes[386] = 0x04
		destBytes[387] = 0x00
		destBytes[388] = 0x07
		destBytes[389] = 0x00
		destBytes[390] = 0x00
		dest, _, _ = destination.ReadDestination(destBytes)
		secret = make([]byte, 32)
		rand.Read(secret)
	}

	date := time.Now()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = CreateBlindedDestination(dest, secret, date)
	}
}

func BenchmarkVerifyBlindedSignature(b *testing.B) {
	destBytes := make([]byte, 391)
	rand.Read(destBytes[:384])
	destBytes[384] = 0x05
	destBytes[385] = 0x00
	destBytes[386] = 0x04
	destBytes[387] = 0x00
	destBytes[388] = 0x07
	destBytes[389] = 0x00
	destBytes[390] = 0x00
	dest, _, _ := destination.ReadDestination(destBytes)

	secret := make([]byte, 32)
	rand.Read(secret)
	date := time.Date(2025, 11, 24, 0, 0, 0, 0, time.UTC)

	blinded, _ := CreateBlindedDestination(dest, secret, date)
	alpha, _ := kdf.DeriveBlindingFactor(secret, "2025-11-24")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VerifyBlindedSignature(blinded, dest, alpha)
	}
}
