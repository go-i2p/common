package encrypted_leaseset

import (
	"testing"
	"time"

	"github.com/go-i2p/crypto/rand"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ————————————————————————————————————————————————
// Per-client authorization tests (auth type 1 DH / 2 PSK)
// Source: client_auth.go + encryption.go
// Spec: https://i2p.net/en/docs/specs/encryptedleaseset §"Per-client authorization"
// ————————————————————————————————————————————————

// newX25519Keypair returns a random X25519 (csk, cpk) pair for DH client auth tests.
func newX25519Keypair(t *testing.T) (csk, cpk []byte) {
	t.Helper()
	csk = make([]byte, ENCRYPTED_LEASESET_X25519_KEY_SIZE)
	_, err := rand.Read(csk)
	require.NoError(t, err)
	cpk, err = x25519DerivePublic(csk)
	require.NoError(t, err)
	return csk, cpk
}

// newPSK returns a random 32-byte pre-shared key for PSK client auth tests.
func newPSK(t *testing.T) []byte {
	t.Helper()
	psk := make([]byte, ENCRYPTED_LEASESET_PSK_SIZE)
	_, err := rand.Read(psk)
	require.NoError(t, err)
	return psk
}

func randomSubcredential(t *testing.T) [32]byte {
	t.Helper()
	var subcred [32]byte
	_, err := rand.Read(subcred[:])
	require.NoError(t, err)
	return subcred
}

// ——— DH client authorization ———

func TestDHClientAuthRoundTrip(t *testing.T) {
	ls2 := createTestLeaseSet2ForEncryption(t)
	subcred := randomSubcredential(t)
	published := uint32(time.Now().Unix())

	csk, cpk := newX25519Keypair(t)
	cfg := &ClientAuthConfig{
		AuthType:           ENCRYPTED_LEASESET_AUTH_TYPE_DH,
		DHClientPublicKeys: [][]byte{cpk},
	}

	encryptedData, err := EncryptInnerLeaseSet2WithAuth(ls2, subcred, published, cfg)
	require.NoError(t, err)

	els := &EncryptedLeaseSet{encryptedInnerData: encryptedData, published: published}
	cred := &ClientCredential{AuthType: ENCRYPTED_LEASESET_AUTH_TYPE_DH, DHPrivateKey: csk}

	decrypted, err := els.DecryptInnerDataWithCredential(subcred, cred)
	require.NoError(t, err)
	require.NotNil(t, decrypted)
	assert.Equal(t, ls2.Published(), decrypted.Published())
	assert.Equal(t, len(ls2.Leases()), len(decrypted.Leases()))
}

func TestDHClientAuthMultipleClients(t *testing.T) {
	ls2 := createTestLeaseSet2ForEncryption(t)
	subcred := randomSubcredential(t)
	published := uint32(time.Now().Unix())

	const n = 3
	csks := make([][]byte, n)
	cpks := make([][]byte, n)
	for i := 0; i < n; i++ {
		csks[i], cpks[i] = newX25519Keypair(t)
	}

	cfg := &ClientAuthConfig{
		AuthType:           ENCRYPTED_LEASESET_AUTH_TYPE_DH,
		DHClientPublicKeys: cpks,
	}
	encryptedData, err := EncryptInnerLeaseSet2WithAuth(ls2, subcred, published, cfg)
	require.NoError(t, err)

	els := &EncryptedLeaseSet{encryptedInnerData: encryptedData, published: published}
	for i := 0; i < n; i++ {
		cred := &ClientCredential{AuthType: ENCRYPTED_LEASESET_AUTH_TYPE_DH, DHPrivateKey: csks[i]}
		decrypted, err := els.DecryptInnerDataWithCredential(subcred, cred)
		require.NoError(t, err, "authorized client %d must decrypt", i)
		require.NotNil(t, decrypted)
	}
}

func TestDHClientAuthUnauthorizedClientFails(t *testing.T) {
	ls2 := createTestLeaseSet2ForEncryption(t)
	subcred := randomSubcredential(t)
	published := uint32(time.Now().Unix())

	_, cpk := newX25519Keypair(t)
	cfg := &ClientAuthConfig{
		AuthType:           ENCRYPTED_LEASESET_AUTH_TYPE_DH,
		DHClientPublicKeys: [][]byte{cpk},
	}
	encryptedData, err := EncryptInnerLeaseSet2WithAuth(ls2, subcred, published, cfg)
	require.NoError(t, err)

	els := &EncryptedLeaseSet{encryptedInnerData: encryptedData, published: published}

	// Different (unauthorized) client key.
	otherCsk, _ := newX25519Keypair(t)
	cred := &ClientCredential{AuthType: ENCRYPTED_LEASESET_AUTH_TYPE_DH, DHPrivateKey: otherCsk}

	_, err = els.DecryptInnerDataWithCredential(subcred, cred)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not authorized")
}

func TestDHClientAuthMissingCredentialFails(t *testing.T) {
	ls2 := createTestLeaseSet2ForEncryption(t)
	subcred := randomSubcredential(t)
	published := uint32(time.Now().Unix())

	_, cpk := newX25519Keypair(t)
	cfg := &ClientAuthConfig{
		AuthType:           ENCRYPTED_LEASESET_AUTH_TYPE_DH,
		DHClientPublicKeys: [][]byte{cpk},
	}
	encryptedData, err := EncryptInnerLeaseSet2WithAuth(ls2, subcred, published, cfg)
	require.NoError(t, err)

	els := &EncryptedLeaseSet{encryptedInnerData: encryptedData, published: published}

	// DecryptInnerData (no credential) must fail on a per-client LeaseSet.
	_, err = els.DecryptInnerData(subcred)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires a ClientCredential")
}

// ——— PSK client authorization ———

func TestPSKClientAuthRoundTrip(t *testing.T) {
	ls2 := createTestLeaseSet2ForEncryption(t)
	subcred := randomSubcredential(t)
	published := uint32(time.Now().Unix())

	psk := newPSK(t)
	cfg := &ClientAuthConfig{
		AuthType:      ENCRYPTED_LEASESET_AUTH_TYPE_PSK,
		PSKClientKeys: [][]byte{psk},
	}
	encryptedData, err := EncryptInnerLeaseSet2WithAuth(ls2, subcred, published, cfg)
	require.NoError(t, err)

	els := &EncryptedLeaseSet{encryptedInnerData: encryptedData, published: published}
	cred := &ClientCredential{AuthType: ENCRYPTED_LEASESET_AUTH_TYPE_PSK, PSK: psk}

	decrypted, err := els.DecryptInnerDataWithCredential(subcred, cred)
	require.NoError(t, err)
	require.NotNil(t, decrypted)
	assert.Equal(t, ls2.Published(), decrypted.Published())
	assert.Equal(t, len(ls2.Leases()), len(decrypted.Leases()))
}

func TestPSKClientAuthMultipleClients(t *testing.T) {
	ls2 := createTestLeaseSet2ForEncryption(t)
	subcred := randomSubcredential(t)
	published := uint32(time.Now().Unix())

	const n = 4
	psks := make([][]byte, n)
	for i := 0; i < n; i++ {
		psks[i] = newPSK(t)
	}
	cfg := &ClientAuthConfig{
		AuthType:      ENCRYPTED_LEASESET_AUTH_TYPE_PSK,
		PSKClientKeys: psks,
	}
	encryptedData, err := EncryptInnerLeaseSet2WithAuth(ls2, subcred, published, cfg)
	require.NoError(t, err)

	els := &EncryptedLeaseSet{encryptedInnerData: encryptedData, published: published}
	for i := 0; i < n; i++ {
		cred := &ClientCredential{AuthType: ENCRYPTED_LEASESET_AUTH_TYPE_PSK, PSK: psks[i]}
		decrypted, err := els.DecryptInnerDataWithCredential(subcred, cred)
		require.NoError(t, err, "authorized client %d must decrypt", i)
		require.NotNil(t, decrypted)
	}
}

func TestPSKClientAuthWrongKeyFails(t *testing.T) {
	ls2 := createTestLeaseSet2ForEncryption(t)
	subcred := randomSubcredential(t)
	published := uint32(time.Now().Unix())

	psk := newPSK(t)
	cfg := &ClientAuthConfig{
		AuthType:      ENCRYPTED_LEASESET_AUTH_TYPE_PSK,
		PSKClientKeys: [][]byte{psk},
	}
	encryptedData, err := EncryptInnerLeaseSet2WithAuth(ls2, subcred, published, cfg)
	require.NoError(t, err)

	els := &EncryptedLeaseSet{encryptedInnerData: encryptedData, published: published}
	cred := &ClientCredential{AuthType: ENCRYPTED_LEASESET_AUTH_TYPE_PSK, PSK: newPSK(t)}

	_, err = els.DecryptInnerDataWithCredential(subcred, cred)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not authorized")
}

func TestClientAuthTypeMismatchFails(t *testing.T) {
	ls2 := createTestLeaseSet2ForEncryption(t)
	subcred := randomSubcredential(t)
	published := uint32(time.Now().Unix())

	psk := newPSK(t)
	cfg := &ClientAuthConfig{
		AuthType:      ENCRYPTED_LEASESET_AUTH_TYPE_PSK,
		PSKClientKeys: [][]byte{psk},
	}
	encryptedData, err := EncryptInnerLeaseSet2WithAuth(ls2, subcred, published, cfg)
	require.NoError(t, err)

	els := &EncryptedLeaseSet{encryptedInnerData: encryptedData, published: published}

	// Supplying a DH credential for a PSK LeaseSet must be rejected.
	csk, _ := newX25519Keypair(t)
	cred := &ClientCredential{AuthType: ENCRYPTED_LEASESET_AUTH_TYPE_DH, DHPrivateKey: csk}
	_, err = els.DecryptInnerDataWithCredential(subcred, cred)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not match")
}

// ——— No-auth backward compatibility ———

func TestNoAuthCredentialIgnored(t *testing.T) {
	ls2 := createTestLeaseSet2ForEncryption(t)
	subcred := randomSubcredential(t)
	published := uint32(time.Now().Unix())

	// Encrypt without per-client auth.
	encryptedData, err := EncryptInnerLeaseSet2(ls2, subcred, published)
	require.NoError(t, err)

	els := &EncryptedLeaseSet{encryptedInnerData: encryptedData, published: published}

	// A spurious credential is harmless for an auth-type-0 LeaseSet (no auth block).
	csk, _ := newX25519Keypair(t)
	cred := &ClientCredential{AuthType: ENCRYPTED_LEASESET_AUTH_TYPE_DH, DHPrivateKey: csk}
	decrypted, err := els.DecryptInnerDataWithCredential(subcred, cred)
	require.NoError(t, err)
	require.NotNil(t, decrypted)
}

// ——— Config / credential validation ———

func TestEncryptWithAuthRejectsInvalidConfig(t *testing.T) {
	ls2 := createTestLeaseSet2ForEncryption(t)
	subcred := randomSubcredential(t)
	published := uint32(time.Now().Unix())

	cases := map[string]*ClientAuthConfig{
		"DH no clients":     {AuthType: ENCRYPTED_LEASESET_AUTH_TYPE_DH},
		"PSK no clients":    {AuthType: ENCRYPTED_LEASESET_AUTH_TYPE_PSK},
		"DH bad key size":   {AuthType: ENCRYPTED_LEASESET_AUTH_TYPE_DH, DHClientPublicKeys: [][]byte{make([]byte, 10)}},
		"PSK bad key size":  {AuthType: ENCRYPTED_LEASESET_AUTH_TYPE_PSK, PSKClientKeys: [][]byte{make([]byte, 10)}},
		"unknown auth type": {AuthType: 99},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := EncryptInnerLeaseSet2WithAuth(ls2, subcred, published, cfg)
			require.Error(t, err)
		})
	}
}

func TestDecryptWithInvalidCredentialSize(t *testing.T) {
	ls2 := createTestLeaseSet2ForEncryption(t)
	subcred := randomSubcredential(t)
	published := uint32(time.Now().Unix())

	_, cpk := newX25519Keypair(t)
	cfg := &ClientAuthConfig{AuthType: ENCRYPTED_LEASESET_AUTH_TYPE_DH, DHClientPublicKeys: [][]byte{cpk}}
	encryptedData, err := EncryptInnerLeaseSet2WithAuth(ls2, subcred, published, cfg)
	require.NoError(t, err)

	els := &EncryptedLeaseSet{encryptedInnerData: encryptedData, published: published}
	cred := &ClientCredential{AuthType: ENCRYPTED_LEASESET_AUTH_TYPE_DH, DHPrivateKey: make([]byte, 5)}
	_, err = els.DecryptInnerDataWithCredential(subcred, cred)
	require.Error(t, err)
}

// ——— Flag-byte encoding ———

func TestAuthFlagByteRoundTrip(t *testing.T) {
	cases := []byte{
		ENCRYPTED_LEASESET_AUTH_TYPE_NONE,
		ENCRYPTED_LEASESET_AUTH_TYPE_DH,
		ENCRYPTED_LEASESET_AUTH_TYPE_PSK,
	}
	for _, authType := range cases {
		flag, err := authFlagByte(authType)
		require.NoError(t, err)
		got, err := parseAuthFlag(flag)
		require.NoError(t, err)
		assert.Equal(t, authType, got)
	}
}

func TestAuthFlagByteValues(t *testing.T) {
	// Verify exact wire encoding per spec (bit 0 = per-client, bits 3-1 = scheme).
	none, _ := authFlagByte(ENCRYPTED_LEASESET_AUTH_TYPE_NONE)
	dh, _ := authFlagByte(ENCRYPTED_LEASESET_AUTH_TYPE_DH)
	psk, _ := authFlagByte(ENCRYPTED_LEASESET_AUTH_TYPE_PSK)
	assert.Equal(t, byte(0x00), none, "no auth → 0x00")
	assert.Equal(t, byte(0x01), dh, "DH → bit0 set, scheme 000")
	assert.Equal(t, byte(0x03), psk, "PSK → bit0 set, scheme 001")
}
