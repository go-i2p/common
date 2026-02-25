package lease_set

import (
	"github.com/go-i2p/crypto/rand"
	"errors"
	"testing"

	"github.com/go-i2p/common/certificate"
	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/lease"
	elgamal "github.com/go-i2p/crypto/elg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Creation tests ---

func TestUnit_LeaseSetCreation(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 1)
	require.NoError(t, err)
	require.NotNil(t, leaseSet)

	dest := leaseSet.Destination()
	assert.NotNil(t, dest)

	keysAndCert := dest.KeysAndCert
	pubKeySize := keysAndCert.KeyCertificate.CryptoSize()
	assert.Equal(t, 256, pubKeySize, "CryptoPublicKeySize should be 256 bytes for ElGamal")

	sigKeySize := keysAndCert.KeyCertificate.SigningPublicKeySize()
	assert.Equal(t, 32, sigKeySize, "SigningPublicKeySize should be 32 bytes for Ed25519")
}

func TestUnit_LeaseSetCreationMultipleLeases(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 3)
	require.NoError(t, err)
	require.NotNil(t, leaseSet)

	assert.Equal(t, 3, leaseSet.LeaseCount())
	assert.Equal(t, 3, len(leaseSet.Leases()))
}

func TestUnit_NewLeaseSetZeroLeases(t *testing.T) {
	dest, encKey, sigKey, sigPrivKey, err := generateTestDestination(t)
	require.NoError(t, err)

	leaseSet, err := NewLeaseSet(*dest, encKey, sigKey, []lease.Lease{}, sigPrivKey)
	require.NoError(t, err)
	require.NotNil(t, leaseSet)

	assert.Equal(t, 0, leaseSet.LeaseCount())
	assert.Empty(t, leaseSet.Leases())

	err = leaseSet.Validate()
	assert.NoError(t, err, "zero-lease LeaseSet should be valid per spec")
}

// --- Accessor tests ---

func TestUnit_Destination(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 1)
	require.NoError(t, err)

	dest := leaseSet.Destination()
	assert.NotNil(t, dest.KeysAndCert)
}

func TestUnit_PublicKey(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 1)
	require.NoError(t, err)

	pubKey, err := leaseSet.PublicKey()
	assert.NoError(t, err)
	assert.Equal(t, LEASE_SET_PUBKEY_SIZE, len(pubKey.Bytes()))
}

func TestUnit_SigningKey(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 1)
	require.NoError(t, err)

	sigKey, err := leaseSet.SigningKey()
	assert.NoError(t, err)
	assert.NotNil(t, sigKey)
	assert.Equal(t, 32, len(sigKey.Bytes()), "Ed25519 signing key should be 32 bytes")
}

func TestUnit_LeaseCount(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 3)
	require.NoError(t, err)

	assert.Equal(t, 3, leaseSet.LeaseCount())
}

func TestUnit_Leases(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 3)
	require.NoError(t, err)

	leases := leaseSet.Leases()
	assert.Equal(t, 3, len(leases))
}

func TestUnit_Signature(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 1)
	require.NoError(t, err)

	sig := leaseSet.Signature()
	assert.NotNil(t, sig)
	assert.Equal(t, 64, len(sig.Bytes()), "Ed25519 signature should be 64 bytes")
}

// --- Expiration tests ---

func TestUnit_NewestExpiration(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 3)
	require.NoError(t, err)

	newest, err := leaseSet.NewestExpiration()
	assert.NoError(t, err)
	assert.NotNil(t, newest)
}

func TestUnit_OldestExpiration(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 3)
	require.NoError(t, err)

	oldest, err := leaseSet.OldestExpiration()
	assert.NoError(t, err)
	assert.NotNil(t, oldest)
}

func TestUnit_ExpirationOrdering(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 3)
	require.NoError(t, err)

	newest, err := leaseSet.NewestExpiration()
	require.NoError(t, err)

	oldest, err := leaseSet.OldestExpiration()
	require.NoError(t, err)

	assert.True(t, oldest.Time().Before(newest.Time()) || oldest.Time().Equal(newest.Time()),
		"oldest should be before or equal to newest")
}

func TestUnit_OldestExpirationSentinel(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 3)
	require.NoError(t, err)

	oldest, err := leaseSet.OldestExpiration()
	require.NoError(t, err)

	leases := leaseSet.Leases()
	for _, l := range leases {
		assert.True(t, oldest.Time().Equal(l.Date().Time()) || oldest.Time().Before(l.Date().Time()),
			"oldest should be <= all lease dates")
	}
}

func TestUnit_NewestExpirationSingleLease(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 1)
	require.NoError(t, err)

	newest, err := leaseSet.NewestExpiration()
	require.NoError(t, err)

	oldest, err := leaseSet.OldestExpiration()
	require.NoError(t, err)

	assert.True(t, newest.Time().Equal(oldest.Time()),
		"single lease: newest and oldest should be equal")
}

func TestUnit_ExpirationNoLeases(t *testing.T) {
	ls := LeaseSet{
		leaseCount: 0,
		leases:     []lease.Lease{},
	}

	t.Run("NewestExpiration returns ErrNoLeases", func(t *testing.T) {
		newest, err := ls.NewestExpiration()
		assert.ErrorIs(t, err, ErrNoLeases)
		assert.Equal(t, data.Date{}, newest)
	})

	t.Run("OldestExpiration returns ErrNoLeases", func(t *testing.T) {
		oldest, err := ls.OldestExpiration()
		assert.ErrorIs(t, err, ErrNoLeases)
		assert.Equal(t, data.Date{}, oldest)
	})
}

// --- Validate tests ---

func TestUnit_ValidateNilLeaseSet(t *testing.T) {
	var ls *LeaseSet
	err := ls.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "lease set is nil")
}

func TestUnit_ValidateValid(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 3)
	require.NoError(t, err)

	err = leaseSet.Validate()
	assert.NoError(t, err)
}

func TestUnit_ValidateSingleLease(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 1)
	require.NoError(t, err)

	err = leaseSet.Validate()
	assert.NoError(t, err)
}

func TestUnit_ValidateMaxLeases(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 16)
	require.NoError(t, err)

	err = leaseSet.Validate()
	assert.NoError(t, err)
}

func TestUnit_ValidateZeroSignature(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 1)
	require.NoError(t, err)

	manualLS := &LeaseSet{
		dest:          leaseSet.dest,
		encryptionKey: leaseSet.encryptionKey,
		signingKey:    leaseSet.signingKey,
		leaseCount:    0,
		leases:        []lease.Lease{},
	}

	err = manualLS.Validate()
	assert.NoError(t, err)
}

// --- IsValid tests ---

func TestUnit_IsValidNil(t *testing.T) {
	var ls *LeaseSet
	assert.False(t, ls.IsValid())
}

func TestUnit_IsValidTrue(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 2)
	require.NoError(t, err)
	assert.True(t, leaseSet.IsValid())
}

// --- PublicKey edge cases ---

func TestUnit_PublicKeyNilEncryptionKey(t *testing.T) {
	ls := LeaseSet{}
	_, err := ls.PublicKey()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "encryption key is nil")
}

// --- Bytes with inconsistent leaseCount ---

func TestUnit_BytesInconsistentLeaseCount(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 3)
	require.NoError(t, err)

	inconsistentLS := &LeaseSet{
		dest:          leaseSet.dest,
		encryptionKey: leaseSet.encryptionKey,
		signingKey:    leaseSet.signingKey,
		leaseCount:    5,
		leases:        leaseSet.leases, // only 3
		signature:     leaseSet.signature,
	}

	err = inconsistentLS.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "lease count mismatch")
}

// --- Signing key type check ---

func TestUnit_SigningKeyTypeMatch(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 1)
	require.NoError(t, err)
	require.NotNil(t, leaseSet)

	sigKey, err := leaseSet.SigningKey()
	require.NoError(t, err)
	assert.Equal(t, 32, len(sigKey.Bytes()), "Ed25519 signing key should be 32 bytes")
}

// --- DetermineSignatureSize ---

func TestUnit_DetermineSignatureSizeCorrect(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 1)
	require.NoError(t, err)

	lsBytes, err := leaseSet.Bytes()
	require.NoError(t, err)

	dest := leaseSet.Destination()
	cert := dest.Certificate()
	kind, err := cert.Type()
	require.NoError(t, err)

	sigSize := determineSignatureSize(cert, kind)
	assert.True(t, sigSize > 0, "signature size should be positive")

	// Verify total bytes = dest + encKey + sigKey + 1 (count) + leases + sig
	destBytes, err := dest.KeysAndCert.Bytes()
	require.NoError(t, err)
	sigKey, err := leaseSet.SigningKey()
	require.NoError(t, err)

	expectedMinSize := len(destBytes) + LEASE_SET_PUBKEY_SIZE + len(sigKey.Bytes()) + 1 + sigSize
	assert.True(t, len(lsBytes) >= expectedMinSize)
}

// --- DetermineSigningKeySize ---

func TestUnit_DetermineSigningKeySizeUsesCorrectAPI(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 1)
	require.NoError(t, err)

	dest := leaseSet.Destination()
	cert := dest.Certificate()
	kind, err := cert.Type()
	require.NoError(t, err)

	sigKeySize := determineSigningKeySize(cert, kind)
	assert.Equal(t, 32, sigKeySize, "Ed25519 signing key should be 32 bytes")
}

// --- NewLeaseSet rejects non-ElGamal encryption keys ---

func TestUnit_NewLeaseSetRejectsNonElGamalKey(t *testing.T) {
	dest, _, sigKey, sigPrivKey, err := generateTestDestination(t)
	require.NoError(t, err)

	var fakeKey mockNonElGamalKey
	_, err = rand.Read(fakeKey[:])
	require.NoError(t, err)

	_, err = NewLeaseSet(*dest, fakeKey, sigKey, []lease.Lease{}, sigPrivKey)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrNonElGamalEncryptionKey),
		"expected ErrNonElGamalEncryptionKey, got: %v", err)
}

func TestUnit_NewLeaseSetAcceptsElGamalKey(t *testing.T) {
	dest, encKey, sigKey, sigPrivKey, err := generateTestDestination(t)
	require.NoError(t, err)

	leaseSet, err := NewLeaseSet(*dest, encKey, sigKey, []lease.Lease{}, sigPrivKey)
	assert.NoError(t, err)
	assert.NotNil(t, leaseSet)
}

func TestUnit_NewLeaseSetAcceptsElGamalPointerKey(t *testing.T) {
	dest, _, sigKey, sigPrivKey, err := generateTestDestination(t)
	require.NoError(t, err)

	var elgKey elgamal.ElgPublicKey
	_, err = rand.Read(elgKey[:])
	require.NoError(t, err)

	leaseSet, err := NewLeaseSet(*dest, &elgKey, sigKey, []lease.Lease{}, sigPrivKey)
	assert.NoError(t, err)
	assert.NotNil(t, leaseSet)
}

func TestUnit_NewLeaseSetRejects256ByteNonElGamalKey(t *testing.T) {
	dest, _, sigKey, sigPrivKey, err := generateTestDestination(t)
	require.NoError(t, err)

	var fakeKey mockNonElGamalKey
	_, err = rand.Read(fakeKey[:])
	require.NoError(t, err)

	_, err = NewLeaseSet(*dest, fakeKey, sigKey, []lease.Lease{}, sigPrivKey)
	assert.Error(t, err, "should reject 256-byte non-ElGamal key")
	assert.True(t, errors.Is(err, ErrNonElGamalEncryptionKey))
}

// --- isAllZero helper ---

func TestUnit_IsAllZero(t *testing.T) {
	t.Run("all zeros", func(t *testing.T) {
		assert.True(t, isAllZero(make([]byte, 256)))
	})

	t.Run("not all zeros", func(t *testing.T) {
		b := make([]byte, 256)
		b[128] = 1
		assert.False(t, isAllZero(b))
	})

	t.Run("single non-zero byte", func(t *testing.T) {
		b := make([]byte, 256)
		b[255] = 0xFF
		assert.False(t, isAllZero(b))
	})

	t.Run("empty slice", func(t *testing.T) {
		assert.False(t, isAllZero([]byte{}))
	})
}

// --- isElGamalKey helper ---

func TestUnit_IsElGamalKey(t *testing.T) {
	t.Run("ElgPublicKey value", func(t *testing.T) {
		var key elgamal.ElgPublicKey
		assert.True(t, isElGamalKey(key))
	})

	t.Run("ElgPublicKey pointer", func(t *testing.T) {
		var key elgamal.ElgPublicKey
		assert.True(t, isElGamalKey(&key))
	})

	t.Run("non-ElGamal key", func(t *testing.T) {
		var key mockNonElGamalKey
		assert.False(t, isElGamalKey(key))
	})
}

// --- NULL/DSA certificate component tests ---

func TestUnit_DetermineSigningKeySizeNullCert(t *testing.T) {
	cert, err := certificate.NewCertificateWithType(certificate.CERT_NULL, nil)
	require.NoError(t, err)

	size := determineSigningKeySize(cert, certificate.CERT_NULL)
	assert.Equal(t, LEASE_SET_SPK_SIZE, size,
		"NULL cert should use default 128-byte signing key size")
}

func TestUnit_DetermineSignatureSizeNullCert(t *testing.T) {
	cert, err := certificate.NewCertificateWithType(certificate.CERT_NULL, nil)
	require.NoError(t, err)

	size := determineSignatureSize(cert, certificate.CERT_NULL)
	assert.Equal(t, LEASE_SET_SIG_SIZE, size,
		"NULL cert should use default 40-byte signature size")
}

func TestUnit_DetermineSignatureTypeNullCert(t *testing.T) {
	cert, err := certificate.NewCertificateWithType(certificate.CERT_NULL, nil)
	require.NoError(t, err)

	sigType := determineSignatureType(cert, certificate.CERT_NULL)
	assert.Equal(t, 0, sigType,
		"NULL cert should use DSA_SHA1 signature type (0)")
}

func TestUnit_ConstructSigningKeyNullCert(t *testing.T) {
	cert, err := certificate.NewCertificateWithType(certificate.CERT_NULL, nil)
	require.NoError(t, err)

	keyData := make([]byte, 128)
	_, err = rand.Read(keyData)
	require.NoError(t, err)

	sigKey, err := constructSigningKey(keyData, cert, certificate.CERT_NULL)
	if err != nil {
		// DSA library may reject random bytes that don't satisfy p constraint.
		assert.Contains(t, err.Error(), "DSA",
			"error should mention DSA for NULL cert path")
	} else {
		assert.NotNil(t, sigKey)
		assert.Equal(t, 128, len(sigKey.Bytes()),
			"DSA signing key should be 128 bytes")
	}
}
