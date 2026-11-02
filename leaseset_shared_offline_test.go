package common

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/offline_signature"
	sigpkg "github.com/go-i2p/common/signature"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- VerifyOfflineSignatureChain -------------------------------------------

func TestVerifyOfflineSignatureChain_NilSignature(t *testing.T) {
	err := VerifyOfflineSignatureChain(nil, []byte{0x01}, "TestStruct")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nil")
}

func TestVerifyOfflineSignatureChain_EmptyAuthorizingKey(t *testing.T) {
	transientPub, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	offSig, err := offline_signature.NewOfflineSignature(
		uint32(time.Now().Add(time.Hour).Unix()),
		uint16(key_certificate.KEYCERT_SIGN_ED25519),
		transientPub,
		make([]byte, sigpkg.EdDSA_SHA512_Ed25519_SIZE),
		uint16(key_certificate.KEYCERT_SIGN_ED25519),
	)
	require.NoError(t, err)

	err = VerifyOfflineSignatureChain(&offSig, nil, "TestStruct")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no authorizing public key")
}

func TestVerifyOfflineSignatureChain_ForgedSignatureRejected(t *testing.T) {
	destPub, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	transientPub, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	forged := make([]byte, sigpkg.EdDSA_SHA512_Ed25519_SIZE)
	offSig, err := offline_signature.NewOfflineSignature(
		uint32(time.Now().Add(time.Hour).Unix()),
		uint16(key_certificate.KEYCERT_SIGN_ED25519),
		transientPub,
		forged,
		uint16(key_certificate.KEYCERT_SIGN_ED25519),
	)
	require.NoError(t, err)

	err = VerifyOfflineSignatureChain(&offSig, destPub, "TestStruct")
	assert.Error(t, err, "a transient key the destination never signed must be rejected")
	assert.Contains(t, err.Error(), "offline signature invalid")
}

func TestVerifyOfflineSignatureChain_ExpiredRejected(t *testing.T) {
	destPub, destPriv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	transientPub, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	offSig, err := offline_signature.CreateOfflineSignature(
		uint32(time.Now().Add(-time.Minute).Unix()),
		key_certificate.KEYCERT_SIGN_ED25519,
		transientPub,
		destPriv,
		key_certificate.KEYCERT_SIGN_ED25519,
	)
	require.NoError(t, err)

	err = VerifyOfflineSignatureChain(&offSig, destPub, "TestStruct")
	assert.Error(t, err, "an expired authorization must be rejected")
	assert.Contains(t, err.Error(), "expired")
}

func TestVerifyOfflineSignatureChain_ValidAccepted(t *testing.T) {
	destPub, destPriv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	transientPub, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	offSig, err := offline_signature.CreateOfflineSignature(
		uint32(time.Now().Add(time.Hour).Unix()),
		key_certificate.KEYCERT_SIGN_ED25519,
		transientPub,
		destPriv,
		key_certificate.KEYCERT_SIGN_ED25519,
	)
	require.NoError(t, err)

	assert.NoError(t, VerifyOfflineSignatureChain(&offSig, destPub, "TestStruct"))
}
