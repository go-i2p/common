package lease_set

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConstants_LeaseSetPubKeySize(t *testing.T) {
	assert.Equal(t, 256, LEASE_SET_PUBKEY_SIZE)
}

func TestConstants_LeaseSetDefaultSigningKeySize(t *testing.T) {
	assert.Equal(t, 128, LEASE_SET_DEFAULT_SIGNING_KEY_SIZE)
}

func TestConstants_LeaseSetDefaultSigSize(t *testing.T) {
	assert.Equal(t, 40, LEASE_SET_DEFAULT_SIG_SIZE)
}

func TestConstants_LeaseSetSPKSizeIsAlias(t *testing.T) {
	assert.Equal(t, LEASE_SET_DEFAULT_SIGNING_KEY_SIZE, LEASE_SET_SPK_SIZE,
		"LEASE_SET_SPK_SIZE should be a deprecated alias for LEASE_SET_DEFAULT_SIGNING_KEY_SIZE")
}

func TestConstants_LeaseSetSigSizeIsAlias(t *testing.T) {
	assert.Equal(t, LEASE_SET_DEFAULT_SIG_SIZE, LEASE_SET_SIG_SIZE,
		"LEASE_SET_SIG_SIZE should be a deprecated alias for LEASE_SET_DEFAULT_SIG_SIZE")
}

func TestConstants_LeaseSetMaxLeases(t *testing.T) {
	assert.Equal(t, 16, LEASE_SET_MAX_LEASES)
}

func TestConstants_ErrNoLeasesNotNil(t *testing.T) {
	assert.NotNil(t, ErrNoLeases)
}

func TestConstants_ErrNoLeasesMessage(t *testing.T) {
	assert.Contains(t, ErrNoLeases.Error(), "no leases")
}
