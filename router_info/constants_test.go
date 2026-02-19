package router_info

import (
	"testing"

	"github.com/go-i2p/common/signature"
	"github.com/stretchr/testify/assert"
)

func TestRouterInfoMinSizeConstant(t *testing.T) {
	assert.Equal(t, 439, ROUTER_INFO_MIN_SIZE)
}

func TestMinGoodVersionConstant(t *testing.T) {
	assert.Equal(t, 58, MIN_GOOD_VERSION)
}

func TestMaxGoodVersionConstant(t *testing.T) {
	assert.Equal(t, 99, MAX_GOOD_VERSION)
}

func TestI2PNetworkNameConstant(t *testing.T) {
	assert.Equal(t, "i2p", I2P_NETWORK_NAME)
}

func TestEd25519PrivateKeySizeConstant(t *testing.T) {
	assert.Equal(t, 64, ED25519_PRIVATE_KEY_SIZE)
}

func TestSignatureTypeConstants(t *testing.T) {
	// Verify our test code references correct sig type values
	assert.Equal(t, 0, signature.SIGNATURE_TYPE_DSA_SHA1)
	assert.Equal(t, 7, signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
}
