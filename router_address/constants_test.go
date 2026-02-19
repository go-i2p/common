package router_address

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRouterAddressMinSizeConstant(t *testing.T) {
	assert.Equal(t, 12, ROUTER_ADDRESS_MIN_SIZE,
		"ROUTER_ADDRESS_MIN_SIZE should be 12")
}

func TestIPVersionStringConstants(t *testing.T) {
	assert.Equal(t, "4", IPV4_VERSION_STRING)
	assert.Equal(t, "6", IPV6_VERSION_STRING)
	assert.Equal(t, "6", IPV6_SUFFIX)
}

func TestTransportConstants(t *testing.T) {
	assert.Equal(t, "ssu", SSU_TRANSPORT_PREFIX)
}

func TestOptionKeyConstants(t *testing.T) {
	assert.Equal(t, "host", HOST_OPTION_KEY)
	assert.Equal(t, "port", PORT_OPTION_KEY)
	assert.Equal(t, "caps", CAPS_OPTION_KEY)
	assert.Equal(t, "s", STATIC_KEY_OPTION_KEY)
	assert.Equal(t, "i", INITIALIZATION_VECTOR_OPTION_KEY)
	assert.Equal(t, "v", PROTOCOL_VERSION_OPTION_KEY)
	assert.Equal(t, "ih", INTRODUCER_HASH_PREFIX)
	assert.Equal(t, "iexp", INTRODUCER_EXPIRATION_PREFIX)
	assert.Equal(t, "itag", INTRODUCER_TAG_PREFIX)
}

func TestCryptographicSizeConstants(t *testing.T) {
	assert.Equal(t, 32, STATIC_KEY_SIZE)
	assert.Equal(t, 16, INITIALIZATION_VECTOR_SIZE)
}

func TestMaxIntroducerNumber(t *testing.T) {
	assert.Equal(t, 2, MAX_INTRODUCER_NUMBER, "MAX_INTRODUCER_NUMBER should be 2 per SSU2 spec")
	assert.Equal(t, 0, MIN_INTRODUCER_NUMBER)
	assert.Equal(t, 0, DEFAULT_INTRODUCER_NUMBER)
}
