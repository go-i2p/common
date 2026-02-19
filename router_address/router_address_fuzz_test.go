package router_address

import (
	"testing"

	"github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
)

func FuzzReadRouterAddress(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x05})
	f.Add(make([]byte, 12))

	valid := []byte{0x05}
	valid = append(valid, make([]byte, 8)...)
	valid = append(valid, 0x00)
	valid = append(valid, 0x00, 0x00)
	f.Add(valid)

	withOpts := []byte{0x05}
	withOpts = append(withOpts, make([]byte, 8)...)
	ts, _ := data.ToI2PString("NTCP2")
	withOpts = append(withOpts, ts...)
	m, _ := data.GoMapToMapping(map[string]string{"host": "127.0.0.1"})
	withOpts = append(withOpts, m.Data()...)
	f.Add(withOpts)

	f.Fuzz(func(t *testing.T, input []byte) {
		ra, remainder, err := ReadRouterAddress(input)
		if err == nil {
			_ = ra.Cost()
			_ = ra.Expiration()
			_ = ra.TransportStyle()
			_ = ra.Options()
			_ = ra.Bytes()
		}
		_ = remainder
	})
}

func TestCorrectsFuzzCrasher1(t *testing.T) {
	assert := assert.New(t)

	defer func() {
		if r := recover(); r != nil {
			assert.Equal(nil, r)
		}
	}()

	router_address_bytes := []byte{0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x00, 0x30, 0x30}
	ReadRouterAddress(router_address_bytes)
}
