package router_address

import (
	"testing"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
)

func FuzzReadRouterAddress(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x05})
	f.Add(make([]byte, 12))

	// emptyTransportSeed has a zero-length I2PString transport_style (0x00 prefix byte),
	// which parseTransportType rejects with ErrEmptyTransportStyle.  It is kept as a
	// seed to exercise the empty-transport rejection path, but it is NOT a valid address.
	emptyTransportSeed := []byte{0x05}
	emptyTransportSeed = append(emptyTransportSeed, make([]byte, 8)...)
	emptyTransportSeed = append(emptyTransportSeed, 0x00)
	emptyTransportSeed = append(emptyTransportSeed, 0x00, 0x00)
	f.Add(emptyTransportSeed)

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

func FuzzBytesRoundTrip(f *testing.F) {
	f.Add(uint8(5), "NTCP2", "127.0.0.1", "9150")
	f.Add(uint8(0), "SSU2", "10.0.0.1", "4567")
	f.Add(uint8(255), "NTCP2", "::1", "443")
	f.Add(uint8(10), "SSU", "192.168.1.1", "8080")

	f.Fuzz(func(t *testing.T, cost uint8, transport string, host string, port string) {
		if transport == "" {
			return
		}
		if len(transport) > 200 {
			return
		}

		ra, err := NewRouterAddress(cost, time.Time{}, transport, map[string]string{
			"host": host,
			"port": port,
		})
		if err != nil {
			return
		}

		serialized := ra.Bytes()
		if serialized == nil {
			return
		}

		parsed, _, err := ReadRouterAddress(serialized)
		if err != nil {
			t.Errorf("ReadRouterAddress failed on Bytes() output: %v", err)
			return
		}

		if ra.Cost() != parsed.Cost() {
			t.Errorf("Cost mismatch: %d != %d", ra.Cost(), parsed.Cost())
		}
	})
}
