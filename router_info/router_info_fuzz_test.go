package router_info

import (
	"testing"

	"github.com/go-i2p/crypto/rand"
)

func FuzzReadRouterInfo(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add(make([]byte, 100))
	f.Add(make([]byte, ROUTER_INFO_MIN_SIZE))

	ri, err := generateTestRouterInfoForFuzz()
	if err == nil && ri != nil {
		b, err := ri.Bytes()
		if err == nil {
			f.Add(b)
		}
	}

	// Add a random seed
	randomData := make([]byte, ROUTER_INFO_MIN_SIZE+100)
	rand.Read(randomData)
	f.Add(randomData)

	f.Fuzz(func(t *testing.T, data []byte) {
		info, _, err := ReadRouterInfo(data)
		if err == nil {
			_ = info.RouterAddressCount()
			_ = info.PeerSize()
			_ = info.Options()
			_ = info.Signature()
			_ = info.Network()
			_ = info.String()
			_, _ = info.Bytes()
			// Exercise VerifySignature to detect panics on malformed key data
			_, _ = info.VerifySignature()
		}
	})
}
