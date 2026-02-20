package lease_set

import (
	"testing"
)

func FuzzReadLeaseSet(f *testing.F) {
	// Seed corpus with various sizes
	f.Add([]byte{})
	f.Add(make([]byte, 100))
	f.Add(make([]byte, 387))
	f.Add(make([]byte, 500))
	f.Add(make([]byte, 1000))

	// Add a seed with a valid-looking destination prefix (NULL cert)
	// 256 bytes pubkey + 128 bytes sigkey + 3 bytes NULL cert (type=0, len=0,0)
	validPrefix := make([]byte, 387+256+128+1+40) // dest + encKey + sigKey + count + sig
	validPrefix[384] = 0x00                       // CERT_NULL type
	validPrefix[385] = 0x00                       // cert length high byte
	validPrefix[386] = 0x00                       // cert length low byte
	f.Add(validPrefix)

	// Add a seed with KEY cert prefix (type=5)
	keyCertPrefix := make([]byte, 600)
	keyCertPrefix[384] = 0x05 // CERT_KEY type
	keyCertPrefix[385] = 0x00 // cert length high byte
	keyCertPrefix[386] = 0x04 // cert length = 4 bytes
	keyCertPrefix[387] = 0x00 // signing type high byte
	keyCertPrefix[388] = 0x07 // signing type = Ed25519 (7)
	keyCertPrefix[389] = 0x00 // crypto type high byte
	keyCertPrefix[390] = 0x00 // crypto type = ElGamal (0)
	f.Add(keyCertPrefix)

	// Add a seed that constructs a valid LeaseSet via the test helper
	// (provides the fuzzer a starting point for mutation)
	f.Add(buildValidLeaseSetSeed(f))

	f.Fuzz(func(t *testing.T, input []byte) {
		// ReadLeaseSet should never panic
		ls, err := ReadLeaseSet(input)
		if err == nil {
			// If parsing succeeded, basic accessors should not panic
			_ = ls.Destination()
			_ = ls.LeaseCount()
			_ = ls.Leases()
			_ = ls.Signature()
			_, _ = ls.Bytes()
			_, _ = ls.PublicKey()
			_, _ = ls.SigningKey()
			_ = ls.Validate()
			_ = ls.IsValid()
		}
	})
}

// buildValidLeaseSetSeed creates a valid serialized LeaseSet for use as a fuzz seed.
func buildValidLeaseSetSeed(f *testing.F) []byte {
	f.Helper()

	routerInfo, _, _, _, _, err := generateTestRouterInfo(&testing.T{})
	if err != nil {
		// If we can't generate test data, return a minimal seed
		return make([]byte, 500)
	}

	leaseSet, err := createTestLeaseSet(&testing.T{}, routerInfo, 1)
	if err != nil {
		return make([]byte, 500)
	}

	lsBytes, err := leaseSet.Bytes()
	if err != nil {
		return make([]byte, 500)
	}

	return lsBytes
}
