package lease

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// FuzzReadLease fuzz tests the ReadLease parser with arbitrary byte sequences.
func FuzzReadLease(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, LEASE_SIZE))
	f.Add(make([]byte, LEASE_SIZE-1))
	f.Add(make([]byte, LEASE_SIZE+10))

	var valid [LEASE_SIZE]byte
	for i := range valid {
		valid[i] = byte(i)
	}
	f.Add(valid[:])

	f.Fuzz(func(t *testing.T, input []byte) {
		lease, remainder, err := ReadLease(input)
		if len(input) < LEASE_SIZE {
			if err == nil {
				t.Error("expected error for short input")
			}
			return
		}
		if err != nil {
			t.Errorf("unexpected error for valid-length input: %v", err)
			return
		}
		if len(remainder) != len(input)-LEASE_SIZE {
			t.Errorf("remainder length %d, want %d", len(remainder), len(input)-LEASE_SIZE)
		}
		if !assert.ObjectsAreEqual(input[:LEASE_SIZE], lease.Bytes()) {
			t.Error("parsed bytes don't match input")
		}
	})
}
