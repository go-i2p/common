package lease

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// FuzzReadLease2 fuzz tests the ReadLease2 parser.
func FuzzReadLease2(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, LEASE2_SIZE))
	f.Add(make([]byte, LEASE2_SIZE-1))
	f.Add(make([]byte, LEASE2_SIZE+10))

	var valid [LEASE2_SIZE]byte
	for i := range valid {
		valid[i] = byte(i)
	}
	f.Add(valid[:])

	f.Fuzz(func(t *testing.T, input []byte) {
		lease2, remainder, err := ReadLease2(input)
		if len(input) < LEASE2_SIZE {
			if err == nil {
				t.Error("expected error for short input")
			}
			return
		}
		if err != nil {
			t.Errorf("unexpected error for valid-length input: %v", err)
			return
		}
		if len(remainder) != len(input)-LEASE2_SIZE {
			t.Errorf("remainder length %d, want %d", len(remainder), len(input)-LEASE2_SIZE)
		}
		if !assert.ObjectsAreEqual(input[:LEASE2_SIZE], lease2.Bytes()) {
			t.Error("parsed bytes don't match input")
		}
	})
}
