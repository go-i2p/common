package lease

import (
	"testing"
	"time"

	"github.com/go-i2p/common/data"
)

// FuzzNewLease fuzz-tests the NewLease constructor with random gateway bytes,
// tunnel IDs, and Unix-millisecond timestamps. Ensures no panics occur and that
// the pre-epoch guard fires correctly for negative millisecond values.
func FuzzNewLease(f *testing.F) {
	var zeroGateway [32]byte
	var fullGateway [32]byte
	for i := range fullGateway {
		fullGateway[i] = 0xFF
	}

	f.Add(zeroGateway[:], uint32(0), int64(0))
	f.Add(fullGateway[:], uint32(0xDEADBEEF), int64(1700000000000))
	f.Add(fullGateway[:], uint32(1), int64(-1))
	f.Add(fullGateway[:], uint32(1), int64(1<<62))

	f.Fuzz(func(t *testing.T, gwBytes []byte, tunnelID uint32, millis int64) {
		if len(gwBytes) < 32 {
			return
		}
		var gw data.Hash
		copy(gw[:], gwBytes[:32])

		expTime := time.UnixMilli(millis).UTC()
		lease, err := NewLease(gw, tunnelID, expTime)
		if millis < 0 {
			if err == nil {
				t.Errorf("NewLease should reject pre-epoch millis=%d", millis)
			}
			if lease != nil {
				t.Errorf("NewLease should return nil lease for pre-epoch millis=%d", millis)
			}
			return
		}
		if err != nil {
			t.Errorf("NewLease returned unexpected error for millis=%d: %v", millis, err)
			return
		}
		if lease == nil {
			t.Errorf("NewLease returned nil lease without error for millis=%d", millis)
		}
	})
}

// FuzzNewLease2 fuzz-tests the NewLease2 constructor with random gateway bytes,
// tunnel IDs, and Unix-second timestamps. Ensures no panics, pre-epoch
// returns ErrPreEpochTimestamp, and overflow returns ErrTimestampOverflow.
func FuzzNewLease2(f *testing.F) {
	var zeroGateway [32]byte
	var fullGateway [32]byte
	for i := range fullGateway {
		fullGateway[i] = 0xFF
	}

	f.Add(zeroGateway[:], uint32(0), int64(0))
	f.Add(fullGateway[:], uint32(0xDEADBEEF), int64(1700000000))
	f.Add(fullGateway[:], uint32(1), int64(-1))
	f.Add(fullGateway[:], uint32(1), int64(int64(LEASE2_MAX_END_DATE)+1))

	f.Fuzz(func(t *testing.T, gwBytes []byte, tunnelID uint32, unixSec int64) {
		if len(gwBytes) < 32 {
			return
		}
		var gw data.Hash
		copy(gw[:], gwBytes[:32])

		expTime := time.Unix(unixSec, 0).UTC()
		lease2, err := NewLease2(gw, tunnelID, expTime)

		if unixSec < 0 {
			if err == nil {
				t.Errorf("NewLease2 should reject pre-epoch unixSec=%d", unixSec)
			}
			if lease2 != nil {
				t.Errorf("NewLease2 should return nil for pre-epoch unixSec=%d", unixSec)
			}
			return
		}
		if uint64(unixSec) > LEASE2_MAX_END_DATE {
			if err == nil {
				t.Errorf("NewLease2 should reject overflow unixSec=%d", unixSec)
			}
			return
		}
		if err != nil {
			t.Errorf("NewLease2 returned unexpected error for unixSec=%d: %v", unixSec, err)
			return
		}
		if lease2 == nil {
			t.Errorf("NewLease2 returned nil lease without error for unixSec=%d", unixSec)
		}
	})
}
