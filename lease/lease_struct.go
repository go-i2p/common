package lease

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/go-i2p/common/data"
)

// Compile-time interface assertions.
var _ fmt.Stringer = Lease{}

/*
[Lease]
Accurate for version 0.9.67

Description
Defines the authorization for a particular tunnel to receive messages targeting a Destination.

Contents
SHA256 Hash of the RouterIdentity of the gateway router, then the TunnelId and finally an end Date.

+----+----+----+----+----+----+----+----+
| tunnel_gw                             |
+                                       +
|                                       |
+                                       +
|                                       |
+                                       +
|                                       |
+----+----+----+----+----+----+----+----+
|     tunnel_id     |      end_date
+----+----+----+----+----+----+----+----+
                    |
+----+----+----+----+

tunnel_gw :: Hash of the RouterIdentity of the tunnel gateway
             length -> 32 bytes

tunnel_id :: TunnelId
             length -> 4 bytes

end_date :: Date
            length -> 8 bytes
*/

// Lease is the representation of an I2P Lease.
//
// https://geti2p.net/spec/common-structures#lease
type Lease [LEASE_SIZE]byte

// NewLease is defined in lease.go for better package visibility.

// TunnelGateway returns the tunnel gateway hash from the lease structure.
// Extracts the first 32 bytes of the lease which contain the SHA256 hash of the RouterIdentity
// of the gateway router responsible for handling messages sent through this tunnel.
// The returned hash can be used to identify and route messages to the appropriate tunnel gateway.
func (lease Lease) TunnelGateway() (hash data.Hash) {
	copy(hash[:], lease[:LEASE_TUNNEL_GW_SIZE])
	return hash
}

// TunnelID returns the tunnel identifier as a 32-bit unsigned integer.
// Extracts bytes 32-35 of the lease structure and converts them from big-endian format
// to a native uint32 value. This ID uniquely identifies the specific tunnel within
// the context of the gateway router and is used for message routing and delivery.
func (lease Lease) TunnelID() uint32 {
	tunnelIDBytes := lease[LEASE_TUNNEL_GW_SIZE : LEASE_TUNNEL_GW_SIZE+LEASE_TUNNEL_ID_SIZE]
	return binary.BigEndian.Uint32(tunnelIDBytes)
}

// Date returns the expiration date of the lease as an I2P Date structure.
// Extracts the last 8 bytes of the lease structure which contain the expiration timestamp
// in milliseconds since Unix epoch. This date determines when the lease becomes invalid
// and can no longer be used for tunnel message delivery within the I2P network.
func (lease Lease) Date() (date data.Date) {
	copy(date[:], lease[LEASE_TUNNEL_GW_SIZE+LEASE_TUNNEL_ID_SIZE:])
	return date
}

// Time returns the expiration time as a Go time.Time value for convenient time operations.
// Uses unsigned decoding with a math.MaxInt64 cap: values above math.MaxInt64 are
// clamped to time.UnixMilli(math.MaxInt64) rather than wrapping to a pre-epoch time
// via signed cast.
//
// Note: For millis > math.MaxInt64 (high bit set), Time() returns the clamped maximum
// while Date().Time() returns the zero time.Time{}. Both handle the edge case safely,
// but callers choosing between the two methods should be aware of this divergence.
func (lease Lease) Time() time.Time {
	millis := binary.BigEndian.Uint64(lease[LEASE_TUNNEL_GW_SIZE+LEASE_TUNNEL_ID_SIZE:])
	if millis > uint64(math.MaxInt64) {
		return time.UnixMilli(math.MaxInt64).UTC()
	}
	return time.UnixMilli(int64(millis)).UTC()
}

// IsExpired returns true if the lease's expiration time is before the current time.
func (lease Lease) IsExpired() bool {
	return lease.Time().Before(time.Now())
}

// Equal returns true if two Lease structures are byte-for-byte identical.
func (lease Lease) Equal(other Lease) bool {
	return lease == other
}

// Validate performs semantic validation on the lease.
// Returns a combined error (via errors.Join) if multiple issues are found:
// zero gateway hash, zero tunnel ID (advisory per spec), null end_date (per spec
// "Date == 0 is undefined or null"), or expired lease.
// Use errors.Is to check for specific error conditions.
// This is separate from construction to allow representing arbitrary wire-format data.
func (lease Lease) Validate() error {
	var errs []error
	gw := lease.TunnelGateway()
	if gw.IsZero() {
		errs = append(errs, ErrZeroGatewayHash)
	}
	if lease.TunnelID() == 0 {
		errs = append(errs, ErrZeroTunnelID)
	}
	millis := binary.BigEndian.Uint64(lease[LEASE_TUNNEL_GW_SIZE+LEASE_TUNNEL_ID_SIZE:])
	if millis == 0 {
		errs = append(errs, ErrNullDate)
	} else if lease.IsExpired() {
		errs = append(errs, ErrExpiredLease)
	}
	return errors.Join(errs...)
}

// String returns a human-readable representation of the Lease for debugging and logging.
func (lease Lease) String() string {
	gw := lease.TunnelGateway()
	return fmt.Sprintf("Lease{gw=%x..., tid=%d, exp=%s}",
		gw[:4], lease.TunnelID(), lease.Time().Format(time.RFC3339))
}

// Bytes returns the complete Lease structure as a byte slice.
// This method enables serialization for network transmission or storage,
// providing API parity with Lease2.Bytes().
func (lease Lease) Bytes() []byte {
	return lease[:]
}
