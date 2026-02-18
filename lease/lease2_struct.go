package lease

import (
	"encoding/binary"
	"time"

	"github.com/go-i2p/common/data"
)

/*
[Lease2]
Accurate for version 0.9.67

Description
Defines the authorization for a particular tunnel to receive messages targeting a Destination.
Lease2 is a more compact version introduced in I2P specification 0.9.38 for use in LeaseSet2 structures.

Contents
SHA256 Hash of the RouterIdentity of the gateway router, then the TunnelId and finally a 4-byte end date.

+----+----+----+----+----+----+----+----+
| tunnel_gw                             |
+                                       +
|                                       |
+                                       +
|                                       |
+                                       +
|                                       |
+----+----+----+----+----+----+----+----+
|     tunnel_id     |    end_date       |
+----+----+----+----+----+----+----+----+

tunnel_gw :: Hash of the RouterIdentity of the tunnel gateway
             length -> 32 bytes

tunnel_id :: TunnelId
             length -> 4 bytes

end_date :: 4-byte expiration timestamp in seconds since Unix epoch
            length -> 4 bytes

Notes:
- Lease2 uses 4-byte timestamps (seconds since epoch) instead of 8-byte timestamps (milliseconds)
- Total size is 40 bytes compared to 44 bytes for legacy Lease
- Introduced in I2P specification 0.9.38 for LeaseSet2 structures
- Provides the same functionality as Lease but with more efficient encoding
*/

// Lease2 is the representation of an I2P Lease2 structure.
// Lease2 is a compact version of Lease introduced in specification 0.9.38 for LeaseSet2.
// It uses 4-byte second timestamps instead of 8-byte millisecond timestamps for efficiency.
//
// https://geti2p.net/spec/common-structures#lease2
type Lease2 [LEASE2_SIZE]byte

// NewLease2 is defined in lease.go for better package visibility.

// TunnelGateway returns the tunnel gateway hash from the lease2 structure.
// Extracts the first 32 bytes of the lease2 which contain the SHA256 hash of the RouterIdentity
// of the gateway router responsible for handling messages sent through this tunnel.
// The returned hash can be used to identify and route messages to the appropriate tunnel gateway.
func (lease2 Lease2) TunnelGateway() (hash data.Hash) {
	copy(hash[:], lease2[:LEASE_TUNNEL_GW_SIZE])
	return
}

// TunnelID returns the tunnel identifier as a 32-bit unsigned integer.
// Extracts bytes 32-35 of the lease2 structure and converts them from big-endian format
// to a native uint32 value. This ID uniquely identifies the specific tunnel within
// the context of the gateway router and is used for message routing and delivery.
func (lease2 Lease2) TunnelID() uint32 {
	tunnelIDBytes := lease2[LEASE_TUNNEL_GW_SIZE : LEASE_TUNNEL_GW_SIZE+LEASE_TUNNEL_ID_SIZE]
	return binary.BigEndian.Uint32(tunnelIDBytes)
}

// EndDate returns the expiration timestamp of the lease2 as a 32-bit unsigned integer.
// The timestamp represents seconds since Unix epoch (January 1, 1970 00:00:00 UTC).
// This is more compact than the legacy Lease which uses 8-byte millisecond timestamps,
// providing sufficient range until year 2106 while reducing structure size.
func (lease2 Lease2) EndDate() uint32 {
	endDateBytes := lease2[LEASE_TUNNEL_GW_SIZE+LEASE_TUNNEL_ID_SIZE:]
	return binary.BigEndian.Uint32(endDateBytes)
}

// Time returns the expiration time as a Go time.Time value for convenient time operations.
// Converts the 4-byte second timestamp to a time.Time in the UTC timezone.
// This method enables easy time comparisons, formatting, and duration calculations.
func (lease2 Lease2) Time() time.Time {
	seconds := lease2.EndDate()
	return time.Unix(int64(seconds), 0).UTC()
}

// Date returns the expiration as an I2P Date for API symmetry with Lease.Date().
// The 4-byte seconds timestamp is converted to an 8-byte millisecond Date.
func (lease2 Lease2) Date() (date data.Date) {
	millis := uint64(lease2.EndDate()) * 1000
	binary.BigEndian.PutUint64(date[:], millis)
	return
}

// IsExpired returns true if the lease2's expiration time is before the current time.
func (lease2 Lease2) IsExpired() bool {
	return lease2.Time().Before(time.Now())
}

// Equal returns true if two Lease2 structures are byte-for-byte identical.
func (lease2 Lease2) Equal(other Lease2) bool {
	return lease2 == other
}

// Validate performs semantic validation on the lease2.
// Returns an error if the lease2 has expired or has a zero gateway hash.
// This is separate from construction to allow representing arbitrary wire-format data.
func (lease2 Lease2) Validate() error {
	gw := lease2.TunnelGateway()
	if gw.IsZero() {
		return ErrZeroGatewayHash
	}
	if lease2.IsExpired() {
		return ErrExpiredLease
	}
	return nil
}

// Bytes returns the complete Lease2 structure as a byte slice.
// This method enables serialization for network transmission or storage.
func (lease2 Lease2) Bytes() []byte {
	return lease2[:]
}
