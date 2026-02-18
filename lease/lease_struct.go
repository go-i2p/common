package lease

import (
	"encoding/binary"
	"time"

	"github.com/go-i2p/common/data"
)

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

// Lease is the represenation of an I2P Lease.
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
	return
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
	return
}

// Time returns the expiration time as a Go time.Time value for convenient time operations.
// Converts the 8-byte millisecond timestamp directly via binary.BigEndian.Uint64 to avoid
// signed integer truncation issues in data.Integer.Int() for timestamps beyond year 2262.
func (lease Lease) Time() time.Time {
	dateBytes := lease[LEASE_TUNNEL_GW_SIZE+LEASE_TUNNEL_ID_SIZE:]
	millis := binary.BigEndian.Uint64(dateBytes)
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
// Returns an error if the lease has expired or has a zero gateway hash.
// This is separate from construction to allow representing arbitrary wire-format data.
func (lease Lease) Validate() error {
	gw := lease.TunnelGateway()
	if gw.IsZero() {
		return ErrZeroGatewayHash
	}
	if lease.IsExpired() {
		return ErrExpiredLease
	}
	return nil
}

// Bytes returns the complete Lease structure as a byte slice.
// This method enables serialization for network transmission or storage,
// providing API parity with Lease2.Bytes().
func (lease Lease) Bytes() []byte {
	return lease[:]
}
