// Package lease implements the I2P lease common data structure
package lease

import (
	"encoding/binary"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/logger"
)

var log = logger.GetGoI2PLogger()

/*
[Lease]
Accurate for version 0.9.49

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

// NewLease creates a new Lease with the provided tunnel gateway, tunnel ID, and expiration time.
// It constructs a properly formatted I2P Lease structure according to the specification, encoding
// the tunnel gateway hash, tunnel ID as big-endian uint32, and expiration time as milliseconds since epoch.
// Returns a pointer to the created Lease and any error encountered during construction.
// Example: lease, err := NewLease(gatewayHash, 12345, time.Now().Add(10*time.Minute))
func NewLease(tunnelGateway data.Hash, tunnelID uint32, expirationTime time.Time) (*Lease, error) {
	log.Debug("Creating new Lease")

	var lease Lease

	// Copy the 32-byte tunnel gateway hash to the beginning of the lease structure
	// This hash identifies the router that will serve as the gateway for this tunnel
	copy(lease[:LEASE_TUNNEL_GW_SIZE], tunnelGateway[:])

	// Convert tunnel ID to big-endian format for network byte order consistency
	// The tunnel ID must be stored as 4 bytes in network byte order for I2P compatibility
	tunnelIDBytes := make([]byte, LEASE_TUNNEL_ID_SIZE)
	binary.BigEndian.PutUint32(tunnelIDBytes, tunnelID)
	copy(lease[LEASE_TUNNEL_GW_SIZE:LEASE_TUNNEL_GW_SIZE+LEASE_TUNNEL_ID_SIZE], tunnelIDBytes)

	// Convert expiration time to I2P Date format (milliseconds since Unix epoch)
	// The date must be stored as 8 bytes in big-endian format for proper network serialization
	millis := expirationTime.UnixNano() / int64(time.Millisecond)
	dateBytes := make([]byte, data.DATE_SIZE)
	binary.BigEndian.PutUint64(dateBytes, uint64(millis))
	copy(lease[LEASE_TUNNEL_GW_SIZE+LEASE_TUNNEL_ID_SIZE:], dateBytes)

	log.WithFields(logger.Fields{
		"tunnel_id":  tunnelID,
		"expiration": expirationTime,
	}).Debug("Successfully created new Lease")

	return &lease, nil
}

// TunnelGateway returns the tunnel gateway hash from the lease structure.
// Extracts the first 32 bytes of the lease which contain the SHA256 hash of the RouterIdentity
// of the gateway router responsible for handling messages sent through this tunnel.
// The returned hash can be used to identify and route messages to the appropriate tunnel gateway.
func (lease Lease) TunnelGateway() (hash data.Hash) {
	copy(hash[:], lease[:LEASE_TUNNEL_GW_SIZE])
	return
}

// ADDED: TunnelID returns the tunnel identifier as a 32-bit unsigned integer.
// Extracts bytes 32-35 of the lease structure and converts them from big-endian format
// to a native uint32 value. This ID uniquely identifies the specific tunnel within
// the context of the gateway router and is used for message routing and delivery.
func (lease Lease) TunnelID() uint32 {
	i := data.Integer(lease[LEASE_TUNNEL_GW_SIZE : LEASE_TUNNEL_GW_SIZE+LEASE_TUNNEL_ID_SIZE])
	return uint32(
		i.Int(),
	)
}

// ADDED: Date returns the expiration date of the lease as an I2P Date structure.
// Extracts the last 8 bytes of the lease structure which contain the expiration timestamp
// in milliseconds since Unix epoch. This date determines when the lease becomes invalid
// and can no longer be used for tunnel message delivery within the I2P network.
func (lease Lease) Date() (date data.Date) {
	copy(date[:], lease[LEASE_TUNNEL_GW_SIZE+LEASE_TUNNEL_ID_SIZE:])
	return
}
