// Package lease implements the I2P lease common data structure
package lease

import (
	"encoding/binary"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/logger"
	"github.com/sirupsen/logrus"
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

// ADDED: NewLease creates a new Lease with the provided tunnel gateway, tunnel ID, and expiration time.
// It constructs a properly formatted I2P Lease structure according to the specification, encoding
// the tunnel gateway hash, tunnel ID as big-endian uint32, and expiration time as milliseconds since epoch.
// Returns a pointer to the created Lease and any error encountered during construction.
// Example: lease, err := NewLease(gatewayHash, 12345, time.Now().Add(10*time.Minute))
func NewLease(tunnelGateway data.Hash, tunnelID uint32, expirationTime time.Time) (*Lease, error) {
	log.Debug("Creating new Lease")

	var lease Lease

	// Gateway hash
	copy(lease[:LEASE_TUNNEL_GW_SIZE], tunnelGateway[:])

	// Convert and copy tunnel ID
	tunnelIDBytes := make([]byte, LEASE_TUNNEL_ID_SIZE)
	binary.BigEndian.PutUint32(tunnelIDBytes, tunnelID)
	copy(lease[LEASE_TUNNEL_GW_SIZE:LEASE_TUNNEL_GW_SIZE+LEASE_TUNNEL_ID_SIZE], tunnelIDBytes)

	// Convert and copy expiration date
	millis := expirationTime.UnixNano() / int64(time.Millisecond)
	dateBytes := make([]byte, data.DATE_SIZE)
	binary.BigEndian.PutUint64(dateBytes, uint64(millis))
	copy(lease[LEASE_TUNNEL_GW_SIZE+LEASE_TUNNEL_ID_SIZE:], dateBytes)

	log.WithFields(logrus.Fields{
		"tunnel_id":  tunnelID,
		"expiration": expirationTime,
	}).Debug("Successfully created new Lease")

	return &lease, nil
}

// TunnelGateway returns the tunnel gateway as a Hash.
func (lease Lease) TunnelGateway() (hash data.Hash) {
	copy(hash[:], lease[:LEASE_TUNNEL_GW_SIZE])
	return
}

// TunnelID returns the tunnel id as a uint23.
func (lease Lease) TunnelID() uint32 {
	i := data.Integer(lease[LEASE_TUNNEL_GW_SIZE : LEASE_TUNNEL_GW_SIZE+LEASE_TUNNEL_ID_SIZE])
	return uint32(
		i.Int(),
	)
}

// Date returns the date as an I2P Date.
func (lease Lease) Date() (date data.Date) {
	copy(date[:], lease[LEASE_TUNNEL_GW_SIZE+LEASE_TUNNEL_ID_SIZE:])
	return
}
