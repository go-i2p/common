package lease

import (
	"encoding/binary"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

var log = logger.GetGoI2PLogger()

// NewLease creates a new Lease with the provided tunnel gateway, tunnel ID, and expiration time.
//
// This function constructs a properly formatted I2P Lease structure according to the specification,
// encoding the tunnel gateway hash, tunnel ID as big-endian uint32, and expiration time as milliseconds
// since epoch. No semantic validation is performed on the inputs; use Validate() to check for
// expired leases, zero gateway hashes, or other semantic issues.
//
// Parameters:
//   - tunnelGateway: SHA256 hash of the RouterIdentity of the gateway router (32 bytes)
//   - tunnelID: Unsigned 32-bit tunnel identifier unique within the gateway router
//   - expirationTime: Time when the lease expires
//
// Returns:
//   - *Lease: Pointer to the created 44-byte lease structure
//   - error: Currently always nil (reserved for future structural validation)
//
// Example:
//
//	gatewayHash, _ := data.NewHashFromSlice(gatewayBytes)
//	expiration := time.Now().Add(10 * time.Minute)
//	lease, err := NewLease(gatewayHash, 12345, expiration)
//	if err != nil {
//	    log.Fatal(err)
//	}
func NewLease(tunnelGateway data.Hash, tunnelID uint32, expirationTime time.Time) (*Lease, error) {
	log.Debug("Creating new Lease")

	// Warn if tunnel ID is 0 per spec recommendation
	if tunnelID == 0 {
		log.Warn("Tunnel ID is 0; the I2P spec recommends values greater than zero except in special cases")
	}

	var lease Lease

	// Copy the 32-byte tunnel gateway hash
	copy(lease[:LEASE_TUNNEL_GW_SIZE], tunnelGateway[:])

	// Convert tunnel ID to big-endian format
	binary.BigEndian.PutUint32(lease[LEASE_TUNNEL_GW_SIZE:LEASE_TUNNEL_GW_SIZE+LEASE_TUNNEL_ID_SIZE], tunnelID)

	// Convert expiration time to I2P Date format (milliseconds since Unix epoch)
	millis := expirationTime.UnixMilli()
	binary.BigEndian.PutUint64(lease[LEASE_TUNNEL_GW_SIZE+LEASE_TUNNEL_ID_SIZE:], uint64(millis))

	log.WithFields(logger.Fields{
		"tunnel_id":  tunnelID,
		"expiration": expirationTime,
	}).Debug("Successfully created new Lease")

	return &lease, nil
}

// NewLease2 creates a new Lease2 with the provided tunnel gateway, tunnel ID, and expiration time.
//
// This function constructs a properly formatted I2P Lease2 structure according to specification 0.9.38,
// encoding the tunnel gateway hash, tunnel ID as big-endian uint32, and expiration time as seconds
// since epoch. Lease2 is a more compact version of Lease (40 bytes vs 44 bytes) used in LeaseSet2.
// No semantic validation is performed on gateway hash or time direction; use Validate() for that.
//
// Parameters:
//   - tunnelGateway: SHA256 hash of the RouterIdentity of the gateway router (32 bytes)
//   - tunnelID: Unsigned 32-bit tunnel identifier unique within the gateway router
//   - expirationTime: Time when the lease expires
//
// Returns:
//   - *Lease2: Pointer to the created 40-byte lease2 structure
//   - error: ErrTimestampOverflow if the time exceeds the uint32 second range (after 2106-02-07)
//
// Note: Lease2 uses 4-byte timestamps representing seconds since Unix epoch, providing sufficient
// range until year 2106 while saving 4 bytes compared to the legacy Lease structure.
//
// Example:
//
//	gatewayHash, _ := data.NewHashFromSlice(gatewayBytes)
//	expiration := time.Now().Add(10 * time.Minute)
//	lease2, err := NewLease2(gatewayHash, 12345, expiration)
//	if err != nil {
//	    log.Fatal(err)
//	}
func NewLease2(tunnelGateway data.Hash, tunnelID uint32, expirationTime time.Time) (*Lease2, error) {
	log.Debug("Creating new Lease2")

	// Warn if tunnel ID is 0 per spec recommendation
	if tunnelID == 0 {
		log.Warn("Tunnel ID is 0; the I2P spec recommends values greater than zero except in special cases")
	}

	// Check for uint32 overflow: Lease2 uses 4-byte second timestamps
	unixSec := expirationTime.Unix()
	if unixSec < 0 || uint64(unixSec) > LEASE2_MAX_END_DATE {
		return nil, oops.Wrapf(ErrTimestampOverflow,
			"expiration time %v (unix=%d) exceeds Lease2 uint32 range (max %d)",
			expirationTime, unixSec, LEASE2_MAX_END_DATE)
	}

	var lease2 Lease2

	// Copy the 32-byte tunnel gateway hash
	copy(lease2[:LEASE_TUNNEL_GW_SIZE], tunnelGateway[:])

	// Convert tunnel ID to big-endian format
	binary.BigEndian.PutUint32(lease2[LEASE_TUNNEL_GW_SIZE:LEASE_TUNNEL_GW_SIZE+LEASE_TUNNEL_ID_SIZE], tunnelID)

	// Convert expiration time to 4-byte timestamp (seconds since Unix epoch)
	binary.BigEndian.PutUint32(lease2[LEASE_TUNNEL_GW_SIZE+LEASE_TUNNEL_ID_SIZE:], uint32(unixSec))

	log.WithFields(logger.Fields{
		"tunnel_id":  tunnelID,
		"expiration": expirationTime,
		"seconds":    uint32(unixSec),
	}).Debug("Successfully created new Lease2")

	return &lease2, nil
}
