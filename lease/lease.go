// Package lease implements the I2P Lease common data structure according to specification version 0.9.67.
//
// ADDED: A Lease defines the authorization for a particular tunnel to receive messages targeting a Destination.
// Each lease contains the SHA256 hash of the RouterIdentity of the gateway router, the tunnel identifier,
// and an expiration date that determines when the lease becomes invalid for message delivery.
//
// ADDED: The lease structure is fundamental to I2P's tunnel-based message routing system, enabling secure
// and anonymous communication by providing time-limited authorization for tunnel message delivery.
// Leases are included in LeaseSet structures that are distributed throughout the I2P network database.
//
// ADDED: Key features:
//   - 44-byte fixed-length structure for efficient network transmission
//   - SHA256 tunnel gateway identification for secure routing
//   - 32-bit tunnel ID for precise tunnel selection within gateway routers
//   - Millisecond-precision expiration timestamps for fine-grained lease management
//   - Complete I2P specification compliance for network interoperability
//
// ADDED: Common usage patterns:
//
//	lease, err := NewLease(gatewayHash, tunnelID, expirationTime)
//	leaseData, remainder, err := ReadLease(networkBytes)
//	gatewayHash := lease.TunnelGateway()
//	tunnelID := lease.TunnelID()
//	expirationDate := lease.Date()
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
// since epoch. It validates that the expiration time is in the future to prevent creating expired leases.
//
// Parameters:
//   - tunnelGateway: SHA256 hash of the RouterIdentity of the gateway router (32 bytes)
//   - tunnelID: Unsigned 32-bit tunnel identifier unique within the gateway router
//   - expirationTime: Time when the lease becomes invalid (must be in the future)
//
// Returns:
//   - *Lease: Pointer to the created 44-byte lease structure
//   - error: ErrExpiredLease if expiration time is not in the future, or validation errors
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

	// Validate that the lease expiration is in the future
	if !expirationTime.After(time.Now()) {
		return nil, oops.Wrapf(ErrExpiredLease, "expiration time %v is not in the future", expirationTime)
	}

	// Validate gateway hash is not zero
	if tunnelGateway.IsZero() {
		return nil, oops.Errorf("tunnel gateway hash cannot be zero")
	}

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

// NewLease2 creates a new Lease2 with the provided tunnel gateway, tunnel ID, and expiration time.
//
// This function constructs a properly formatted I2P Lease2 structure according to specification 0.9.38,
// encoding the tunnel gateway hash, tunnel ID as big-endian uint32, and expiration time as seconds
// since epoch. Lease2 is a more compact version of Lease (40 bytes vs 44 bytes) used in LeaseSet2.
// It validates that the expiration time is in the future to prevent creating expired leases.
//
// Parameters:
//   - tunnelGateway: SHA256 hash of the RouterIdentity of the gateway router (32 bytes)
//   - tunnelID: Unsigned 32-bit tunnel identifier unique within the gateway router
//   - expirationTime: Time when the lease becomes invalid (must be in the future)
//
// Returns:
//   - *Lease2: Pointer to the created 40-byte lease2 structure
//   - error: ErrExpiredLease if expiration time is not in the future, or validation errors
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

	// Validate that the lease expiration is in the future
	if !expirationTime.After(time.Now()) {
		return nil, oops.Wrapf(ErrExpiredLease, "expiration time %v is not in the future", expirationTime)
	}

	// Validate gateway hash is not zero
	if tunnelGateway.IsZero() {
		return nil, oops.Errorf("tunnel gateway hash cannot be zero")
	}

	var lease2 Lease2

	// Copy the 32-byte tunnel gateway hash to the beginning of the lease structure
	// This hash identifies the router that will serve as the gateway for this tunnel
	copy(lease2[:LEASE_TUNNEL_GW_SIZE], tunnelGateway[:])

	// Convert tunnel ID to big-endian format for network byte order consistency
	// The tunnel ID must be stored as 4 bytes in network byte order for I2P compatibility
	tunnelIDBytes := make([]byte, LEASE_TUNNEL_ID_SIZE)
	binary.BigEndian.PutUint32(tunnelIDBytes, tunnelID)
	copy(lease2[LEASE_TUNNEL_GW_SIZE:LEASE_TUNNEL_GW_SIZE+LEASE_TUNNEL_ID_SIZE], tunnelIDBytes)

	// Convert expiration time to 4-byte timestamp (seconds since Unix epoch)
	// This is the key difference from legacy Lease which uses 8-byte millisecond timestamps
	seconds := uint32(expirationTime.Unix())
	endDateBytes := make([]byte, LEASE2_END_DATE_SIZE)
	binary.BigEndian.PutUint32(endDateBytes, seconds)
	copy(lease2[LEASE_TUNNEL_GW_SIZE+LEASE_TUNNEL_ID_SIZE:], endDateBytes)

	log.WithFields(logger.Fields{
		"tunnel_id":  tunnelID,
		"expiration": expirationTime,
		"seconds":    seconds,
	}).Debug("Successfully created new Lease2")

	return &lease2, nil
}
