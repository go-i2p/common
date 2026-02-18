package lease

import (
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// ReadLease parses a Lease structure from raw byte data according to I2P specification.
// Validates that the input data contains at least 44 bytes required for a complete lease,
// then extracts the tunnel gateway hash, tunnel ID, and expiration date into a Lease structure.
// Returns the parsed lease, any remaining unparsed bytes, and an error if parsing fails.
func ReadLease(data []byte) (lease Lease, remainder []byte, err error) {
	log.WithField("input_length", len(data)).Debug("Reading Lease from bytes")

	// Validate input data length before attempting to parse lease structure
	if len(data) < LEASE_SIZE {
		err = oops.Errorf("error parsing lease: not enough data (expected %d bytes, got %d bytes)", LEASE_SIZE, len(data))
		log.WithFields(logger.Fields{
			"data_length":     len(data),
			"required_length": LEASE_SIZE,
		}).Error("Failed to read lease: insufficient data")
		return
	}

	// Copy exactly LEASE_SIZE bytes to create the lease structure
	copy(lease[:], data[:LEASE_SIZE])
	remainder = data[LEASE_SIZE:]

	log.WithFields(logger.Fields{
		"tunnel_id":        lease.TunnelID(),
		"expiration":       lease.Date().Time(),
		"remainder_length": len(remainder),
	}).Debug("Successfully read Lease")

	return
}

// NewLeaseFromBytes creates a new Lease pointer from raw byte data using ReadLease.
// This convenience function wraps ReadLease to return a pointer to the parsed Lease structure
// instead of a value copy, which is useful for APIs that expect lease pointers.
// Returns nil on parsing errors along with the error and any remaining unparsed data.
func NewLeaseFromBytes(data []byte) (lease *Lease, remainder []byte, err error) {
	log.WithField("input_length", len(data)).Debug("Creating Lease from bytes")

	var l Lease
	// Use ReadLease to perform the actual parsing and validation
	l, remainder, err = ReadLease(data)
	if err != nil {
		log.WithError(err).Error("Failed to read Lease from bytes")
		return nil, remainder, err
	}

	lease = &l

	log.WithFields(logger.Fields{
		"tunnel_id":        lease.TunnelID(),
		"expiration":       lease.Date().Time(),
		"remainder_length": len(remainder),
	}).Debug("Successfully created Lease from bytes")

	return
}
