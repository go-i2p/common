package lease

import (
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// ReadLease2 parses a Lease2 structure from raw byte data according to I2P specification 0.9.67.
// Validates that the input data contains at least 40 bytes required for a complete Lease2,
// then extracts the tunnel gateway hash, tunnel ID, and 4-byte expiration timestamp.
// Returns the parsed Lease2, any remaining unparsed bytes, and an error if parsing fails.
//
// Example: lease2, remainder, err := ReadLease2(networkData)
func ReadLease2(data []byte) (lease2 Lease2, remainder []byte, err error) {
	log.WithField("input_length", len(data)).Debug("Reading Lease2 from bytes")

	// Validate input data length before attempting to parse lease2 structure
	// Ensures that buffer underflows cannot occur during lease2 field extraction
	if len(data) < LEASE2_SIZE {
		err = oops.Errorf("error parsing lease2: not enough data (expected %d bytes, got %d bytes)", LEASE2_SIZE, len(data))
		log.WithFields(logger.Fields{
			"data_length":     len(data),
			"required_length": LEASE2_SIZE,
		}).Error("Failed to read Lease2: insufficient data")
		return
	}

	// Copy exactly LEASE2_SIZE bytes to create the lease2 structure
	// This preserves the original data while extracting the lease2 portion safely
	copy(lease2[:], data[:LEASE2_SIZE])
	remainder = data[LEASE2_SIZE:]

	log.WithFields(logger.Fields{
		"tunnel_id":        lease2.TunnelID(),
		"expiration":       lease2.Time(),
		"end_date_seconds": lease2.EndDate(),
		"remainder_length": len(remainder),
	}).Debug("Successfully read Lease2")

	return
}

// NewLease2FromBytes creates a new Lease2 pointer from raw byte data using ReadLease2.
// This convenience function wraps ReadLease2 to return a pointer to the parsed Lease2 structure
// instead of a value copy, which is useful for APIs that expect lease pointers.
// Returns nil on parsing errors along with the error and any remaining unparsed data.
//
// Example: lease2Ptr, remainder, err := NewLease2FromBytes(networkData)
func NewLease2FromBytes(data []byte) (lease2 *Lease2, remainder []byte, err error) {
	log.WithField("input_length", len(data)).Debug("Creating Lease2 from bytes")

	var l2 Lease2
	// Use ReadLease2 to perform the actual parsing and validation
	// This ensures consistent error handling and logging across both functions
	l2, remainder, err = ReadLease2(data)
	if err != nil {
		log.WithError(err).Error("Failed to read Lease2 from bytes")
		return nil, remainder, err
	}

	// Convert value type to pointer type for convenient API usage
	// Many I2P APIs expect lease pointers for efficient memory management
	lease2 = &l2

	log.WithFields(logger.Fields{
		"tunnel_id":        lease2.TunnelID(),
		"expiration":       lease2.Time(),
		"end_date_seconds": lease2.EndDate(),
		"remainder_length": len(remainder),
	}).Debug("Successfully created Lease2 from bytes")

	return
}
