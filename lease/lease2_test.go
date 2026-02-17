package lease

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-i2p/common/data"
)

// TestNewLease2 verifies that NewLease2 correctly constructs a Lease2 structure
// with the provided tunnel gateway hash, tunnel ID, and expiration time.
func TestNewLease2(t *testing.T) {
	// Create test data
	var gatewayHash data.Hash
	copy(gatewayHash[:], []byte("test_gateway_hash_32_bytes_long!"))
	tunnelID := uint32(12345)
	expirationTime := time.Now().Add(10 * time.Minute)

	// Create Lease2
	lease2, err := NewLease2(gatewayHash, tunnelID, expirationTime)
	require.NoError(t, err)
	require.NotNil(t, lease2)

	// Verify gateway hash
	assert.Equal(t, gatewayHash, lease2.TunnelGateway())

	// Verify tunnel ID
	assert.Equal(t, tunnelID, lease2.TunnelID())

	// Verify expiration time (should be truncated to seconds)
	expectedSeconds := uint32(expirationTime.Unix())
	assert.Equal(t, expectedSeconds, lease2.EndDate())

	// Verify time conversion
	retrievedTime := lease2.Time()
	assert.Equal(t, expirationTime.Unix(), retrievedTime.Unix())
}

// TestLease2TunnelGateway verifies that TunnelGateway correctly extracts
// the 32-byte gateway hash from the Lease2 structure.
func TestLease2TunnelGateway(t *testing.T) {
	assert := assert.New(t)

	expectedGatewayBytes := []byte("example_32_bytes_hash_to_test_00")

	// Construct Lease2 bytes manually
	var lease2Bytes []byte
	lease2Bytes = append(lease2Bytes, expectedGatewayBytes...)
	lease2Bytes = append(lease2Bytes, make([]byte, LEASE2_SIZE-LEASE_TUNNEL_GW_SIZE)...)
	lease2 := Lease2(lease2Bytes)

	// Verify gateway extraction
	tunnelGateway := lease2.TunnelGateway()
	assert.ElementsMatch(expectedGatewayBytes, tunnelGateway.Bytes())
}

// TestLease2TunnelID verifies that TunnelID correctly extracts and converts
// the 4-byte big-endian tunnel ID from the Lease2 structure.
func TestLease2TunnelID(t *testing.T) {
	assert := assert.New(t)

	expectedTunnelID := uint32(0x21373133) // Big-endian representation
	expectedTunnelIDBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(expectedTunnelIDBytes, expectedTunnelID)

	// Construct Lease2 bytes manually
	var lease2Bytes []byte
	lease2Bytes = append(lease2Bytes, make([]byte, LEASE_TUNNEL_GW_SIZE)...)
	lease2Bytes = append(lease2Bytes, expectedTunnelIDBytes...)
	lease2Bytes = append(lease2Bytes, make([]byte, LEASE2_SIZE-LEASE_TUNNEL_GW_SIZE-LEASE_TUNNEL_ID_SIZE)...)
	lease2 := Lease2(lease2Bytes)

	// Verify tunnel ID extraction
	tunnelID := lease2.TunnelID()
	assert.Equal(expectedTunnelID, tunnelID)
}

// TestLease2EndDate verifies that EndDate correctly extracts and converts
// the 4-byte big-endian expiration timestamp from the Lease2 structure.
func TestLease2EndDate(t *testing.T) {
	assert := assert.New(t)

	expectedEndDate := uint32(1735689599) // Dec 31, 2024 23:59:59 UTC
	expectedEndDateBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(expectedEndDateBytes, expectedEndDate)

	// Construct Lease2 bytes manually
	var lease2Bytes []byte
	lease2Bytes = append(lease2Bytes, make([]byte, LEASE_TUNNEL_GW_SIZE+LEASE_TUNNEL_ID_SIZE)...)
	lease2Bytes = append(lease2Bytes, expectedEndDateBytes...)
	lease2 := Lease2(lease2Bytes)

	// Verify end date extraction
	endDate := lease2.EndDate()
	assert.Equal(expectedEndDate, endDate)
}

// TestLease2Time verifies that Time correctly converts the 4-byte timestamp
// to a Go time.Time value in UTC timezone.
func TestLease2Time(t *testing.T) {
	assert := assert.New(t)

	expectedTime := time.Date(2025, 12, 31, 23, 59, 59, 0, time.UTC)
	expectedEndDate := uint32(expectedTime.Unix())
	expectedEndDateBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(expectedEndDateBytes, expectedEndDate)

	// Construct Lease2 bytes manually
	var lease2Bytes []byte
	lease2Bytes = append(lease2Bytes, make([]byte, LEASE_TUNNEL_GW_SIZE+LEASE_TUNNEL_ID_SIZE)...)
	lease2Bytes = append(lease2Bytes, expectedEndDateBytes...)
	lease2 := Lease2(lease2Bytes)

	// Verify time conversion
	retrievedTime := lease2.Time()
	assert.Equal(expectedTime.Unix(), retrievedTime.Unix())
	assert.Equal("UTC", retrievedTime.Location().String())
}

// TestReadLease2ValidData verifies that ReadLease2 correctly parses
// a valid 40-byte Lease2 structure from byte data.
func TestReadLease2ValidData(t *testing.T) {
	assert := assert.New(t)

	// Create valid Lease2 data
	var gatewayHash data.Hash
	copy(gatewayHash[:], []byte("valid_gateway_hash_for_testing!!"))
	tunnelID := uint32(54321)
	expirationTime := time.Date(2026, 6, 15, 12, 30, 45, 0, time.UTC)

	originalLease2, err := NewLease2(gatewayHash, tunnelID, expirationTime)
	assert.NoError(err)

	// Add extra bytes to test remainder
	testData := append(originalLease2.Bytes(), []byte("extra_data")...)

	// Parse Lease2
	parsedLease2, remainder, err := ReadLease2(testData)
	assert.NoError(err)
	assert.Equal([]byte("extra_data"), remainder)

	// Verify parsed data matches original
	assert.Equal(originalLease2.TunnelGateway(), parsedLease2.TunnelGateway())
	assert.Equal(originalLease2.TunnelID(), parsedLease2.TunnelID())
	assert.Equal(originalLease2.EndDate(), parsedLease2.EndDate())
	assert.Equal(originalLease2.Bytes(), parsedLease2.Bytes())
}

// TestReadLease2InsufficientData verifies that ReadLease2 returns an error
// when the input data is shorter than 40 bytes.
func TestReadLease2InsufficientData(t *testing.T) {
	assert := assert.New(t)

	// Test with various insufficient data lengths
	testCases := []int{0, 1, 10, 20, 30, 39}

	for _, dataLen := range testCases {
		insufficientData := make([]byte, dataLen)
		_, _, err := ReadLease2(insufficientData)
		assert.Error(err, "Expected error for data length %d", dataLen)
		assert.Contains(err.Error(), "not enough data")
	}
}

// TestReadLease2ExactSize verifies that ReadLease2 correctly handles
// data that is exactly 40 bytes with no remainder.
func TestReadLease2ExactSize(t *testing.T) {
	assert := assert.New(t)

	// Create exactly 40 bytes of data
	var gatewayHash data.Hash
	copy(gatewayHash[:], []byte("exact_size_gateway_hash_32_bytes"))
	tunnelID := uint32(99999)
	expirationTime := time.Now().Add(1 * time.Hour)

	lease2, err := NewLease2(gatewayHash, tunnelID, expirationTime)
	assert.NoError(err)

	// Parse exactly 40 bytes
	parsedLease2, remainder, err := ReadLease2(lease2.Bytes())
	assert.NoError(err)
	assert.Empty(remainder)
	assert.Equal(lease2.Bytes(), parsedLease2.Bytes())
}

// TestNewLease2FromBytesValidData verifies that NewLease2FromBytes correctly
// creates a Lease2 pointer from valid byte data.
func TestNewLease2FromBytesValidData(t *testing.T) {
	assert := assert.New(t)

	// Create valid Lease2 data
	var gatewayHash data.Hash
	copy(gatewayHash[:], []byte("pointer_test_gateway_hash_32byte"))
	tunnelID := uint32(11111)
	expirationTime := time.Date(2027, 3, 20, 10, 15, 30, 0, time.UTC)

	originalLease2, err := NewLease2(gatewayHash, tunnelID, expirationTime)
	assert.NoError(err)

	// Parse using pointer function
	lease2Ptr, remainder, err := NewLease2FromBytes(originalLease2.Bytes())
	assert.NoError(err)
	assert.NotNil(lease2Ptr)
	assert.Empty(remainder)

	// Verify pointer data matches original
	assert.Equal(originalLease2.TunnelGateway(), lease2Ptr.TunnelGateway())
	assert.Equal(originalLease2.TunnelID(), lease2Ptr.TunnelID())
	assert.Equal(originalLease2.EndDate(), lease2Ptr.EndDate())
}

// TestNewLease2FromBytesInsufficientData verifies that NewLease2FromBytes
// returns nil and an error when given insufficient data.
func TestNewLease2FromBytesInsufficientData(t *testing.T) {
	assert := assert.New(t)

	insufficientData := make([]byte, 20)
	lease2Ptr, _, err := NewLease2FromBytes(insufficientData)
	assert.Error(err)
	assert.Nil(lease2Ptr)
}

// TestLease2Bytes verifies that Bytes() returns the complete 40-byte Lease2 structure.
func TestLease2Bytes(t *testing.T) {
	assert := assert.New(t)

	var gatewayHash data.Hash
	copy(gatewayHash[:], []byte("bytes_test_gateway_hash_32_bytes"))
	tunnelID := uint32(77777)
	expirationTime := time.Date(2028, 9, 10, 14, 45, 0, 0, time.UTC)

	lease2, err := NewLease2(gatewayHash, tunnelID, expirationTime)
	assert.NoError(err)

	bytes := lease2.Bytes()
	assert.Equal(LEASE2_SIZE, len(bytes))
	assert.Equal(lease2[:], bytes)
}

// TestLease2VsLeaseSize verifies that Lease2 is indeed 4 bytes smaller than Lease.
func TestLease2VsLeaseSize(t *testing.T) {
	assert := assert.New(t)

	assert.Equal(40, LEASE2_SIZE, "Lease2 should be 40 bytes")
	assert.Equal(44, LEASE_SIZE, "Lease should be 44 bytes")
	assert.Equal(4, LEASE_SIZE-LEASE2_SIZE, "Lease2 should be 4 bytes smaller than Lease")
}

// TestLease2TimestampRange verifies that Lease2 can handle the full range
// of 4-byte timestamps (until year 2106).
func TestLease2TimestampRange(t *testing.T) {
	assert := assert.New(t)

	var gatewayHash data.Hash
	copy(gatewayHash[:], []byte("timestamp_range_test_gateway_hash"))

	// Test near-future timestamp
	nearFuture := time.Now().Add(24 * time.Hour) // Tomorrow
	lease2Future, err := NewLease2(gatewayHash, 1, nearFuture)
	assert.NoError(err)
	assert.Equal(uint32(nearFuture.Unix()), lease2Future.EndDate())

	// Test far-future timestamp (near limit of 32-bit unsigned int)
	farFuture := time.Date(2106, 2, 7, 6, 28, 0, 0, time.UTC) // Close to uint32 max
	lease2Far, err := NewLease2(gatewayHash, 2, farFuture)
	assert.NoError(err)
	assert.Equal(uint32(farFuture.Unix()), lease2Far.EndDate())

	// Verify time conversion works correctly
	assert.Equal(nearFuture.Unix(), lease2Future.Time().Unix())
	assert.Equal(farFuture.Unix(), lease2Far.Time().Unix())
}

// TestLease2RoundTrip verifies that a Lease2 can be created, serialized,
// parsed, and retain all its original values.
func TestLease2RoundTrip(t *testing.T) {
	assert := assert.New(t)

	// Create original Lease2
	var gatewayHash data.Hash
	copy(gatewayHash[:], []byte("roundtrip_test_gateway_hash_32by"))
	tunnelID := uint32(42424)
	expirationTime := time.Now().Add(1 * time.Hour) // 1 hour from now

	originalLease2, err := NewLease2(gatewayHash, tunnelID, expirationTime)
	assert.NoError(err)

	// Serialize to bytes
	serialized := originalLease2.Bytes()

	// Parse back from bytes
	parsedLease2, remainder, err := ReadLease2(serialized)
	assert.NoError(err)
	assert.Empty(remainder)

	// Verify all fields match
	assert.Equal(originalLease2.TunnelGateway(), parsedLease2.TunnelGateway())
	assert.Equal(originalLease2.TunnelID(), parsedLease2.TunnelID())
	assert.Equal(originalLease2.EndDate(), parsedLease2.EndDate())
	assert.Equal(originalLease2.Time().Unix(), parsedLease2.Time().Unix())
	assert.Equal(originalLease2.Bytes(), parsedLease2.Bytes())
}
