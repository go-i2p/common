# lease_set2
--
    import "github.com/go-i2p/common/lease_set2"

Package lease_set2 implements the I2P LeaseSet2 common data structure

Package lease_set2 implements the I2P LeaseSet2 common data structure

Package lease_set2 implements the I2P LeaseSet2 common data structure

## Usage

```go
const (
	// LEASESET2_MIN_SIZE is the absolute minimum size for a LeaseSet2 structure.
	// This assumes: LeaseSet2Header (395 bytes) + empty options (2 bytes) +
	// 1 encryption key (5 bytes header + 32 bytes X25519) + 0 leases (1 byte) + signature (64 bytes EdDSA)
	// = 395 + 2 + 5 + 32 + 1 + 64 = 499 bytes minimum
	LEASESET2_MIN_SIZE = 499

	// LEASESET2_HEADER_MIN_SIZE is the minimum size of LeaseSet2Header without offline signature.
	// Destination (387 bytes) + published (4 bytes) + expires (2 bytes) + flags (2 bytes)
	// = 395 bytes
	LEASESET2_HEADER_MIN_SIZE = 395

	// LEASESET2_PUBLISHED_SIZE is the size of the published timestamp field (4 bytes, seconds since epoch).
	LEASESET2_PUBLISHED_SIZE = 4

	// LEASESET2_EXPIRES_SIZE is the size of the expires offset field (2 bytes, offset from published in seconds).
	// Maximum offset is 65535 seconds (18.2 hours), but typically limited to ~660 seconds (11 minutes).
	LEASESET2_EXPIRES_SIZE = 2

	// LEASESET2_FLAGS_SIZE is the size of the flags field (2 bytes).
	LEASESET2_FLAGS_SIZE = 2

	// LEASESET2_ENCRYPTION_KEY_TYPE_SIZE is the size of each encryption key type field (2 bytes).
	LEASESET2_ENCRYPTION_KEY_TYPE_SIZE = 2

	// LEASESET2_ENCRYPTION_KEY_LENGTH_SIZE is the size of each encryption key length field (2 bytes).
	LEASESET2_ENCRYPTION_KEY_LENGTH_SIZE = 2

	// LEASESET2_MAX_LEASES is the maximum number of Lease2 structures allowed in a LeaseSet2 (16).
	// This is the same limit as legacy LeaseSet.
	LEASESET2_MAX_LEASES = 16

	// LEASESET2_MAX_ENCRYPTION_KEYS is a reasonable upper limit for the number of encryption keys.
	// While the spec doesn't define a hard maximum, practical implementations support 1-4 keys.
	LEASESET2_MAX_ENCRYPTION_KEYS = 16
)
```
LeaseSet2 Structure Size Constants These constants define the minimum and
maximum sizes for LeaseSet2 components according to I2P specification 0.9.67.

```go
const (
	// LEASESET2_FLAG_OFFLINE_KEYS indicates that an offline signature is present (bit 0).
	// When set, the LeaseSet2Header contains an OfflineSignature structure.
	LEASESET2_FLAG_OFFLINE_KEYS = 1 << 0 // 0x0001

	// LEASESET2_FLAG_UNPUBLISHED indicates this is an unpublished leaseset (bit 1).
	// Unpublished leasesets should not be flooded, published, or sent in response to queries.
	// If expired, do not query the netdb for a new one unless FLAG_BLINDED is also set.
	LEASESET2_FLAG_UNPUBLISHED = 1 << 1 // 0x0002

	// LEASESET2_FLAG_BLINDED indicates this leaseset will be blinded and encrypted when published (bit 2).
	// If set, bit 1 (UNPUBLISHED) should also be set.
	// If this leaseset expires, query the blinded location in the netdb.
	// Introduced in I2P version 0.9.42.
	LEASESET2_FLAG_BLINDED = 1 << 2 // 0x0004
)
```
LeaseSet2 Flags Constants These constants define the bit flags used in the
LeaseSet2 flags field.

```go
const (
	// LEASESET2_MAX_EXPIRES_OFFSET is the maximum value that can be stored in the expires field (2 bytes).
	// This represents 65535 seconds or approximately 18.2 hours.
	LEASESET2_MAX_EXPIRES_OFFSET = 65535

	// LEASESET2_TYPICAL_MAX_EXPIRES is the typical maximum expiration offset for LeaseSet2 (660 seconds = 11 minutes).
	// While the field supports up to 18.2 hours, most implementations limit this to ~11 minutes.
	LEASESET2_TYPICAL_MAX_EXPIRES = 660

	// METALEASESET_MAX_EXPIRES is the maximum expiration offset for MetaLeaseSet (65535 seconds = 18.2 hours).
	// MetaLeaseSet can use the full range of the expires field.
	METALEASESET_MAX_EXPIRES = 65535
)
```
LeaseSet2 Expiration Constants These constants define typical expiration time
limits for LeaseSet2 structures.

#### type EncryptionKey

```go
type EncryptionKey struct {
}
```

EncryptionKey represents a single encryption key entry in LeaseSet2. Each entry
contains the key type, length, and the actual key data.

#### type LeaseSet2

```go
type LeaseSet2 struct {
}
```

LeaseSet2 represents an I2P LeaseSet2 structure introduced in specification
0.9.38. LeaseSet2 is the modern replacement for the legacy LeaseSet, providing
enhanced features:

    - Multiple encryption keys per leaseset for crypto agility
    - More compact Lease2 structures with 4-byte timestamps
    - Service record options for DNS-SD style service discovery
    - Optional offline signature support for enhanced security
    - Published timestamp field for better versioning

https://geti2p.net/spec/common-structures#leaseset2

#### func  ReadLeaseSet2

```go
func ReadLeaseSet2(data []byte) (ls2 LeaseSet2, remainder []byte, err error)
```
ReadLeaseSet2 parses a LeaseSet2 structure from the provided byte slice. Returns
the parsed LeaseSet2, remaining bytes, and any error encountered.

The parsing process:

    1. Parse destination (387+ bytes)
    2. Parse published timestamp (4 bytes)
    3. Parse expires offset (2 bytes)
    4. Parse flags (2 bytes)
    5. If flags bit 0 set, parse offline signature (variable length)
    6. Parse options mapping (variable length, 2+ bytes)
    7. Parse encryption keys (1+ keys, variable length)
    8. Parse Lease2 structures (0+ leases, 40 bytes each)
    9. Parse signature (variable length based on signature type)

Returns error if:

    - Data is too short for minimum LeaseSet2 size
    - Destination parsing fails
    - Any component parsing fails
    - Number of encryption keys or leases exceeds maximum allowed

#### func (*LeaseSet2) Destination

```go
func (ls2 *LeaseSet2) Destination() destination.Destination
```
Destination returns the destination identity associated with this LeaseSet2. The
destination contains the signing and encryption public keys for the service.

#### func (*LeaseSet2) EncryptionKeyCount

```go
func (ls2 *LeaseSet2) EncryptionKeyCount() int
```
EncryptionKeyCount returns the number of encryption keys in this LeaseSet2.

#### func (*LeaseSet2) EncryptionKeys

```go
func (ls2 *LeaseSet2) EncryptionKeys() []EncryptionKey
```
EncryptionKeys returns the slice of encryption keys. Keys are in order of server
preference, most-preferred first.

#### func (*LeaseSet2) ExpirationTime

```go
func (ls2 *LeaseSet2) ExpirationTime() time.Time
```
ExpirationTime returns the absolute expiration time as a Go time.Time value.
This is calculated as PublishedTime() + Expires() seconds.

#### func (*LeaseSet2) Expires

```go
func (ls2 *LeaseSet2) Expires() uint16
```
Expires returns the expiration offset in seconds from the published timestamp.
The actual expiration time is Published() + Expires().

#### func (*LeaseSet2) Flags

```go
func (ls2 *LeaseSet2) Flags() uint16
```
Flags returns the raw flags value (2 bytes). Use HasOfflineKeys(),
IsUnpublished(), IsBlinded() for flag checking.

#### func (*LeaseSet2) HasOfflineKeys

```go
func (ls2 *LeaseSet2) HasOfflineKeys() bool
```
HasOfflineKeys returns true if the offline signature flag is set (bit 0). When
true, the OfflineSignature field will be populated.

#### func (*LeaseSet2) IsBlinded

```go
func (ls2 *LeaseSet2) IsBlinded() bool
```
IsBlinded returns true if the blinded flag is set (bit 2). When set, this
unencrypted leaseset will be blinded and encrypted when published. Introduced in
I2P version 0.9.42.

#### func (*LeaseSet2) IsExpired

```go
func (ls2 *LeaseSet2) IsExpired() bool
```
IsExpired checks if the LeaseSet2 has expired based on the current time. Returns
true if the current time is after the expiration time.

#### func (*LeaseSet2) IsUnpublished

```go
func (ls2 *LeaseSet2) IsUnpublished() bool
```
IsUnpublished returns true if the unpublished flag is set (bit 1). Unpublished
leasesets should not be flooded or published to the network database.

#### func (*LeaseSet2) LeaseCount

```go
func (ls2 *LeaseSet2) LeaseCount() int
```
LeaseCount returns the number of Lease2 structures in this LeaseSet2.

#### func (*LeaseSet2) Leases

```go
func (ls2 *LeaseSet2) Leases() []lease.Lease2
```
Leases returns the slice of Lease2 structures.

#### func (*LeaseSet2) OfflineSignature

```go
func (ls2 *LeaseSet2) OfflineSignature() *offline_signature.OfflineSignature
```
OfflineSignature returns the optional offline signature structure. Returns nil
if HasOfflineKeys() is false.

#### func (*LeaseSet2) Options

```go
func (ls2 *LeaseSet2) Options() common.Mapping
```
Options returns the mapping containing service record options. Options are used
for DNS-SD style service discovery.

#### func (*LeaseSet2) Published

```go
func (ls2 *LeaseSet2) Published() uint32
```
Published returns the published timestamp as a uint32 (seconds since Unix
epoch). This timestamp indicates when the LeaseSet2 was created/published.

#### func (*LeaseSet2) PublishedTime

```go
func (ls2 *LeaseSet2) PublishedTime() time.Time
```
PublishedTime returns the published timestamp as a Go time.Time value. Converts
the 4-byte second timestamp to time.Time in UTC timezone.

#### func (*LeaseSet2) Signature

```go
func (ls2 *LeaseSet2) Signature() sig.Signature
```
Signature returns the signature over the LeaseSet2 data. The signature is
created by the destination's signing key or the transient key if offline
signature is present.
