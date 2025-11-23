# offline_signature
--
    import "github.com/go-i2p/common/offline_signature"

Package offline_signature implements the I2P OfflineSignature common data
structure according to specification version 0.9.67.

OfflineSignature is an optional part of LeaseSet2Header, and is also used in
streaming and I2CP protocols. It allows a destination to use offline signing
keys for enhanced security by separating the long-term signing key from the
transient signing key used for daily operations.

Specification: https://geti2p.net/spec/common-structures#offlinesignature
Introduced: I2P version 0.9.38 (Proposal 123)

Package offline_signature implements the I2P OfflineSignature common data
structure according to specification version 0.9.67.

OfflineSignature provides enhanced security for I2P destinations by enabling the
use of short-lived transient signing keys while keeping the long-term
destination signing key offline. This structure is used in LeaseSet2Header,
streaming, and I2CP protocols.

Key features:

    - Transient signing keys with expiration timestamps
    - Offline generation for enhanced security
    - Signature verification using destination's long-term key
    - Complete I2P specification 0.9.67 compliance

Specification: https://geti2p.net/spec/common-structures#offlinesignature
Introduced: I2P version 0.9.38 (Proposal 123)

Package offline_signature implements the I2P OfflineSignature common data
structure.

Package offline_signature implements the I2P OfflineSignature common data
structure.

## Usage

```go
const (
	// OFFLINE_SIGNATURE_MIN_SIZE defines the minimum byte length of an OfflineSignature.
	// This includes: 4 bytes (expires) + 2 bytes (sigtype) + minimum key size + minimum signature size.
	// The actual minimum depends on signature types, but EdDSA (type 7) gives us 4+2+32+64 = 102 bytes.
	OFFLINE_SIGNATURE_MIN_SIZE = 102

	// EXPIRES_SIZE defines the byte length of the expires field (4-byte timestamp).
	// Seconds since the epoch, rolls over in 2106.
	EXPIRES_SIZE = 4

	// SIGTYPE_SIZE defines the byte length of the signature type field.
	SIGTYPE_SIZE = 2
)
```

```go
var (
	// ErrInvalidOfflineSignatureData indicates that the provided data cannot be parsed as an OfflineSignature.
	ErrInvalidOfflineSignatureData = errors.New("invalid offline signature data")

	// ErrInsufficientData indicates that there is not enough data to parse the complete OfflineSignature.
	ErrInsufficientData = errors.New("insufficient data for offline signature")

	// ErrUnknownSignatureType indicates that the signature type is not recognized or supported.
	ErrUnknownSignatureType = errors.New("unknown or unsupported signature type")

	// ErrExpiredOfflineSignature indicates that the offline signature has passed its expiration time.
	ErrExpiredOfflineSignature = errors.New("offline signature has expired")
)
```

#### func  SignatureSize

```go
func SignatureSize(sigtype uint16) int
```
SignatureSize returns the byte length of a signature for the given signature
type. This function maps I2P signature type identifiers to their corresponding
signature sizes. Returns 0 for unknown or unsupported signature types.

Signature sizes are defined in I2P specification 0.9.67. Reference:
https://geti2p.net/spec/common-structures#signature

#### func  SigningPublicKeySize

```go
func SigningPublicKeySize(sigtype uint16) int
```
SigningPublicKeySize returns the byte length of a signing public key for the
given signature type. This function maps I2P signature type identifiers to their
corresponding public key sizes. Returns 0 for unknown or unsupported signature
types.

Signature types map to signing public key sizes as defined in I2P specification
0.9.67. Reference: https://geti2p.net/spec/common-structures#signingpublickey

#### type OfflineSignature

```go
type OfflineSignature struct {
}
```

OfflineSignature represents an I2P offline signature structure used in
LeaseSet2, streaming, and I2CP protocols. It enables enhanced security by
allowing destinations to use short-lived transient signing keys while keeping
the long-term destination signing key offline.

The structure contains:

    - Expiration timestamp for the transient key
    - Transient signing public key type and data
    - Signature by the destination's long-term key proving authorization

This structure can and should be generated offline for maximum security.

#### func  NewOfflineSignature

```go
func NewOfflineSignature(expires uint32, transientSigType uint16, transientPublicKey []byte,
	signature []byte, destinationSigType uint16) (OfflineSignature, error)
```
NewOfflineSignature creates a new OfflineSignature from raw components. This is
a convenience constructor for creating OfflineSignature structures
programmatically.

Parameters:

    - expires: Unix timestamp (seconds since epoch) when the transient key expires
    - transientSigType: Signature type of the transient signing key
    - transientPublicKey: Raw bytes of the transient signing public key
    - signature: Signature by the destination's long-term key
    - destinationSigType: Signature type of the destination (for validation)

Returns:

    - OfflineSignature: Constructed offline signature structure
    - error: nil on success, error if parameters are invalid

#### func  ReadOfflineSignature

```go
func ReadOfflineSignature(data []byte, destinationSigType uint16) (OfflineSignature, []byte, error)
```
ReadOfflineSignature parses an OfflineSignature from raw byte data according to
I2P specification 0.9.67.

This function extracts the expiration timestamp, transient signing public key
type and data, and the signature created by the destination's long-term signing
key. The destinationSigType parameter is required to determine the correct
signature length.

Parameters:

    - data: Raw byte slice containing the OfflineSignature data
    - destinationSigType: Signature type of the destination (required for signature length calculation)

Returns:

    - OfflineSignature: Parsed offline signature structure
    - remainder: Remaining bytes after the OfflineSignature
    - error: nil on success, error describing the parsing failure otherwise

The function validates:

    - Minimum data length requirements
    - Known signature type for transient key
    - Known signature type for destination
    - Sufficient data for complete structure

Example usage:

    offlineSig, remainder, err := ReadOfflineSignature(data, signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
    if err != nil {
        log.Fatal("Failed to parse offline signature:", err)
    }

#### func (*OfflineSignature) Bytes

```go
func (o *OfflineSignature) Bytes() []byte
```
Bytes serializes the OfflineSignature to its wire format according to I2P
specification 0.9.67.

The serialized format is:

    - 4 bytes: expires (big-endian uint32)
    - 2 bytes: sigtype (big-endian uint16)
    - variable: transient_public_key (length determined by sigtype)
    - variable: signature (length determined by destination signature type)

Returns the complete binary representation suitable for network transmission or
storage.

#### func (*OfflineSignature) DestinationSigType

```go
func (o *OfflineSignature) DestinationSigType() uint16
```
DestinationSigType returns the signature type of the destination (used for
signature length).

#### func (*OfflineSignature) Expires

```go
func (o *OfflineSignature) Expires() uint32
```
Expires returns the expiration timestamp as a uint32 (seconds since epoch). The
timestamp rolls over in 2106.

#### func (*OfflineSignature) ExpiresDate

```go
func (o *OfflineSignature) ExpiresDate() (*data.Date, error)
```
ExpiresDate returns the expiration timestamp as an I2P Date (8 bytes). This
converts the 4-byte timestamp to the 8-byte I2P Date format (milliseconds since
epoch).

Note: The 4-byte timestamp in OfflineSignature represents seconds, while I2P
Date uses milliseconds. This function provides conversion for compatibility with
other I2P date structures.

#### func (*OfflineSignature) ExpiresTime

```go
func (o *OfflineSignature) ExpiresTime() time.Time
```
ExpiresTime returns the expiration timestamp as a time.Time for convenience.

#### func (*OfflineSignature) IsExpired

```go
func (o *OfflineSignature) IsExpired() bool
```
IsExpired checks if the offline signature has passed its expiration time.
Returns true if the current time is after the expiration timestamp.

#### func (*OfflineSignature) Len

```go
func (o *OfflineSignature) Len() int
```
Len returns the total byte length of the serialized OfflineSignature.

#### func (*OfflineSignature) Signature

```go
func (o *OfflineSignature) Signature() []byte
```
Signature returns a copy of the signature bytes created by the destination's
long-term key.

#### func (*OfflineSignature) String

```go
func (o *OfflineSignature) String() string
```
String returns a human-readable representation of the OfflineSignature for
debugging. Includes expiration time, signature types, and data lengths.

#### func (*OfflineSignature) TransientPublicKey

```go
func (o *OfflineSignature) TransientPublicKey() []byte
```
TransientPublicKey returns a copy of the transient signing public key bytes.

#### func (*OfflineSignature) TransientSigType

```go
func (o *OfflineSignature) TransientSigType() uint16
```
TransientSigType returns the signature type of the transient signing public key.
