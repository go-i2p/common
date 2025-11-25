# encrypted_leaseset

Package `encrypted_leaseset` implements the I2P EncryptedLeaseSet common data structure (Database Store Type 5).

## Overview

EncryptedLeaseSet provides encrypted and blinded lease sets for enhanced privacy and forward secrecy in I2P hidden services. Introduced in I2P version 0.9.38, it addresses privacy concerns with traditional lease sets by:

- **Encrypting destination and leases**: The actual service destination and tunnel endpoints are encrypted, protecting against traffic analysis
- **Blinded key derivation**: Each published EncryptedLeaseSet uses a blinded destination, preventing correlation between different publications of the same service
- **Per-client encryption**: Unique symmetric keys can be derived for each authorized client
- **Forward secrecy**: Cookie rotation ensures past encrypted data cannot be decrypted if keys are compromised
- **Anti-replay protection**: Cookies prevent reuse of captured encrypted lease sets

## Structure

An EncryptedLeaseSet consists of the following components (wire format):

```text
+----+----+----+----+----+----+----+----+
| blinded_destination (387+ bytes)      |
|   - Derived from actual destination   |
|   - Prevents correlation              |
+----+----+----+----+----+----+----+----+
| published (4 bytes)                   |
|   - Seconds since Unix epoch          |
+----+----+----+----+----+----+----+----+
| expires (2 bytes)                     |
|   - Offset from published (seconds)   |
+----+----+----+----+----+----+----+----+
| flags (2 bytes)                       |
|   - Bit 0: Offline signature present  |
|   - Bit 1: Unpublished                |
|   - Bit 2: Blinded (always set)       |
+----+----+----+----+----+----+----+----+
| [offline_signature] (variable)        |
|   - Optional, if flags bit 0 set      |
+----+----+----+----+----+----+----+----+
| options (2+ bytes)                    |
|   - Mapping for service metadata      |
+----+----+----+----+----+----+----+----+
| cookie (32 bytes)                     |
|   - For key derivation and anti-replay|
+----+----+----+----+----+----+----+----+
| inner_length (2 bytes)                |
|   - Size of encrypted data            |
+----+----+----+----+----+----+----+----+
| encrypted_inner_data (variable)       |
|   - Encrypted LeaseSet2 structure     |
+----+----+----+----+----+----+----+----+
| signature (variable)                  |
|   - By blinded destination or         |
|     transient key                     |
+----+----+----+----+----+----+----+----+
```

## Usage

### Basic Example (Structure Only - Phase 3)

**Note**: Full encryption/decryption functionality will be implemented in Phase 4 after crypto package integration.

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/go-i2p/common/encrypted_leaseset"
)

func main() {
    // Parse encrypted lease set from network data
    data := []byte{/* received from network */}
    els, remainder, err := encrypted_leaseset.ReadEncryptedLeaseSet(data)
    if err != nil {
        log.Fatal("Failed to parse:", err)
    }
    
    // Check if expired
    if els.IsExpired() {
        fmt.Println("Encrypted lease set has expired")
        return
    }
    
    // Access outer (public) fields
    fmt.Printf("Blinded destination: %s\n", els.BlindedDestination().Base32Address())
    fmt.Printf("Published: %s\n", els.PublishedTime())
    fmt.Printf("Expires: %s\n", els.ExpirationTime())
    fmt.Printf("Cookie: %x\n", els.Cookie())
    fmt.Printf("Encrypted data length: %d bytes\n", els.InnerLength())
    
    // Check flags
    if els.HasOfflineKeys() {
        fmt.Println("Uses offline signature")
    }
    if els.IsBlinded() {
        fmt.Println("Uses blinded destination (always true)")
    }
}
```

### Future Usage (Phase 4 - With Crypto)

```go
// Decrypt inner data (requires authorization cookie and private key)
authCookie := []byte{/* 32-byte cookie */}
privateKey := /* your X25519 private key */

innerData, err := els.DecryptInnerData(authCookie, privateKey)
if err != nil {
    log.Fatal("Decryption failed:", err)
}

// Parse inner LeaseSet2
innerLS2, _, err := lease_set2.ReadLeaseSet2(innerData)
if err != nil {
    log.Fatal("Failed to parse inner LeaseSet2:", err)
}

// Access actual destination and leases
dest := innerLS2.Destination()
leases := innerLS2.Leases()

fmt.Printf("Actual destination: %s\n", dest.Base32Address())
fmt.Printf("Number of leases: %d\n", len(leases))
```

## Security Considerations

### Blinding

The blinded destination is derived from the actual service destination using a blinding factor (alpha). This ensures:

- **Unlinkability**: Different EncryptedLeaseSet publications cannot be correlated to the same service
- **Forward unlinkability**: Even if the blinding secret is compromised, past publications remain unlinkable
- **Verifiability**: Clients can verify the blinded destination matches the expected service

### Cookie Management

The 32-byte cookie serves multiple purposes:

- **Key derivation**: Combined with ECDH shared secret via HKDF to derive symmetric encryption key
- **Anti-replay**: Each EncryptedLeaseSet should use a unique cookie
- **Authorization**: Only clients with the correct cookie can decrypt the inner data

Best practices:

- Generate cryptographically random cookies
- Rotate cookies periodically (e.g., every publication)
- Never reuse cookies across different publications
- Include cookie in authorization credentials

### Encryption

The encrypted inner data protects:

- **Destination**: The actual service destination and its signing/encryption keys
- **Encryption keys**: Per-endpoint encryption keys (if multiple)
- **Leases**: Active tunnel endpoints and their expiration times

Recommended algorithms (Phase 4):

- **Symmetric encryption**: ChaCha20-Poly1305 or AES-256-GCM
- **Key derivation**: HKDF-SHA256
- **Key agreement**: X25519 (Curve25519 ECDH)

## Implementation Status

### Phase 3.1: EncryptedLeaseSet Foundation ✅ Complete

- ✅ Package structure created
- ✅ Constants defined
- ✅ Struct definitions complete
- ✅ README documentation
- ✅ Header parsing (destination, published, expires, flags)
- ✅ Options parsing
- ✅ Signature parsing
- ✅ `Bytes()` for outer structure
- ✅ Comprehensive test suite (72.7% coverage)

### Phase 3.2: Crypto Package Assessment (In Progress)

Current status of github.com/go-i2p/crypto@v0.0.5:

**Available:**
- ✅ ChaCha20Poly1305 AEAD - Ready for inner data encryption
- ✅ HKDF - Ready for key derivation
- ✅ KDF with standard purposes - Ready for consistent key derivation
- ✅ X25519 ECDH - Ready for key agreement
- ✅ Ed25519 - Ready for signing
- ✅ Elligator2 - Available for obfuscation (if needed)

**Missing (BLOCKING Phase 4):**
- ❌ Ed25519 point blinding - Required for blinded destinations
- ❌ Blinding factor derivation - Required for per-day blinding
- ❌ PurposeEncryptedLeaseSetEncryption constant - Required for KDF

### Phase 4: Encryption Integration (BLOCKED)

Blocked pending crypto package updates:

- ⏳ Crypto package integration
- ⏳ `DecryptInnerData()` method
- ⏳ `EncryptInnerLeaseSet2()` helper
- ⏳ Blinding key derivation (BLOCKED - needs crypto package)
- ⏳ End-to-end encryption/decryption tests
- ⏳ Security property validation

## API Reference

### Core Functions (Planned)

```go
// Reading/parsing
func ReadEncryptedLeaseSet(data []byte) (EncryptedLeaseSet, []byte, error)

// Serialization
func (els *EncryptedLeaseSet) Bytes() ([]byte, error)

// Accessors
func (els *EncryptedLeaseSet) BlindedDestination() destination.Destination
func (els *EncryptedLeaseSet) Published() uint32
func (els *EncryptedLeaseSet) PublishedTime() time.Time
func (els *EncryptedLeaseSet) Expires() uint16
func (els *EncryptedLeaseSet) ExpirationTime() time.Time
func (els *EncryptedLeaseSet) IsExpired() bool
func (els *EncryptedLeaseSet) Flags() uint16
func (els *EncryptedLeaseSet) HasOfflineKeys() bool
func (els *EncryptedLeaseSet) IsUnpublished() bool
func (els *EncryptedLeaseSet) IsBlinded() bool  // Always true
func (els *EncryptedLeaseSet) OfflineSignature() *offline_signature.OfflineSignature
func (els *EncryptedLeaseSet) Options() data.Mapping
func (els *EncryptedLeaseSet) Cookie() [32]byte
func (els *EncryptedLeaseSet) InnerLength() uint16
func (els *EncryptedLeaseSet) EncryptedInnerData() []byte
func (els *EncryptedLeaseSet) Signature() sig.Signature

// Encryption/decryption (Phase 4)
func (els *EncryptedLeaseSet) DecryptInnerData(authCookie []byte, privateKey interface{}) ([]byte, error)
func EncryptInnerLeaseSet2(ls2 lease_set2.LeaseSet2, cookie [32]byte, publicKey interface{}) ([]byte, error)
```

## Related Packages

- `github.com/go-i2p/common/lease_set` - Legacy LeaseSet (Type 1)
- `github.com/go-i2p/common/lease_set2` - Modern LeaseSet (Type 3)
- `github.com/go-i2p/common/meta_leaseset` - MetaLeaseSet aggregation (Type 7)
- `github.com/go-i2p/common/destination` - Destination and identity handling
- `github.com/go-i2p/common/offline_signature` - Offline signature support
- `github.com/go-i2p/crypto` - Cryptographic operations (Phase 4)

## I2P Specification

- **Common Structures**: <https://geti2p.net/spec/common-structures>
- **EncryptedLeaseSet**: <https://geti2p.net/spec/common-structures#encryptedleaseset>
- **LeaseSet2**: <https://geti2p.net/spec/common-structures#leaseset2>
- **Proposal 123**: <https://geti2p.net/spec/proposals/123-new-netdb-entries>

## Version

Target I2P Specification: **0.9.67** (June 2025)  
Implementation Phase: **Phase 3 - Foundation**

## License

See the main repository LICENSE file for licensing information.
