# encrypted_leaseset

Package `encrypted_leaseset` implements the I2P EncryptedLeaseSet common data structure (Database Store Type 5).

## Overview

EncryptedLeaseSet provides encrypted and blinded lease sets for enhanced privacy in I2P hidden services. Introduced in I2P version 0.9.38, it addresses privacy concerns with traditional lease sets by:

- **Encrypting destination and leases**: The actual service destination and tunnel endpoints are encrypted, protecting against traffic analysis
- **Blinded key derivation**: Each published EncryptedLeaseSet uses a blinded signing key, preventing correlation between different publications of the same service
- **Two-layer encryption**: Uses HKDF-SHA256 + ChaCha20 stream cipher with per-publication random salts
- **Subcredential binding**: Encryption is bound to knowledge of the destination's signing public key via a subcredential, so only clients who know the original destination can decrypt

## Wire Format

An EncryptedLeaseSet consists of the following fields (cleartext outer structure):

```text
+----+----+----+----+----+----+----+----+
| sig_type (2 bytes)                    |
|   - Red25519 (11) or Ed25519 (7)     |
+----+----+----+----+----+----+----+----+
| blinded_public_key (variable)         |
|   - 32 bytes for Ed25519/Red25519    |
+----+----+----+----+----+----+----+----+
| published (4 bytes)                   |
|   - Seconds since Unix epoch          |
+----+----+----+----+----+----+----+----+
| expires (2 bytes)                     |
|   - Offset from published (seconds)   |
+----+----+----+----+----+----+----+----+
| flags (2 bytes)                       |
|   - Bit 0: Offline signature present  |
|   - Bit 1: Unpublished               |
|   - Bits 2-15: Reserved (must be 0)  |
+----+----+----+----+----+----+----+----+
| [offline_signature] (variable)        |
|   - Present only if flags bit 0 set   |
+----+----+----+----+----+----+----+----+
| inner_length (2 bytes)                |
|   - Size of encrypted_data            |
+----+----+----+----+----+----+----+----+
| encrypted_data (inner_length bytes)   |
|   - Two-layer ChaCha20 encrypted      |
|     LeaseSet2 (see below)             |
+----+----+----+----+----+----+----+----+
| signature (variable)                  |
|   - By blinded key or transient key   |
|   - 64 bytes for Ed25519/Red25519    |
+----+----+----+----+----+----+----+----+
```

### Encrypted Data Structure

The `encrypted_data` field uses a two-layer ChaCha20 stream cipher scheme:

```text
encrypted_data = outerSalt(32) || Layer1Ciphertext

Layer 1 plaintext = flag(1) || [per-client auth block] || innerCiphertext

innerCiphertext   = innerSalt(32) || Layer2Ciphertext

Layer 2 plaintext = serialized LeaseSet2
```

The `flag` byte's bit 0 selects per-client authorization; when set, bits 3-1
select the scheme (DH or PSK) and the auth block follows (see
[Per-Client Authorization](#per-client-authorization)). When clear (auth type 0)
no auth block is present.

Key derivation:
- Layer 1 key: `HKDF-SHA256(outerSalt, subcredential || published, "ELS2_L1K", 44)`
- Layer 2 key: `HKDF-SHA256(innerSalt, authCookie || subcredential || published, "ELS2_L2K", 44)`

For auth type 0, `authCookie` is the zero-length byte array, so the Layer 2 input
reduces to `subcredential || published`.

Where `subcredential = SHA-256("subcredential" || credential || blindedPubKey)` and `credential = SHA-256("credential" || destSigningPubKey)`.

## Usage

### Parsing an EncryptedLeaseSet

```go
// Parse from network data
els, remainder, err := encrypted_leaseset.ReadEncryptedLeaseSet(data)
if err != nil {
    log.Fatal("Failed to parse:", err)
}

// Access outer fields
fmt.Printf("Sig type: %d\n", els.SigType())
fmt.Printf("Published: %s\n", els.PublishedTime())
fmt.Printf("Expires: %s\n", els.ExpirationTime())
fmt.Printf("Encrypted data length: %d bytes\n", els.InnerLength())
```

### Decrypting the Inner LeaseSet2

```go
// Derive subcredential from known destination signing key and blinded key
subcredential := encrypted_leaseset.DeriveSubcredential(
    destSigningPubKey,
    els.BlindedPublicKey(),
)

// Decrypt
innerLS2, err := els.DecryptInnerData(subcredential)
if err != nil {
    log.Fatal("Decryption failed:", err)
}

// Access actual destination and leases
dest := innerLS2.Destination()
leases := innerLS2.Leases()
base32Addr, err := dest.Base32Address()
if err != nil {
    log.Fatal("Failed to encode address:", err)
}
fmt.Printf("Actual destination: %s\n", base32Addr)
fmt.Printf("Number of leases: %d\n", len(leases))
```

### Constructing and Encrypting

```go
// Derive subcredential
subcredential := encrypted_leaseset.DeriveSubcredential(destSigningPubKey, blindedPubKey)

// Encrypt the inner LeaseSet2
published := uint32(time.Now().Unix())
encryptedData, err := encrypted_leaseset.EncryptInnerLeaseSet2(
    ls2, subcredential, published,
)
if err != nil {
    log.Fatal("Encryption failed:", err)
}

// Build the EncryptedLeaseSet
els, err := encrypted_leaseset.NewEncryptedLeaseSet(
    key_certificate.KEYCERT_SIGN_ED25519,
    blindedPubKey,
    published,
    600,     // expires offset (seconds)
    0,       // flags
    nil,     // offline signature (nil if not used)
    encryptedData,
    signingPrivKey,
)
if err != nil {
    log.Fatal("Construction failed:", err)
}

// Serialize for network transmission
wireBytes, err := els.Bytes()
```

## Security Considerations

### Blinding

The blinded signing key is derived from the destination's Ed25519 signing key using a date-dependent blinding factor. This ensures:

- **Unlinkability**: Different publications cannot be correlated to the same service
- **Verifiability**: Clients who know the destination can derive the expected blinded key

### Subcredentials

The subcredential binds encryption to knowledge of the original destination's signing public key. Only clients who know the unblinded destination can compute the subcredential and decrypt the inner data.

### Encryption

The inner LeaseSet2 is protected by two-layer ChaCha20 stream cipher:

- **Layer 1**: Keyed by `HKDF(outerSalt, subcredential || published, "ELS2_L1K")`
- **Layer 2**: Keyed by `HKDF(innerSalt, subcredential || published, "ELS2_L2K")`
- Random salts ensure distinct ciphertexts for each publication

### Known Limitations

- **Red25519 signing**: The spec mandates Red25519 (randomized nonces) for the outer signature. This implementation uses standard deterministic Ed25519, which produces verifiable signatures but allows correlation of re-publications of the same data. A full Red25519 implementation is planned.

## Per-Client Authorization

EncryptedLeaseSet supports restricting decryption to a list of authorized clients
(I2P spec §"Per-client authorization"). A random 32-byte `authCookie` is generated
per publication, encrypted to each authorized client, and folded into the Layer 2
key derivation (`innerInput = authCookie || subcredential || published`). Only
clients that can recover `authCookie` can decrypt the inner LeaseSet2.

Two schemes are supported:

- **DH (auth type 1, X25519)** — each client generates an X25519 keypair and gives
  the server its public key. The server uses an ephemeral DH exchange so the
  client's private key never leaves its device.
- **PSK (auth type 2)** — each client shares a 32-byte pre-shared key with the
  server out-of-band.

The Layer 1 middle layer carries, after a 1-byte flag, either the ephemeral public
key (DH) or salt (PSK), a 2-byte client count, and one 40-byte `authClient` entry
per client (`clientID(8) || clientCookie(32)`).

### Encrypting with per-client authorization (server)

```go
// DH: collect each authorized client's X25519 public key (cpk_i).
cfg := &encrypted_leaseset.ClientAuthConfig{
    AuthType:           encrypted_leaseset.ENCRYPTED_LEASESET_AUTH_TYPE_DH,
    DHClientPublicKeys: [][]byte{clientPubKey1, clientPubKey2},
}

// PSK alternative:
// cfg := &encrypted_leaseset.ClientAuthConfig{
//     AuthType:      encrypted_leaseset.ENCRYPTED_LEASESET_AUTH_TYPE_PSK,
//     PSKClientKeys: [][]byte{psk1, psk2},
// }

encryptedData, err := encrypted_leaseset.EncryptInnerLeaseSet2WithAuth(
    ls2, subcredential, published, cfg,
)
```

### Decrypting with a client credential (client)

```go
// DH: supply the client's X25519 private key (csk_i).
cred := &encrypted_leaseset.ClientCredential{
    AuthType:     encrypted_leaseset.ENCRYPTED_LEASESET_AUTH_TYPE_DH,
    DHPrivateKey: clientPrivKey,
}

// PSK alternative:
// cred := &encrypted_leaseset.ClientCredential{
//     AuthType: encrypted_leaseset.ENCRYPTED_LEASESET_AUTH_TYPE_PSK,
//     PSK:      psk,
// }

innerLS2, err := els.DecryptInnerDataWithCredential(subcredential, cred)
if err != nil {
    // err is "not authorized" if this client has no matching entry.
    log.Fatal("Decryption failed:", err)
}
```

For auth type 0 (no per-client authorization), pass `cfg == nil` /
`cred == nil`, or use `EncryptInnerLeaseSet2` / `DecryptInnerData`.

## API Reference

### Core Functions

```go
// Parsing
func ReadEncryptedLeaseSet(data []byte) (EncryptedLeaseSet, []byte, error)

// Construction
func NewEncryptedLeaseSet(sigType uint16, blindedPubKey []byte, published uint32,
    expiresOffset uint16, flags uint16, offlineSig *offline_signature.OfflineSignature,
    encryptedInnerData []byte, signingKey interface{}) (*EncryptedLeaseSet, error)
func NewEncryptedLeaseSetFromDestination(dest destination.Destination, published uint32,
    expiresOffset uint16, flags uint16, offlineSig *offline_signature.OfflineSignature,
    encryptedInnerData []byte, signingKey interface{}) (*EncryptedLeaseSet, error)

// Encryption
func DeriveSubcredential(destSigningPubKey []byte, sigTypeA uint16,
    blindedPubKey []byte, sigTypeBlinded uint16) [32]byte
func EncryptInnerLeaseSet2(ls2 *lease_set2.LeaseSet2, subcredential [32]byte,
    published uint32) ([]byte, error)
func EncryptInnerLeaseSet2WithAuth(ls2 *lease_set2.LeaseSet2, subcredential [32]byte,
    published uint32, cfg *ClientAuthConfig) ([]byte, error)

// Blinding
func CreateBlindedDestination(dest destination.Destination, secret []byte,
    date time.Time) (destination.Destination, error)

// Serialization
func (els *EncryptedLeaseSet) Bytes() ([]byte, error)

// Accessors
func (els *EncryptedLeaseSet) SigType() uint16
func (els *EncryptedLeaseSet) BlindedPublicKey() []byte
func (els *EncryptedLeaseSet) Published() uint32
func (els *EncryptedLeaseSet) PublishedTime() time.Time
func (els *EncryptedLeaseSet) Expires() uint16
func (els *EncryptedLeaseSet) ExpirationTime() time.Time
func (els *EncryptedLeaseSet) IsExpired() bool
func (els *EncryptedLeaseSet) Flags() uint16
func (els *EncryptedLeaseSet) HasOfflineKeys() bool
func (els *EncryptedLeaseSet) IsUnpublished() bool
func (els *EncryptedLeaseSet) OfflineSignature() *offline_signature.OfflineSignature
func (els *EncryptedLeaseSet) InnerLength() uint16
func (els *EncryptedLeaseSet) EncryptedInnerData() []byte
func (els *EncryptedLeaseSet) Signature() sig.Signature

// Decryption
func (els *EncryptedLeaseSet) DecryptInnerData(subcredential [32]byte) (*lease_set2.LeaseSet2, error)
func (els *EncryptedLeaseSet) DecryptInnerDataWithCredential(subcredential [32]byte,
    cred *ClientCredential) (*lease_set2.LeaseSet2, error)

// Validation
func (els *EncryptedLeaseSet) Validate() error
func (els *EncryptedLeaseSet) IsValid() bool

// Verification
func (els *EncryptedLeaseSet) Verify() error
```

## Related Packages

- `github.com/go-i2p/common/lease_set2` - Modern LeaseSet (Type 3) — the inner structure
- `github.com/go-i2p/common/destination` - Destination and identity handling
- `github.com/go-i2p/common/offline_signature` - Offline signature support
- `github.com/go-i2p/common/key_certificate` - Key certificate types and sizes
- `github.com/go-i2p/crypto` - Cryptographic operations (Ed25519, blinding)

## I2P Specification

- **Common Structures — EncryptedLeaseSet**: <https://geti2p.net/spec/common-structures#encryptedleaseset>
- **Encrypted LeaseSet Specification**: <https://geti2p.net/spec/encryptedleaseset>
- **Proposal 123**: <https://geti2p.net/spec/proposals/123-new-netdb-entries>

## License

See the main repository LICENSE file for licensing information.
