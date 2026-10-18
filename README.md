# go-i2p/common

A comprehensive Go library implementing I2P (Invisible Internet Project) network protocol common data structures and utilities. This library provides type-safe implementations of the I2P specification common structures, factored out from the main I2P router to enable reusable components for parsing, encoding, and manipulating I2P network data.

## Notes on scope:

go-i2p theoretically has strictly scoped packages for low-level operations.
This package is strictly scoped to common data structures only and properly structured.

 - [go-i2p/common](https://github.com/go-i2p/common): I2P Common datastructures

This package MAY use any of the following libraries, and SHOULD use them where possible.

 - [go-i2p/crypto](https://github.com/go-i2p/crypto): Cryptographic primitives only
 - [go-i2p/logger](https://github.com/go-i2p/logger): Structured logging wrapper

This package MUST NOT use any of the following libraries.

 - [go-i2p/noise](https://github.com/go-i2p/noise): Noise handshake implementations
 - [go-i2p/go-noise](https://github.com/go-i2p/go-noise): Noise handshake modifications and router interface
 - [go-i2p/go-i2p](https://github.com/go-i2p/go-i2p): I2P router implementation

---

## Installation

```bash
go mod init your-project
go get github.com/go-i2p/common
```

---

## Usage

### Creating Key Certificates (New Simplified API)

The library now provides simplified constructors for common key certificate types:

```go
package main

import (
    "fmt"
    "github.com/go-i2p/common/key_certificate"
)

func main() {
    // Modern Ed25519/X25519 key certificate (recommended)
    keyCert, err := key_certificate.NewEd25519X25519KeyCertificate()
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        return
    }
    
    fmt.Printf("Signing type: %d\n", keyCert.SigningPublicKeyType())
    fmt.Printf("Crypto type: %d\n", keyCert.PublicKeyType())
    
    // Or create with custom key types
    keyCert, err = key_certificate.NewKeyCertificateWithTypes(
        key_certificate.KEYCERT_SIGN_ED25519,
        key_certificate.KEYCERT_CRYPTO_X25519,
    )
}
```

### Getting Key Sizes Without Object Creation

Query key sizes for padding calculations without creating certificate objects:

```go
package main

import (
    "fmt"
    "github.com/go-i2p/common/key_certificate"
    "github.com/go-i2p/common/keys_and_cert"
)

func main() {
    // Get size information for key types
    sizes, err := key_certificate.GetKeySizes(
        key_certificate.KEYCERT_SIGN_ED25519,
        key_certificate.KEYCERT_CRYPTO_X25519,
    )
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        return
    }
    
    // Calculate padding size. ExpectedPaddingSize caps the inline signing key
    // at KEYS_AND_CERT_SPK_SIZE (128 bytes), so signing public keys larger
    // than that (P521, RSA) carry the excess in the Key Certificate payload
    // instead of reducing the padding further.
    paddingSize := keys_and_cert.ExpectedPaddingSize(
        sizes.CryptoPublicKeySize,
        sizes.SigningPublicKeySize,
    )
    
    fmt.Printf("Signature size: %d bytes\n", sizes.SignatureSize)
    fmt.Printf("Signing public key size: %d bytes\n", sizes.SigningPublicKeySize)
    fmt.Printf("Crypto public key size: %d bytes\n", sizes.CryptoPublicKeySize)
    fmt.Printf("Required padding: %d bytes\n", paddingSize)
}
```

### Using the Certificate Builder Pattern

For complex certificate construction scenarios:

```go
package main

import (
    "fmt"
    "github.com/go-i2p/common/certificate"
)

func main() {
    // Build a KEY certificate (7=Ed25519 signing, 4=X25519 crypto)
    builder := certificate.NewCertificateBuilder()
    builder, err := builder.WithKeyTypes(7, 4)
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        return
    }
    cert, err := builder.Build()
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        return
    }
    _ = cert

    // Or build a certificate with a custom payload
    // (HASHCASH payloads must be printable ASCII)
    customPayload := []byte("hashcash:WX-123456789012")
    builder2 := certificate.NewCertificateBuilder()
    builder2, err = builder2.WithType(certificate.CERT_HASHCASH)
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        return
    }
    builder2, err = builder2.WithPayload(customPayload)
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        return
    }
    cert, err = builder2.Build()
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        return
    }
    _ = cert
}
```

### Simple Integer Encoding

Use the new encoding utilities for cleaner binary encoding:

```go
package main

import (
    "fmt"
    "github.com/go-i2p/common/data"
)

func main() {
    // Encode integers without error handling (for valid values)
    signingType := data.EncodeUint16(7)  // Ed25519
    cryptoType := data.EncodeUint16(4)   // X25519
    
    fmt.Printf("Signing type bytes: %v\n", signingType[:])
    fmt.Printf("Crypto type bytes: %v\n", cryptoType[:])
    
    // Decode back to integers
    sigValue := data.DecodeUint16(signingType)
    cryptoValue := data.DecodeUint16(cryptoType)
    
    fmt.Printf("Decoded signing: %d, crypto: %d\n", sigValue, cryptoValue)
    
    // For variable-length encoding with validation
    bytes, err := data.EncodeIntN(1234, 2)
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        return
    }
    fmt.Printf("Encoded bytes: %v\n", bytes)
}
```

### Basic Certificate Parsing

```go
package main

import (
    "fmt"
    "github.com/go-i2p/common/certificate"
)

func main() {
    // Parse I2P certificate from binary data
    // A KEY certificate (type 5) with a 4-byte payload: signing type 7
    // (Ed25519) and crypto type 0 (ElGamal). The trailing 2 bytes are not
    // part of the certificate and are returned as the remainder.
    data := []byte{0x05, 0x00, 0x04, 0x00, 0x07, 0x00, 0x00, 0xaa, 0xbb}
    cert, remainder, err := certificate.ReadCertificate(data)
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        return
    }
    
    certType, err := cert.Type()
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        return
    }
    certLen, err := cert.Length()
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        return
    }
    fmt.Printf("Certificate type: %d\n", certType)
    fmt.Printf("Certificate length: %d\n", certLen)
    fmt.Printf("Remaining bytes: %d\n", len(remainder))
}
```

### Working with Destinations

```go
package main

import (
    "fmt"
    "github.com/go-i2p/common/destination"
)

func main() {
    // Read destination from binary data
    data := []byte{/* destination bytes */}
    dest, remainder, err := destination.ReadDestination(data)
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        return
    }
    _ = remainder
    base32Address, err := dest.Base32Address()
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        return
    }
    base64Address, err := dest.Base64()
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        return
    }
    fmt.Printf("Base32 address: %s\n", base32Address)
    fmt.Printf("Base64 address: %s\n", base64Address)
}
```

### Parsing Router Information

```go
package main

import (
    "fmt"
    "github.com/go-i2p/common/router_info"
)

func main() {
    // Read router info from binary data
    data := []byte{/* router info bytes */}
    routerInfo, remainder, err := router_info.ReadRouterInfo(data)
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        return
    }
    _ = remainder
    identity := routerInfo.RouterIdentity()
    addresses := routerInfo.RouterAddresses()
    capabilities := routerInfo.RouterCapabilities()
    
    fmt.Printf("Router identity: %v\n", identity)
    fmt.Printf("Router addresses: %d\n", len(addresses))
    fmt.Printf("Router capabilities: %s\n", capabilities)
}
```

### Working with I2P Strings

```go
package main

import (
    "fmt"
    "github.com/go-i2p/common/data"
)

func main() {
    // Parse I2P string from binary data
    stringData := []byte{0x05, 'h', 'e', 'l', 'l', 'o'}
    i2pString := data.I2PString(stringData)
    
    length, err := i2pString.Length()
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        return
    }
    
    content, err := i2pString.Data()
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        return
    }
    
    fmt.Printf("String length: %d\n", length)
    fmt.Printf("String content: %s\n", content)
}
```

---

## Logging

This library uses [`github.com/go-i2p/logger`](https://github.com/go-i2p/logger) for comprehensive structured logging. Every log message emitted by this library includes `pkg` and `func` fields identifying the source package and function.

### Enabling Debug Logging

Logging is disabled by default (output is discarded). `DEBUG_I2P` is the switch
that enables it; `WARNFAIL_I2P` is only read once `DEBUG_I2P` is set, so it has
no effect on its own.

```bash
# Enable debug output
DEBUG_I2P=debug go run your-program.go

# Treat warnings and errors as fatal (for strict validation) - requires DEBUG_I2P
DEBUG_I2P=debug WARNFAIL_I2P=true go run your-program.go
```

### Log Output Format

All log messages include structured fields for filtering and diagnostics:

```
time=2025-01-01 12:00:00 level=debug msg=Reading Destination from bytes func=ReadDestination input_length=387 pkg=destination
time=2025-01-01 12:00:00 level=error msg=ReadDate: data is too short func=ReadDate pkg=data
```

### Per-Package Logging

Each package has a dedicated `log.go` file declaring its logger instance. The following packages emit structured logs:

`base32`, `base64`, `certificate`, `common`, `data`, `destination`, `encrypted_leaseset`, `key_certificate`, `keys_and_cert`, `lease`, `lease_set`, `lease_set2`, `meta_leaseset`, `offline_signature`, `router_address`, `router_identity`, `router_info`, `session_key`, `session_tag`, `signature`

---

## Requirements

- **Go Version**: 1.26.8 or later (per the `go` directive in `go.mod`)
- **I2P Specification**: 0.9.71 (page updated October 2026)
- **Dependencies**:
  - `github.com/go-i2p/crypto` - I2P cryptographic primitives
  - `github.com/go-i2p/logger` - Structured logging wrapper
  - `github.com/go-i2p/red25519` - RedDSA signatures
  - `github.com/samber/oops` - Enhanced error handling
  - `golang.org/x/crypto` - Additional cryptographic primitives
- **Test-only dependencies**:
  - `github.com/stretchr/testify` - Testing utilities
  - `go.step.sm/crypto` - Test key material

---

## Testing

Run the comprehensive test suite:

```bash
# Run all tests
go test ./...

# Run specific component tests
go test ./certificate/...
go test ./destination/...
go test ./router_info/...

# Run tests with debug logging enabled
DEBUG_I2P=debug go test ./...

# Run fuzz tests
go test -fuzz=FuzzReadCertificate ./certificate/
```

---

## License

MIT License - see [LICENSE](LICENSE) file for details.

Copyright (c) 2025 I2P For Go
