# go-i2p/common

A comprehensive Go library implementing I2P (Invisible Internet Project) network protocol common data structures and utilities. This library provides type-safe implementations of the I2P specification common structures, factored out from the main I2P router to enable reusable components for parsing, encoding, and manipulating I2P network data.

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
    
    // Calculate padding size
    paddingSize := keys_and_cert.KEYS_AND_CERT_DATA_SIZE - 
        (sizes.CryptoPublicKeySize + sizes.SigningPublicKeySize)
    
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
    // Build a key certificate using fluent interface
    cert, err := certificate.NewCertificateBuilder().
        WithKeyTypes(certificate.KEYCERT_SIGN_ED25519, certificate.KEYCERT_CRYPTO_X25519).
        Build()
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        return
    }
    
    // Or build a certificate with custom payload
    customPayload := []byte{0x01, 0x02, 0x03, 0x04}
    cert, err = certificate.NewCertificateBuilder().
        WithType(certificate.CERT_SIGNED).
        WithPayload(customPayload).
        Build()
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
    data := []byte{0x00, 0x00, 0x02, 0xff, 0xff}
    cert, remainder, err := certificate.ReadCertificate(data)
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        return
    }
    
    fmt.Printf("Certificate type: %d\n", cert.Type())
    fmt.Printf("Certificate length: %d\n", cert.Length())
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
    
    // Generate I2P addresses
    base32Address := dest.Base32Address()
    base64Address := dest.Base64()
    
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
    
    // Access router information
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

## Requirements

- **Go Version**: 1.24.2 or later
- **I2P Specification**: 0.9.67 (June 2025)
- **Dependencies**:
  - `github.com/go-i2p/go-i2p` - Core I2P library
  - `github.com/go-i2p/logger` - Structured logging wrapper
  - `github.com/samber/oops` - Enhanced error handling
  - `github.com/sirupsen/logrus` - Logging framework
  - `github.com/stretchr/testify` - Testing utilities

---

## Testing

Run the comprehensive test suite:

```bash
# Run all tests
make test

# Run specific component tests
go test ./certificate/...
go test ./destination/...
go test ./router_info/...

# Run fuzz tests
go test -fuzz=FuzzCertificate ./certificate/
```

---

## License

MIT License - see [LICENSE](LICENSE) file for details.

Copyright (c) 2025 I2P For Go
