# router_identity
--
    import "github.com/go-i2p/common/router_identity"

![router_identity.svg](router_identity.svg)

Package router_identity implements the I2P RouterIdentity common data structure

Package router_identity implements the I2P RouterIdentity common data structure

Package router_identity implements the I2P RouterIdentity common data structure

## Usage

#### type RouterIdentity

```go
type RouterIdentity struct {
	*keys_and_cert.KeysAndCert
}
```

RouterIdentity is the represenation of an I2P RouterIdentity. Moved from:
router_identity.go

https://geti2p.net/spec/common-structures#routeridentity

#### func  NewRouterIdentity

```go
func NewRouterIdentity(publicKey types.RecievingPublicKey, signingPublicKey types.SigningPublicKey, cert certificate.Certificate, padding []byte) (*RouterIdentity, error)
```
NewRouterIdentity creates a new RouterIdentity with the specified parameters.
Moved from: router_identity.go

#### func  ReadRouterIdentity

```go
func ReadRouterIdentity(data []byte) (router_identity *RouterIdentity, remainder []byte, err error)
```
ReadRouterIdentity returns RouterIdentity from a []byte. The remaining bytes
after the specified length are also returned. Returns a list of errors that
occurred during parsing. Moved from: router_identity.go

#### func (*RouterIdentity) AsDestination

```go
func (router_identity *RouterIdentity) AsDestination() destination.Destination
```
AsDestination converts the RouterIdentity to a Destination. Moved from:
router_identity.go



router_identity 

github.com/go-i2p/common/router_identity

[go-i2p template file](/template.md)
