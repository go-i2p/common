# session_tag
--
    import "github.com/go-i2p/common/session_tag"

![session_tag.svg](session_tag.svg)

Package session_tag implements the I2P SessionTag common data structure

Package session_tag implements the I2P SessionTag common data structure

Package session_tag implements the I2P SessionTag common data structure

## Usage

```go
const SessionTagSize = 32
```
SessionTagSize is the size of an I2P SessionTag in bytes. According to the I2P
specification, a SessionTag is always 32 bytes.

https://geti2p.net/spec/common-structures#session-tag

#### type SessionTag

```go
type SessionTag struct {
}
```

SessionTag is the representation of an I2P SessionTag. A SessionTag is a 32-byte
random number used in I2P for session identification.

https://geti2p.net/spec/common-structures#session-tag

#### func  NewSessionTag

```go
func NewSessionTag(data []byte) (session_tag *SessionTag, remainder []byte, err error)
```
NewSessionTag creates a new *SessionTag from []byte using ReadSessionTag.
Returns a pointer to SessionTag unlike ReadSessionTag.

#### func  NewSessionTagFromArray

```go
func NewSessionTagFromArray(data [SessionTagSize]byte) SessionTag
```
NewSessionTagFromArray creates a new SessionTag from a byte array.

#### func  NewSessionTagFromBytes

```go
func NewSessionTagFromBytes(data []byte) (SessionTag, error)
```
NewSessionTagFromBytes creates a new SessionTag from a byte slice. The input
must be exactly SessionTagSize bytes long.

#### func  ReadSessionTag

```go
func ReadSessionTag(bytes []byte) (info SessionTag, remainder []byte, err error)
```
ReadSessionTag returns SessionTag from a []byte. The remaining bytes after the
specified length are also returned. Returns a list of errors that occurred
during parsing.

#### func (SessionTag) Array

```go
func (st SessionTag) Array() [SessionTagSize]byte
```
Array returns the SessionTag as a byte array. This method provides access to the
underlying fixed-size array.

#### func (SessionTag) Bytes

```go
func (st SessionTag) Bytes() []byte
```
Bytes returns the SessionTag as a byte slice. This method provides compatibility
with code that expects []byte.

#### func (SessionTag) Equal

```go
func (st SessionTag) Equal(other SessionTag) bool
```
Equal checks if two SessionTags are equal.

#### func (*SessionTag) SetBytes

```go
func (st *SessionTag) SetBytes(data []byte) error
```
SetBytes sets the SessionTag value from a byte slice. The input must be exactly
SessionTagSize bytes long.

#### func (SessionTag) String

```go
func (st SessionTag) String() string
```
String returns a hex representation of the SessionTag for debugging.



session_tag 

github.com/go-i2p/common/session_tag

[go-i2p template file](/template.md)
