package router_info

import (
	"bytes"
	"encoding/base64"
	"testing"

	i2pbase64 "github.com/go-i2p/common/base64"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// realRouterInfoB64 is a RouterInfo written to disk by a real I2P router
// (router.version=0.9.68) in the netDb wire format, i.e. exactly what i2pd and
// the Java router persist as routerInfo-<hash>.dat. It is embedded verbatim so
// the regression test is deterministic and does not depend on a local
// ~/.i2pd/netDb or ~/.i2p/netDb being present.
//
// The record uses the spec layout: a self-delimiting RouterIdentity at offset 0,
// then published(8), then addressesCount(1), then the addresses, peer_size(1),
// the options mapping, and the signature. The 32-byte identHash is the netDb
// *filename* (the database key, sha256 of the RouterIdentity) and is NOT part of
// the record bytes.
const realRouterInfoB64 = "+AdW/pSMxM0fnAn/lOQ4dWy7/X0Q88YuaIYi2b/ZtFjoTBZ7j+0YUja5tjg9NBw9wGhZoBfS6e19nVCGTA0arehMFnuP7RhSNrm2OD00HD3AaFmgF9Lp7X2dUIZMDRqt6EwWe4/tGFI2ubY4PTQcPcBoWaAX0untfZ1QhkwNGq3oTBZ7j+0YUja5tjg9NBw9wGhZoBfS6e19nVCGTA0arehMFnuP7RhSNrm2OD00HD3AaFmgF9Lp7X2dUIZMDRqt6EwWe4/tGFI2ubY4PTQcPcBoWaAX0untfZ1QhkwNGq3oTBZ7j+0YUja5tjg9NBw9wGhZoBfS6e19nVCGTA0arehMFnuP7RhSNrm2OD00HD3AaFmgF9Lp7X2dUIZMDRqt6EwWe4/tGFI2ubY4PTQcPcBoWaAX0untfZ1QhkwNGq3oTBZ7j+0YUja5tjg9NBw9wGhZoBfS6e19nVCGTA0araaCem9F6+W8eHRy38cpivFvluwH8U24SawZlQ3/yoFQBQAEAAcABAAAAaFSV5E9AgMAAAAAAAAAAAVOVENQMgB1BGhvc3Q9DDY2LjIyOC4wLjIyNzsBaT0YOG1vczVVWVpmTE5EcGszNUlxUDBzQT09OwRwb3J0PQUxOTExNDsBcz0sSFhMNnUtMEZHRWFNOXNGOXU4eWhzU3pqR1hQZ0luUk1lSmVLOUQ1cG1TMD07AXY9ATI7CAAAAAAAAAAABFNTVTIAkwRjYXBzPQJCQzsEaG9zdD0MNjYuMjI4LjAuMjI3OwFpPSxoOG1pfjNWRzRmYktia1NvRU1KQTFvdWM0SzdzRS0wd2pVcmZUS0xyVVFVPTsEcG9ydD0FMTkxMTQ7AXM9LFBqZUlnU3E2ZE5OQWNVT0xnbktHY1ZTeGVVSkRwWVR6Y3lvcVpCd3BrRlk9OwF2PQEyOwAALARjYXBzPQJMUjsFbmV0SWQ9ATI7DnJvdXRlci52ZXJzaW9uPQYwLjkuNjg7RmIp6JbkYgJ8nYwTgi9teMrRHHvKaJWecaEZp4jHBmD7IbvH7CuRvh27YQ+8AXTx+q5W78pAIUMA0Z/NV8aHAQ=="

// realRouterInfoFilename is the netDb filename (without the "routerInfo-" prefix
// or ".dat" suffix) for realRouterInfoB64. It is the I2P-base64 of the SHA-256
// of the contained RouterIdentity, and is the value the parsed IdentHash must
// match.
const realRouterInfoFilename = "-b~TLVngucqcvEiMjcHa8kow-H66Or87~QNcbxgowOY="

// TestReadRouterInfoRealFile is a regression test for parsing a RouterInfo that
// was written by a real I2P router (i2pd / Java) rather than by go-i2p itself.
//
// It guards against a misaligned wire-format parse: if the leading fields were
// read in the wrong order (e.g. treating the 32-byte identHash as the identity,
// or expecting a 2-byte routerIdentityLength that the spec does not define), the
// identity would decode to garbage, published would be wrong, and the address
// count would read 0 — which is what caused every peer to be classified
// unreachable and tunnel building to fail.
//
// The assertions below pin the three properties that the bug report requires:
//   - the record parses cleanly with no leftover bytes,
//   - the address count is non-zero (the record really carries addresses),
//   - the computed IdentHash equals the netDb filename (the record's own key).
//
// It additionally asserts byte-for-byte round-tripping, since the structure is
// signed and must re-serialize exactly as received.
func TestReadRouterInfoRealFile(t *testing.T) {
	data, err := base64.StdEncoding.DecodeString(realRouterInfoB64)
	require.NoError(t, err, "embedded fixture must be valid base64")
	require.NotEmpty(t, data)

	info, remainder, err := ReadRouterInfo(data)
	require.NoError(t, err, "real i2pd/Java-written RouterInfo must parse")
	require.Empty(t, remainder, "parser must consume the whole record")

	// The record must expose its addresses, not a zero count.
	assert.Greater(t, info.RouterAddressCount(), 0,
		"real RouterInfo must parse to a non-zero address count")
	assert.Equal(t, 2, info.RouterAddressCount(),
		"this fixture carries exactly two RouterAddresses (NTCP2 + SSU)")
	assert.Len(t, info.RouterAddresses(), info.RouterAddressCount(),
		"parsed address slice must match the declared count")

	// The published date must be a real timestamp, not the zero value that a
	// misaligned parse would produce.
	require.NotNil(t, info.Published())
	assert.False(t, info.Published().IsZero(),
		"published date must decode to a real timestamp")

	// The computed IdentHash must equal the netDb filename (the record's key).
	// base64.EncodeToString uses I2P's filename alphabet (+ -> '-', / -> '~'),
	// which is exactly how i2pd and Java name routerInfo-<hash>.dat files.
	identHash, err := info.IdentHash()
	require.NoError(t, err, "IdentHash must be computable from the parsed identity")
	assert.Equal(t, realRouterInfoFilename, i2pbase64.EncodeToString(identHash[:]),
		"IdentHash must match the routerInfo-<hash>.dat filename")

	// The record is signed and must round-trip byte-for-byte so that the
	// signature stays valid on re-publish.
	reSerialized, err := info.Bytes()
	require.NoError(t, err, "parsed RouterInfo must re-serialize")
	assert.True(t, bytes.Equal(reSerialized, data),
		"real RouterInfo must round-trip byte-for-byte (in=%d out=%d)", len(data), len(reSerialized))
}
