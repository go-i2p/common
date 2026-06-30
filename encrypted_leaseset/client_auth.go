package encrypted_leaseset

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"io"

	"github.com/go-i2p/crypto/curve25519"
	"github.com/go-i2p/crypto/rand"

	"github.com/samber/oops"
	"golang.org/x/crypto/hkdf"
)

// ClientAuthConfig specifies per-client authorization when encrypting an
// EncryptedLeaseSet (server side).
//
// Exactly one authorization scheme is described, identified by AuthType:
//
//   - ENCRYPTED_LEASESET_AUTH_TYPE_DH  — populate DHClientPublicKeys with each
//     authorized client's X25519 public key (cpk_i, 32 bytes).
//   - ENCRYPTED_LEASESET_AUTH_TYPE_PSK — populate PSKClientKeys with each
//     authorized client's pre-shared key (psk_i, 32 bytes).
//
// A single random authCookie is generated per publication and encrypted to each
// authorized client; only clients that can recover authCookie can derive the
// Layer 2 key and decrypt the inner LeaseSet2.
//
// Spec: https://i2p.net/en/docs/specs/encryptedleaseset §"Per-client authorization"
type ClientAuthConfig struct {
	// AuthType selects the authorization scheme (DH or PSK).
	AuthType byte

	// DHClientPublicKeys holds each authorized client's X25519 public key
	// (cpk_i, 32 bytes). Used only when AuthType is DH.
	DHClientPublicKeys [][]byte

	// PSKClientKeys holds each authorized client's pre-shared key (psk_i, 32
	// bytes). Used only when AuthType is PSK.
	PSKClientKeys [][]byte
}

// ClientCredential supplies a single client's secret used to recover authCookie
// when decrypting an EncryptedLeaseSet (client side).
//
//   - For DH auth, set DHPrivateKey to the client's X25519 private key (csk_i, 32
//     bytes). The corresponding public key cpk_i is derived internally.
//   - For PSK auth, set PSK to the client's pre-shared key (psk_i, 32 bytes).
//
// Spec: https://i2p.net/en/docs/specs/encryptedleaseset §"Per-client authorization"
type ClientCredential struct {
	// AuthType selects the authorization scheme (DH or PSK).
	AuthType byte

	// DHPrivateKey is the client's X25519 private key (csk_i, 32 bytes). Used
	// only when AuthType is DH.
	DHPrivateKey []byte

	// PSK is the client's pre-shared key (psk_i, 32 bytes). Used only when
	// AuthType is PSK.
	PSK []byte
}

// authFlagByte encodes a high-level auth type into the Layer 1 flag byte.
//
// Bit layout (per spec §"Layer 1 (middle)"):
//   - Bit 0: 0 for everybody, 1 for per-client
//   - Bits 3-1: authentication scheme (000 = DH, 001 = PSK), only if bit 0 is set
//   - Bits 7-4: unused, set to 0
func authFlagByte(authType byte) (byte, error) {
	switch authType {
	case ENCRYPTED_LEASESET_AUTH_TYPE_NONE:
		return 0x00, nil
	case ENCRYPTED_LEASESET_AUTH_TYPE_DH:
		return ENCRYPTED_LEASESET_AUTH_FLAG_PERCLIENT |
			(ENCRYPTED_LEASESET_AUTH_SCHEME_DH << ENCRYPTED_LEASESET_AUTH_SCHEME_SHIFT), nil
	case ENCRYPTED_LEASESET_AUTH_TYPE_PSK:
		return ENCRYPTED_LEASESET_AUTH_FLAG_PERCLIENT |
			(ENCRYPTED_LEASESET_AUTH_SCHEME_PSK << ENCRYPTED_LEASESET_AUTH_SCHEME_SHIFT), nil
	default:
		return 0, oops.Code("invalid_auth_type").
			With("auth_type", authType).
			Errorf("unsupported per-client auth type %d", authType)
	}
}

// parseAuthFlag decodes a Layer 1 flag byte into a high-level auth type.
// Returns ENCRYPTED_LEASESET_AUTH_TYPE_NONE when the per-client bit is clear.
func parseAuthFlag(flag byte) (byte, error) {
	if flag&ENCRYPTED_LEASESET_AUTH_FLAG_PERCLIENT == 0 {
		return ENCRYPTED_LEASESET_AUTH_TYPE_NONE, nil
	}
	scheme := (flag >> ENCRYPTED_LEASESET_AUTH_SCHEME_SHIFT) & ENCRYPTED_LEASESET_AUTH_SCHEME_MASK
	switch scheme {
	case ENCRYPTED_LEASESET_AUTH_SCHEME_DH:
		return ENCRYPTED_LEASESET_AUTH_TYPE_DH, nil
	case ENCRYPTED_LEASESET_AUTH_SCHEME_PSK:
		return ENCRYPTED_LEASESET_AUTH_TYPE_PSK, nil
	default:
		return 0, oops.Code("unknown_auth_scheme").
			With("scheme", scheme).
			Errorf("unknown per-client auth scheme %d in Layer 1 flag byte", scheme)
	}
}

// validateClientAuthConfig validates a server-side ClientAuthConfig.
func validateClientAuthConfig(cfg *ClientAuthConfig) error {
	switch cfg.AuthType {
	case ENCRYPTED_LEASESET_AUTH_TYPE_DH:
		if len(cfg.DHClientPublicKeys) == 0 {
			return oops.Code("no_clients").Errorf("DH client auth requires at least one client public key")
		}
		for i, pk := range cfg.DHClientPublicKeys {
			if len(pk) != ENCRYPTED_LEASESET_X25519_KEY_SIZE {
				return oops.Code("invalid_client_key_size").
					With("index", i).With("size", len(pk)).
					Errorf("DH client public key %d has size %d, expected %d",
						i, len(pk), ENCRYPTED_LEASESET_X25519_KEY_SIZE)
			}
		}
	case ENCRYPTED_LEASESET_AUTH_TYPE_PSK:
		if len(cfg.PSKClientKeys) == 0 {
			return oops.Code("no_clients").Errorf("PSK client auth requires at least one pre-shared key")
		}
		for i, psk := range cfg.PSKClientKeys {
			if len(psk) != ENCRYPTED_LEASESET_PSK_SIZE {
				return oops.Code("invalid_psk_size").
					With("index", i).With("size", len(psk)).
					Errorf("PSK client key %d has size %d, expected %d",
						i, len(psk), ENCRYPTED_LEASESET_PSK_SIZE)
			}
		}
	default:
		return oops.Code("invalid_auth_type").
			With("auth_type", cfg.AuthType).
			Errorf("unsupported per-client auth type %d", cfg.AuthType)
	}
	return nil
}

// validateClientCredential validates a client-side ClientCredential.
func validateClientCredential(cred *ClientCredential) error {
	switch cred.AuthType {
	case ENCRYPTED_LEASESET_AUTH_TYPE_DH:
		if len(cred.DHPrivateKey) != ENCRYPTED_LEASESET_X25519_KEY_SIZE {
			return oops.Code("invalid_client_key_size").
				With("size", len(cred.DHPrivateKey)).
				Errorf("DH client private key has size %d, expected %d",
					len(cred.DHPrivateKey), ENCRYPTED_LEASESET_X25519_KEY_SIZE)
		}
	case ENCRYPTED_LEASESET_AUTH_TYPE_PSK:
		if len(cred.PSK) != ENCRYPTED_LEASESET_PSK_SIZE {
			return oops.Code("invalid_psk_size").
				With("size", len(cred.PSK)).
				Errorf("PSK client key has size %d, expected %d",
					len(cred.PSK), ENCRYPTED_LEASESET_PSK_SIZE)
		}
	default:
		return oops.Code("invalid_auth_type").
			With("auth_type", cred.AuthType).
			Errorf("unsupported per-client auth type %d", cred.AuthType)
	}
	return nil
}

// x25519DerivePublic returns the X25519 public key for the given 32-byte private
// key using the go-i2p/crypto curve25519 primitive.
func x25519DerivePublic(priv []byte) ([]byte, error) {
	sk, err := curve25519.NewCurve25519PrivateKey(priv)
	if err != nil {
		return nil, oops.Errorf("invalid X25519 private key: %w", err)
	}
	pub, err := sk.Public()
	if err != nil {
		return nil, oops.Errorf("X25519 public key derivation failed: %w", err)
	}
	return pub.Bytes(), nil
}

// x25519DH computes the X25519 shared secret between priv and pub using the
// go-i2p/crypto curve25519 primitive.
func x25519DH(priv, pub []byte) ([]byte, error) {
	shared, err := curve25519.SharedKey(priv, pub)
	if err != nil {
		return nil, oops.Errorf("X25519 shared-secret computation failed: %w", err)
	}
	return shared, nil
}

// clientAuthKeys holds the per-client key material derived via HKDF.
type clientAuthKeys struct {
	key [32]byte
	iv  [12]byte
	id  [8]byte
}

// deriveClientAuthKeys runs HKDF-SHA256 to produce the 52-byte per-client output
// keying material and splits it into clientKey(32) || clientIV(12) || clientID(8).
//
// Per spec:
//
//	okm = HKDF(salt, authInput, info, 52)
//	clientKey_i = okm[0:32]; clientIV_i = okm[32:44]; clientID_i = okm[44:52]
func deriveClientAuthKeys(salt, authInput []byte, info string) (clientAuthKeys, error) {
	var out clientAuthKeys
	reader := hkdf.New(sha256.New, authInput, salt, []byte(info))
	okm := make([]byte, ENCRYPTED_LEASESET_AUTH_OKM_SIZE)
	if _, err := io.ReadFull(reader, okm); err != nil {
		return out, oops.Errorf("per-client HKDF derivation failed: %w", err)
	}
	copy(out.key[:], okm[0:32])
	copy(out.iv[:], okm[32:44])
	copy(out.id[:], okm[44:52])
	return out, nil
}

// buildAuthInputDH assembles the DH authInput:
// sharedSecret || cpk || subcredential || publishedTimestamp.
func buildAuthInputDH(sharedSecret, cpk []byte, subcred [32]byte, published uint32) []byte {
	buf := make([]byte, 0, len(sharedSecret)+len(cpk)+32+4)
	buf = append(buf, sharedSecret...)
	buf = append(buf, cpk...)
	buf = append(buf, subcred[:]...)
	buf = appendUint32(buf, published)
	return buf
}

// buildAuthInputPSK assembles the PSK authInput:
// psk || subcredential || publishedTimestamp.
func buildAuthInputPSK(psk []byte, subcred [32]byte, published uint32) []byte {
	buf := make([]byte, 0, len(psk)+32+4)
	buf = append(buf, psk...)
	buf = append(buf, subcred[:]...)
	buf = appendUint32(buf, published)
	return buf
}

// appendUint32 appends a big-endian uint32 to b.
func appendUint32(b []byte, v uint32) []byte {
	var tmp [4]byte
	binary.BigEndian.PutUint32(tmp[:], v)
	return append(b, tmp[:]...)
}

// buildClientAuthBlock constructs the Layer 1 per-client authorization block and
// returns it along with the freshly generated authCookie that keys Layer 2.
//
// The returned block layout depends on cfg.AuthType:
//
//	DH:  epk(32)     || clients(2) || [clientID(8) || clientCookie(32)]*
//	PSK: authSalt(32)|| clients(2) || [clientID(8) || clientCookie(32)]*
func buildClientAuthBlock(cfg *ClientAuthConfig, subcred [32]byte, published uint32) ([]byte, [32]byte, error) {
	var authCookie [32]byte
	if _, err := rand.Read(authCookie[:]); err != nil {
		return nil, authCookie, oops.Errorf("authCookie generation failed: %w", err)
	}

	switch cfg.AuthType {
	case ENCRYPTED_LEASESET_AUTH_TYPE_DH:
		block, err := buildDHAuthBlock(cfg.DHClientPublicKeys, authCookie, subcred, published)
		return block, authCookie, err
	case ENCRYPTED_LEASESET_AUTH_TYPE_PSK:
		block, err := buildPSKAuthBlock(cfg.PSKClientKeys, authCookie, subcred, published)
		return block, authCookie, err
	default:
		return nil, authCookie, oops.Code("invalid_auth_type").
			With("auth_type", cfg.AuthType).
			Errorf("unsupported per-client auth type %d", cfg.AuthType)
	}
}

// buildDHAuthBlock encrypts authCookie to each client's X25519 public key.
func buildDHAuthBlock(clientPubKeys [][]byte, authCookie, subcred [32]byte, published uint32) ([]byte, error) {
	esk := make([]byte, ENCRYPTED_LEASESET_X25519_KEY_SIZE)
	if _, err := rand.Read(esk); err != nil {
		return nil, oops.Errorf("ephemeral key generation failed: %w", err)
	}
	epk, err := x25519DerivePublic(esk)
	if err != nil {
		return nil, err
	}

	entries := make([]byte, 0, len(clientPubKeys)*ENCRYPTED_LEASESET_AUTH_CLIENT_SIZE)
	for i, cpk := range clientPubKeys {
		shared, err := x25519DH(esk, cpk)
		if err != nil {
			return nil, oops.Errorf("DH with client %d failed: %w", i, err)
		}
		authInput := buildAuthInputDH(shared, cpk, subcred, published)
		keys, err := deriveClientAuthKeys(epk, authInput, ELS2_DH_AUTH_INFO)
		if err != nil {
			return nil, err
		}
		entry, err := encryptAuthClientEntry(keys, authCookie)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry...)
	}

	return assembleAuthBlock(epk, len(clientPubKeys), entries), nil
}

// buildPSKAuthBlock encrypts authCookie to each client's pre-shared key.
func buildPSKAuthBlock(psks [][]byte, authCookie, subcred [32]byte, published uint32) ([]byte, error) {
	authSalt := make([]byte, ENCRYPTED_LEASESET_AUTH_SALT_SIZE)
	if _, err := rand.Read(authSalt); err != nil {
		return nil, oops.Errorf("authSalt generation failed: %w", err)
	}

	entries := make([]byte, 0, len(psks)*ENCRYPTED_LEASESET_AUTH_CLIENT_SIZE)
	for _, psk := range psks {
		authInput := buildAuthInputPSK(psk, subcred, published)
		keys, err := deriveClientAuthKeys(authSalt, authInput, ELS2_PSK_AUTH_INFO)
		if err != nil {
			return nil, err
		}
		entry, err := encryptAuthClientEntry(keys, authCookie)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry...)
	}

	return assembleAuthBlock(authSalt, len(psks), entries), nil
}

// encryptAuthClientEntry builds a single authClient entry:
// clientID(8) || ENCRYPT(clientKey, clientIV, authCookie)(32).
func encryptAuthClientEntry(keys clientAuthKeys, authCookie [32]byte) ([]byte, error) {
	clientCookie, err := chacha20Crypt(keys.key, keys.iv, authCookie[:])
	if err != nil {
		return nil, oops.Errorf("authCookie encryption failed: %w", err)
	}
	entry := make([]byte, 0, ENCRYPTED_LEASESET_AUTH_CLIENT_SIZE)
	entry = append(entry, keys.id[:]...)
	entry = append(entry, clientCookie...)
	return entry, nil
}

// assembleAuthBlock concatenates the scheme-specific header (epk or authSalt),
// the 2-byte client count, and the serialized authClient entries.
func assembleAuthBlock(header []byte, numClients int, entries []byte) []byte {
	block := make([]byte, 0, len(header)+ENCRYPTED_LEASESET_AUTH_CLIENT_COUNT_SIZE+len(entries))
	block = append(block, header...)
	var countBuf [2]byte
	binary.BigEndian.PutUint16(countBuf[:], uint16(numClients))
	block = append(block, countBuf[:]...)
	block = append(block, entries...)
	return block
}

// recoverAuthCookie parses the Layer 1 per-client auth block, recovers authCookie
// using the supplied credential, and returns authCookie plus the remaining bytes
// (the inner ciphertext that follows the auth block).
//
// authType must already have been decoded from the Layer 1 flag byte and must
// match cred.AuthType.
func recoverAuthCookie(authType byte, data []byte, cred *ClientCredential, subcred [32]byte, published uint32) ([]byte, []byte, error) {
	if cred == nil {
		return nil, nil, oops.Code("missing_credential").
			Errorf("per-client auth type %d requires a ClientCredential", authType)
	}
	if cred.AuthType != authType {
		return nil, nil, oops.Code("auth_type_mismatch").
			With("expected", authType).With("got", cred.AuthType).
			Errorf("credential auth type %d does not match LeaseSet auth type %d", cred.AuthType, authType)
	}

	switch authType {
	case ENCRYPTED_LEASESET_AUTH_TYPE_DH:
		return recoverAuthCookieDH(data, cred, subcred, published)
	case ENCRYPTED_LEASESET_AUTH_TYPE_PSK:
		return recoverAuthCookiePSK(data, cred, subcred, published)
	default:
		return nil, nil, oops.Code("invalid_auth_type").
			With("auth_type", authType).
			Errorf("unsupported per-client auth type %d", authType)
	}
}

// recoverAuthCookieDH recovers authCookie from a DH auth block.
func recoverAuthCookieDH(data []byte, cred *ClientCredential, subcred [32]byte, published uint32) ([]byte, []byte, error) {
	epk, entries, rest, err := parseAuthBlock(data, ENCRYPTED_LEASESET_X25519_KEY_SIZE)
	if err != nil {
		return nil, nil, err
	}

	cpk, err := x25519DerivePublic(cred.DHPrivateKey)
	if err != nil {
		return nil, nil, err
	}
	shared, err := x25519DH(cred.DHPrivateKey, epk)
	if err != nil {
		return nil, nil, err
	}
	authInput := buildAuthInputDH(shared, cpk, subcred, published)
	keys, err := deriveClientAuthKeys(epk, authInput, ELS2_DH_AUTH_INFO)
	if err != nil {
		return nil, nil, err
	}

	authCookie, err := findAndDecryptCookie(entries, keys)
	if err != nil {
		return nil, nil, err
	}
	return authCookie, rest, nil
}

// recoverAuthCookiePSK recovers authCookie from a PSK auth block.
func recoverAuthCookiePSK(data []byte, cred *ClientCredential, subcred [32]byte, published uint32) ([]byte, []byte, error) {
	authSalt, entries, rest, err := parseAuthBlock(data, ENCRYPTED_LEASESET_AUTH_SALT_SIZE)
	if err != nil {
		return nil, nil, err
	}

	authInput := buildAuthInputPSK(cred.PSK, subcred, published)
	keys, err := deriveClientAuthKeys(authSalt, authInput, ELS2_PSK_AUTH_INFO)
	if err != nil {
		return nil, nil, err
	}

	authCookie, err := findAndDecryptCookie(entries, keys)
	if err != nil {
		return nil, nil, err
	}
	return authCookie, rest, nil
}

// parseAuthBlock parses the scheme header (epk or authSalt, headerSize bytes),
// the 2-byte client count, and that many 40-byte authClient entries. It returns
// the header, the raw entries slice, and any remaining bytes (inner ciphertext).
func parseAuthBlock(data []byte, headerSize int) (header, entries, rest []byte, err error) {
	minLen := headerSize + ENCRYPTED_LEASESET_AUTH_CLIENT_COUNT_SIZE
	if len(data) < minLen {
		return nil, nil, nil, oops.Code("auth_block_too_short").
			With("got", len(data)).With("need", minLen).
			Errorf("Layer 1 auth block too short: got %d bytes, need at least %d", len(data), minLen)
	}
	header = data[:headerSize]
	countOff := headerSize
	numClients := int(binary.BigEndian.Uint16(data[countOff : countOff+ENCRYPTED_LEASESET_AUTH_CLIENT_COUNT_SIZE]))
	entriesOff := countOff + ENCRYPTED_LEASESET_AUTH_CLIENT_COUNT_SIZE
	entriesLen := numClients * ENCRYPTED_LEASESET_AUTH_CLIENT_SIZE
	if len(data) < entriesOff+entriesLen {
		return nil, nil, nil, oops.Code("auth_block_truncated").
			With("clients", numClients).With("available", len(data)-entriesOff).
			Errorf("Layer 1 auth block truncated: %d clients need %d bytes, have %d",
				numClients, entriesLen, len(data)-entriesOff)
	}
	entries = data[entriesOff : entriesOff+entriesLen]
	rest = data[entriesOff+entriesLen:]
	return header, entries, rest, nil
}

// findAndDecryptCookie scans authClient entries for one whose clientID matches the
// derived keys, then decrypts its cookie to recover authCookie.
func findAndDecryptCookie(entries []byte, keys clientAuthKeys) ([]byte, error) {
	for off := 0; off+ENCRYPTED_LEASESET_AUTH_CLIENT_SIZE <= len(entries); off += ENCRYPTED_LEASESET_AUTH_CLIENT_SIZE {
		clientID := entries[off : off+ENCRYPTED_LEASESET_CLIENT_ID_SIZE]
		if subtle.ConstantTimeCompare(clientID, keys.id[:]) != 1 {
			continue
		}
		cookieOff := off + ENCRYPTED_LEASESET_CLIENT_ID_SIZE
		clientCookie := entries[cookieOff : cookieOff+ENCRYPTED_LEASESET_CLIENT_COOKIE_SIZE]
		authCookie, err := chacha20Crypt(keys.key, keys.iv, clientCookie)
		if err != nil {
			return nil, oops.Errorf("authCookie decryption failed: %w", err)
		}
		return authCookie, nil
	}
	return nil, oops.Code("client_not_authorized").
		Errorf("no matching authClient entry: this client is not authorized")
}
