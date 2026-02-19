package key_certificate

// Common raw key certificate byte sequences used across tests.
// Format: [cert_type=0x05, length_hi, length_lo, signing_type_hi, signing_type_lo, crypto_type_hi, crypto_type_lo]
var (
	// testKeyCertBytesEd25519X25519 is a valid Ed25519/X25519 key certificate (signing=7, crypto=4).
	testKeyCertBytesEd25519X25519 = []byte{0x05, 0x00, 0x04, 0x00, 0x07, 0x00, 0x04}

	// testKeyCertBytesDSAElGamal is a valid DSA-SHA1/ElGamal key certificate (signing=0, crypto=0).
	testKeyCertBytesDSAElGamal = []byte{0x05, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00}

	// testKeyCertBytesP521Signing is a valid P521 signing key certificate (signing=3, crypto=7 MLKEM1024).
	testKeyCertBytesP521Signing = []byte{0x05, 0x00, 0x04, 0x00, 0x03, 0x00, 0x07}

	// testKeyCertBytesP256P256 is a valid P256/P256 key certificate (signing=1, crypto=1).
	testKeyCertBytesP256P256 = []byte{0x05, 0x00, 0x04, 0x00, 0x01, 0x00, 0x01}

	// testKeyCertBytesP384P384 is a valid P384/P384 key certificate (signing=2, crypto=2).
	testKeyCertBytesP384P384 = []byte{0x05, 0x00, 0x04, 0x00, 0x02, 0x00, 0x02}

	// testKeyCertBytesWithTrailing is Ed25519/X25519 followed by 3 trailing bytes.
	testKeyCertBytesWithTrailing = []byte{0x05, 0x00, 0x04, 0x00, 0x07, 0x00, 0x04, 0xAA, 0xBB, 0xCC}

	// testKeyCertBytesShortPayload is a key certificate with only 1-byte payload (too short for key types).
	testKeyCertBytesShortPayload = []byte{0x05, 0x00, 0x01, 0x00}

	// testKeyCertBytesShortCert is a truncated certificate (only 3 bytes, missing crypto type field).
	testKeyCertBytesShortCert = []byte{0x05, 0x00, 0x02}

	// testUnknownTypeBytes is a 2-byte big-endian encoding of type 1000 (unknown).
	testUnknownTypeBytes = []byte{0x03, 0xe8}

	// testAllSigningTypes lists all spec-defined signing key types for iteration in tests.
	testAllSigningTypes = []int{
		KEYCERT_SIGN_DSA_SHA1,
		KEYCERT_SIGN_P256,
		KEYCERT_SIGN_P384,
		KEYCERT_SIGN_P521,
		KEYCERT_SIGN_RSA2048,
		KEYCERT_SIGN_RSA3072,
		KEYCERT_SIGN_RSA4096,
		KEYCERT_SIGN_ED25519,
		KEYCERT_SIGN_ED25519PH,
		KEYCERT_SIGN_REDDSA_ED25519,
	}
)
