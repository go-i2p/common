package signature

// makeSignatureData creates a byte slice of the given length filled with a pattern.
func makeSignatureData(length int) []byte {
	data := make([]byte, length)
	for i := range data {
		data[i] = byte((i * 37) ^ 0xAB)
	}
	return data
}

// supportedSigTypes returns all supported signature type/size pairs for table-driven tests.
func supportedSigTypes() []struct {
	Name    string
	SigType int
	Size    int
} {
	return []struct {
		Name    string
		SigType int
		Size    int
	}{
		{"DSA_SHA1", SIGNATURE_TYPE_DSA_SHA1, DSA_SHA1_SIZE},
		{"ECDSA_SHA256_P256", SIGNATURE_TYPE_ECDSA_SHA256_P256, ECDSA_SHA256_P256_SIZE},
		{"ECDSA_SHA384_P384", SIGNATURE_TYPE_ECDSA_SHA384_P384, ECDSA_SHA384_P384_SIZE},
		{"ECDSA_SHA512_P521", SIGNATURE_TYPE_ECDSA_SHA512_P521, ECDSA_SHA512_P521_SIZE},
		{"RSA_SHA256_2048", SIGNATURE_TYPE_RSA_SHA256_2048, RSA_SHA256_2048_SIZE},
		{"RSA_SHA384_3072", SIGNATURE_TYPE_RSA_SHA384_3072, RSA_SHA384_3072_SIZE},
		{"RSA_SHA512_4096", SIGNATURE_TYPE_RSA_SHA512_4096, RSA_SHA512_4096_SIZE},
		{"EdDSA_SHA512_Ed25519", SIGNATURE_TYPE_EDDSA_SHA512_ED25519, EdDSA_SHA512_Ed25519_SIZE},
		{"EdDSA_SHA512_Ed25519ph", SIGNATURE_TYPE_EDDSA_SHA512_ED25519PH, EdDSA_SHA512_Ed25519ph_SIZE},
		{"RedDSA_SHA512_Ed25519", SIGNATURE_TYPE_REDDSA_SHA512_ED25519, RedDSA_SHA512_Ed25519_SIZE},
	}
}
