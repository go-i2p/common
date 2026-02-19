package keys_and_cert

// Shared test constants for the keys_and_cert package.

// testKeyCertBytesP256ElGamal is a KEY certificate payload: signing=P256(1), crypto=ElGamal(0).
var testKeyCertBytesP256ElGamal = []byte{0x05, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00}

// testKeyCertBytesEd25519ElGamal is a KEY certificate payload: signing=Ed25519(7), crypto=ElGamal(0).
var testKeyCertBytesEd25519ElGamal = []byte{0x05, 0x00, 0x04, 0x00, 0x07, 0x00, 0x00}

// testKeyCertBytesEd25519X25519 is a KEY certificate payload: signing=Ed25519(7), crypto=X25519(4).
var testKeyCertBytesEd25519X25519 = []byte{0x05, 0x00, 0x04, 0x00, 0x07, 0x00, 0x04}

// testNullCertBytes is a NULL certificate: type=0, length=0.
var testNullCertBytes = []byte{0x00, 0x00, 0x00}
