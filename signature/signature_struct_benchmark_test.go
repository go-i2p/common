package signature

import (
	"testing"
)

func BenchmarkReadSignature(b *testing.B) {
	data := make([]byte, EdDSA_SHA512_Ed25519_SIZE+100)
	for i := range data {
		data[i] = byte(i % 256)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = ReadSignature(data, SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
	}
}

func BenchmarkNewSignatureFromBytes(b *testing.B) {
	data := make([]byte, EdDSA_SHA512_Ed25519_SIZE)
	for i := range data {
		data[i] = byte(i % 256)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = NewSignatureFromBytes(data, SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
	}
}

func BenchmarkSignatureEqual(b *testing.B) {
	data1 := make([]byte, EdDSA_SHA512_Ed25519_SIZE)
	data2 := make([]byte, EdDSA_SHA512_Ed25519_SIZE)
	for i := range data1 {
		data1[i] = byte(i % 256)
		data2[i] = byte(i % 256)
	}
	sig1, _ := NewSignatureFromBytes(data1, SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
	sig2, _ := NewSignatureFromBytes(data2, SIGNATURE_TYPE_EDDSA_SHA512_ED25519)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sig1.Equal(&sig2)
	}
}

func BenchmarkSignatureBytes(b *testing.B) {
	data := make([]byte, EdDSA_SHA512_Ed25519_SIZE)
	sig, _ := NewSignatureFromBytes(data, SIGNATURE_TYPE_EDDSA_SHA512_ED25519)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sig.Bytes()
	}
}

func BenchmarkSignatureValidate(b *testing.B) {
	data := make([]byte, EdDSA_SHA512_Ed25519_SIZE)
	sig, _ := NewSignatureFromBytes(data, SIGNATURE_TYPE_EDDSA_SHA512_ED25519)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sig.Validate()
	}
}

func BenchmarkSignatureSize(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = SignatureSize(SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
	}
}
