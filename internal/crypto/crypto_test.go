package crypto

import (
	"testing"
)

func BenchmarkEncryptCBCWithHMAC(b *testing.B) {
	enc, _, err := DeriveKeys("secret", true)
	if err != nil {
		b.Fatal(err)
	}
	block, err := PrepareBlock(enc, CipherAES128CBC)
	if err != nil {
		b.Fatal(err)
	}
	payload := make([]byte, 1400)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := EncryptWithBlock(payload, enc, CipherAES128CBC, AuthHMACSHA1, block); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecryptCBCWithHMAC(b *testing.B) {
	enc, dec, err := DeriveKeys("secret", true)
	if err != nil {
		b.Fatal(err)
	}
	encBlock, err := PrepareBlock(enc, CipherAES128CBC)
	if err != nil {
		b.Fatal(err)
	}
	decBlock, err := PrepareBlock(dec, CipherAES128CBC)
	if err != nil {
		b.Fatal(err)
	}
	payload := make([]byte, 1400)
	ciphertext, err := EncryptWithBlock(payload, enc, CipherAES128CBC, AuthHMACSHA1, encBlock)
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := DecryptWithBlock(ciphertext, dec, CipherAES128CBC, AuthHMACSHA1, decBlock); err != nil {
			b.Fatal(err)
		}
	}
}
