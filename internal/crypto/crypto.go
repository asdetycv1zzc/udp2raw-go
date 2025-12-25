package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5" //nolint:gosec // md5 is required for compatibility
	crand "crypto/rand"
	"crypto/sha1" //nolint:gosec // sha1 is required for compatibility
	"crypto/sha256"
	"errors"
	"fmt"
	"hash/crc32"
	"io"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

// AuthMode describes integrity strategy.
type AuthMode string

// CipherMode describes confidentiality strategy.
type CipherMode string

const (
	AuthNone     AuthMode = "none"
	AuthMD5      AuthMode = "md5"
	AuthCRC32    AuthMode = "crc32"
	AuthSimple   AuthMode = "simple"
	AuthHMACSHA1 AuthMode = "hmac_sha1"

	CipherNone      CipherMode = "none"
	CipherAES128CBC CipherMode = "aes128cbc"
	CipherAES128CFB CipherMode = "aes128cfb"
	CipherXOR       CipherMode = "xor"
)

// Keys holds derived key material for both directions.
type Keys struct {
	CipherKey []byte
	AuthKey   []byte
	XorPad    []byte
}

// DeriveKeys mimics the legacy C++ key schedule using PBKDF2 + HKDF.
func DeriveKeys(secret string, isClient bool) (*Keys, *Keys, error) {
	salt := sha256.Sum256([]byte("udp2raw_salt1"))
	base := pbkdf2.Key([]byte(secret), salt[:16], 10000, 32, sha256.New)

	serverInfoCipher := []byte("cipher_key server-->client")
	serverInfoHMAC := []byte("hmac_key server-->client")
	clientInfoCipher := []byte("cipher_key client-->server")
	clientInfoHMAC := []byte("hmac_key client-->server")
	xorInfo := []byte("gro")

	encryptInfoCipher := serverInfoCipher
	encryptInfoHMAC := serverInfoHMAC
	decryptInfoCipher := clientInfoCipher
	decryptInfoHMAC := clientInfoHMAC
	if isClient {
		encryptInfoCipher, decryptInfoCipher = decryptInfoCipher, encryptInfoCipher
		encryptInfoHMAC, decryptInfoHMAC = decryptInfoHMAC, encryptInfoHMAC
	}

	encCipher, err := expand(base, encryptInfoCipher, 64)
	if err != nil {
		return nil, nil, err
	}
	decCipher, err := expand(base, decryptInfoCipher, 64)
	if err != nil {
		return nil, nil, err
	}
	encHMAC, err := expand(base, encryptInfoHMAC, 64)
	if err != nil {
		return nil, nil, err
	}
	decHMAC, err := expand(base, decryptInfoHMAC, 64)
	if err != nil {
		return nil, nil, err
	}
	xorPad, err := expand(base, xorInfo, 256)
	if err != nil {
		return nil, nil, err
	}

	enc := &Keys{CipherKey: encCipher[:16], AuthKey: encHMAC[:20], XorPad: xorPad}
	dec := &Keys{CipherKey: decCipher[:16], AuthKey: decHMAC[:20], XorPad: xorPad}

	return enc, dec, nil
}

func expand(base []byte, info []byte, n int) ([]byte, error) {
	reader := hkdf.New(sha256.New, base, nil, info)
	buf := make([]byte, n)
	if _, err := io.ReadFull(reader, buf); err != nil {
		return nil, fmt.Errorf("hkdf expand: %w", err)
	}
	return buf, nil
}

// Encrypt applies cipher and auth according to selected modes.
func Encrypt(plain []byte, encKeys *Keys, cipherMode CipherMode, authMode AuthMode) ([]byte, error) {
	var body []byte
	switch cipherMode {
	case CipherNone:
		body = append([]byte(nil), plain...)
	case CipherXOR:
		body = applyXOR(plain, encKeys.XorPad)
	case CipherAES128CFB:
		iv := randomIV(aes.BlockSize)
		block, err := aes.NewCipher(encKeys.CipherKey)
		if err != nil {
			return nil, err
		}
		stream := cipher.NewCFBEncrypter(block, iv)
		buf := make([]byte, len(plain))
		stream.XORKeyStream(buf, plain)
		body = append(iv, buf...)
	case CipherAES128CBC:
		iv := randomIV(aes.BlockSize)
		block, err := aes.NewCipher(encKeys.CipherKey)
		if err != nil {
			return nil, err
		}
		padded := pkcs7Pad(plain, block.BlockSize())
		buf := make([]byte, len(padded))
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(buf, padded)
		body = append(iv, buf...)
	default:
		return nil, fmt.Errorf("unsupported cipher mode %s", cipherMode)
	}

	switch authMode {
	case AuthNone:
		return body, nil
	case AuthMD5:
		h := md5.Sum(body)
		return append(body, h[:]...), nil
	case AuthCRC32:
		c := crc32.ChecksumIEEE(body)
		var out []byte
		out = append(out, body...)
		out = append(out, byte(c>>24), byte(c>>16), byte(c>>8), byte(c))
		return out, nil
	case AuthSimple:
		h1, h2 := simpleHashes(body)
		out := append(body, h1...)
		return append(out, h2...), nil
	case AuthHMACSHA1:
		mac := hmac.New(sha1.New, encKeys.AuthKey)
		mac.Write(body)
		return mac.Sum(body), nil
	default:
		return nil, fmt.Errorf("unsupported auth mode %s", authMode)
	}
}

// Decrypt reverses Encrypt and validates integrity.
func Decrypt(ciphertext []byte, decKeys *Keys, cipherMode CipherMode, authMode AuthMode) ([]byte, error) {
	var body []byte
	var err error

	switch authMode {
	case AuthNone:
		body = ciphertext
	case AuthMD5:
		if len(ciphertext) < md5.Size {
			return nil, errors.New("ciphertext too small for md5")
		}
		body, err = verifyTail(ciphertext, md5.Size, func(msg, sig []byte) bool {
			m := md5.Sum(msg)
			return hmac.Equal(sig, m[:])
		})
		if err != nil {
			return nil, err
		}
	case AuthCRC32:
		if len(ciphertext) < 4 {
			return nil, errors.New("ciphertext too small for crc32")
		}
		body, err = verifyTail(ciphertext, 4, func(msg, sig []byte) bool {
			c := crc32.ChecksumIEEE(msg)
			exp := []byte{byte(c >> 24), byte(c >> 16), byte(c >> 8), byte(c)}
			return hmac.Equal(sig, exp)
		})
		if err != nil {
			return nil, err
		}
	case AuthSimple:
		if len(ciphertext) < 8 {
			return nil, errors.New("ciphertext too small for simple auth")
		}
		body, err = verifyTail(ciphertext, 8, func(msg, sig []byte) bool {
			h1, h2 := simpleHashes(msg)
			return hmac.Equal(sig[:4], h1) && hmac.Equal(sig[4:], h2)
		})
		if err != nil {
			return nil, err
		}
	case AuthHMACSHA1:
		if len(ciphertext) < sha1.Size {
			return nil, errors.New("ciphertext too small for hmac")
		}
		body, err = verifyTail(ciphertext, sha1.Size, func(msg, sig []byte) bool {
			mac := hmac.New(sha1.New, decKeys.AuthKey)
			mac.Write(msg)
			return hmac.Equal(mac.Sum(nil), sig)
		})
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported auth mode %s", authMode)
	}

	switch cipherMode {
	case CipherNone:
		return append([]byte(nil), body...), nil
	case CipherXOR:
		return applyXOR(body, decKeys.XorPad), nil
	case CipherAES128CFB:
		if len(body) < aes.BlockSize {
			return nil, errors.New("ciphertext too small for iv")
		}
		iv := body[:aes.BlockSize]
		block, err := aes.NewCipher(decKeys.CipherKey)
		if err != nil {
			return nil, err
		}
		stream := cipher.NewCFBDecrypter(block, iv)
		plain := make([]byte, len(body)-aes.BlockSize)
		stream.XORKeyStream(plain, body[aes.BlockSize:])
		return plain, nil
	case CipherAES128CBC:
		if len(body) < aes.BlockSize {
			return nil, errors.New("ciphertext too small for iv")
		}
		iv := body[:aes.BlockSize]
		block, err := aes.NewCipher(decKeys.CipherKey)
		if err != nil {
			return nil, err
		}
		if (len(body)-aes.BlockSize)%block.BlockSize() != 0 {
			return nil, errors.New("ciphertext not full blocks")
		}
		buf := make([]byte, len(body)-aes.BlockSize)
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(buf, body[aes.BlockSize:])
		plain, err := pkcs7Unpad(buf, block.BlockSize())
		if err != nil {
			return nil, err
		}
		return plain, nil
	default:
		return nil, fmt.Errorf("unsupported cipher mode %s", cipherMode)
	}
}

func pkcs7Pad(data []byte, bs int) []byte {
	pad := bs - (len(data) % bs)
	out := make([]byte, len(data)+pad)
	copy(out, data)
	for i := 0; i < pad; i++ {
		out[len(data)+i] = byte(pad)
	}
	return out
}

func pkcs7Unpad(data []byte, bs int) ([]byte, error) {
	if len(data) == 0 || len(data)%bs != 0 {
		return nil, errors.New("invalid padding")
	}
	pad := int(data[len(data)-1])
	if pad == 0 || pad > bs || pad > len(data) {
		return nil, errors.New("invalid padding")
	}
	for i := 0; i < pad; i++ {
		if data[len(data)-1-i] != byte(pad) {
			return nil, errors.New("invalid padding")
		}
	}
	return data[:len(data)-pad], nil
}

func verifyTail(ciphertext []byte, tail int, checker func(msg, sig []byte) bool) ([]byte, error) {
	body := ciphertext[:len(ciphertext)-tail]
	sig := ciphertext[len(ciphertext)-tail:]
	if !checker(body, sig) {
		return nil, errors.New("auth failure")
	}
	return body, nil
}

func applyXOR(in []byte, pad []byte) []byte {
	out := make([]byte, len(in))
	for i := range in {
		out[i] = in[i] ^ pad[i%len(pad)]
	}
	return out
}

func simpleHashes(msg []byte) ([]byte, []byte) {
	var h1 uint32 = 5381
	var h2 uint32
	for _, c := range msg {
		h1 = ((h1 << 5) + h1) ^ uint32(c)
		h2 = uint32(c) + (h2 << 6) + (h2 << 16) - h2
	}
	return uint32ToBytes(h1), uint32ToBytes(h2)
}

func uint32ToBytes(v uint32) []byte {
	return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

func randomIV(n int) []byte {
	iv := make([]byte, n)
	if _, err := crand.Read(iv); err != nil {
		panic(err)
	}
	return iv
}
