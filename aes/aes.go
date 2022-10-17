package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"strings"
)

// NewEncryptionKey generates a random 256-bit key for Encrypt() and
// Decrypt(). It panics if the source of randomness fails.
func NewEncryptionKey() (*[32]byte, error) {
	key := [32]byte{}
	_, err := io.ReadFull(rand.Reader, key[:])
	if err != nil {
		return nil, err
	}
	return &key, nil
}

// Encrypt encrypts data using 256-bit AES-GCM.  This both hides the content of
// the data and provides a check that it hasn't been altered. Output takes the
// form nonce|ciphertext|tag where '|' indicates concatenation.
func Encrypt(plaintext []byte, key *[32]byte) (ciphertext []byte, err error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt decrypts data using 256-bit AES-GCM.  This both hides the content of
// the data and provides a check that it hasn't been altered. Expects input
// form nonce|ciphertext|tag where '|' indicates concatenation.
func Decrypt(ciphertext []byte, key *[32]byte) (plaintext []byte, err error) {
	if key == nil {
		return nil, errors.New("key is nil")
	}
	if key == &[32]byte{} {
		return nil, errors.New("key is empty")
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("malformed ciphertext")
	}

	return gcm.Open(nil,
		ciphertext[:gcm.NonceSize()],
		ciphertext[gcm.NonceSize():],
		nil,
	)
}

func EncryptString(s string, key *[32]byte) (string, error) {
	ciphertext, err := Encrypt([]byte(s), key)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func DecryptString(s string, key *[32]byte) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	plaintext, err := Decrypt(ciphertext, key)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func KeyToBase64(key *[32]byte) string {
	return base64.StdEncoding.EncodeToString(key[:])
}

func Base64ToKey(s string) *[32]byte {
	key := [32]byte{}
	copy(key[:], s)
	return &key
}

func PadStr(s string, l int) string {
	if len(s) > l {
		return s[:l]
	}
	return s + strings.Repeat("$", l-len(s))
}

func UnpadStr(s string) string {
	for strings.HasSuffix(s, "$") {
		s = s[:len(s)-1]
	}
	return s
}

func PadKey(key string) *[32]byte {
	// Generate a key from user input
	key = PadStr(key, 32)
	var keyarr [32]byte
	copy(keyarr[:], key)
	return &keyarr
}

func UnpadKey(key *[32]byte) string {
	return UnpadStr(string(key[:]))
}
