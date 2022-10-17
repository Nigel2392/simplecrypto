package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
)

// Encrypt encrypts data with public key
func Encrypt(msg []byte, pub *rsa.PublicKey) ([]byte, error) {
	hash := sha512.New()
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, pub, msg, nil)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

func PemToPubkey(pubkeystr string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pubkeystr))
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return key.(*rsa.PublicKey), nil
}

func WritePubPem(key *rsa.PublicKey, filename string) error {
	block, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(filename, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: block}), 0644)
	if err != nil {
		return err
	}
	return nil
}

func ImportPubPem(filename string) (*rsa.PublicKey, error) {
	keyfile, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(keyfile)
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return key.(*rsa.PublicKey), nil
}

func GenKeypair(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privkey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	return privkey, &privkey.PublicKey, nil
}

// Decrypt decrypts data with private key
func Decrypt(ciphertext []byte, priv *rsa.PrivateKey) ([]byte, error) {
	hash := sha512.New()
	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, priv, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func WritePrivPem(key *rsa.PrivateKey, filename string) error {
	block, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(filename, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: block}), 0644)
	if err != nil {
		return err
	}
	return nil
}

func PemToPrivkey(privkeystr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privkeystr))
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return key.(*rsa.PrivateKey), nil
}

func ImportPrivPem(filename string) (*rsa.PrivateKey, error) {
	keyfile, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(keyfile)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return key.(*rsa.PrivateKey), nil
}
