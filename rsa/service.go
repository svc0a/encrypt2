package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
)

type Encoder interface {
	Encode(string) (string, error)
	private()
}

type Decoder interface {
	Decode(string) (string, error)
	private()
}

func NewEncoder(privateKey string) Encoder {
	return impl{
		privateKey: privateKey,
	}
}

func NewDecoder(publicKey string) Decoder {
	return impl{
		publicKey: publicKey,
	}
}

type impl struct {
	privateKey string
	publicKey  string
}

func (i impl) Encode(s string) (string, error) {
	// Decode the private key from PEM format
	block, _ := pem.Decode([]byte(i.privateKey))
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return "", errors.New("failed to decode private key")
	}

	// Parse the RSA private key
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}

	// Encrypt the message using RSA private key
	encryptedBytes, err := rsa.SignPKCS1v15(rand.Reader, privateKey, 0, []byte(s))
	if err != nil {
		return "", err
	}

	// Encode the encrypted message as base64 string
	return base64.StdEncoding.EncodeToString(encryptedBytes), nil
}

func (i impl) Decode(s string) (string, error) {
	// Decode the public key from PEM format
	block, _ := pem.Decode([]byte(i.publicKey))
	if block == nil || block.Type != "PUBLIC KEY" {
		return "", errors.New("failed to decode public key")
	}

	// Parse the RSA public key
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", err
	}

	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return "", errors.New("not an RSA public key")
	}

	// Decode the base64 string into bytes
	encryptedBytes, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}

	// Decrypt the message using RSA public key
	decryptedBytes, err := rsa.DecryptPKCS1v15(rand.Reader, rsaPubKey, encryptedBytes)
	if err != nil {
		return "", err
	}

	// Return the decrypted message as string
	return string(decryptedBytes), nil
}

func (i impl) private() {
	// Private method to satisfy the interface
}
