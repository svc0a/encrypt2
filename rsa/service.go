package rsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
)

// Encoder is responsible for signing messages using an RSA private key.
type Encoder interface {
	Sign(message string) (string, error)
	private()
}

// Decoder is responsible for verifying signatures using an RSA public key.
type Decoder interface {
	Verify(message, signature string) error
	private()
}

// NewEncoder initializes an Encoder with the provided PEM-encoded RSA private key.
func NewEncoder(privateKeyPEM string) (Encoder, error) {
	privateKey, err := parsePrivateKey(privateKeyPEM)
	if err != nil {
		return nil, err
	}
	return &encoderImpl{privateKey: privateKey}, nil
}

// NewDecoder initializes a Decoder with the provided PEM-encoded RSA public key.
func NewDecoder(publicKeyPEM string) (Decoder, error) {
	publicKey, err := parsePublicKey(publicKeyPEM)
	if err != nil {
		return nil, err
	}
	return &decoderImpl{publicKey: publicKey}, nil
}

// encoderImpl implements the Encoder interface.
type encoderImpl struct {
	privateKey *rsa.PrivateKey
}

func (e *encoderImpl) Sign(message string) (string, error) {
	// Hash the message using SHA-256.
	hashed := sha256.Sum256([]byte(message))

	// Sign the hashed message using PKCS1v15.
	signature, err := rsa.SignPKCS1v15(rand.Reader, e.privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return "", err
	}

	// Return the signature encoded in base64.
	return base64.StdEncoding.EncodeToString(signature), nil
}

func (e *encoderImpl) private() {}

// decoderImpl implements the Decoder interface.
type decoderImpl struct {
	publicKey *rsa.PublicKey
}

func (d *decoderImpl) Verify(message, signatureB64 string) error {
	// Decode the base64-encoded signature.
	signature, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return err
	}

	// Hash the message using SHA-256.
	hashed := sha256.Sum256([]byte(message))

	// Verify the signature using PKCS1v15.
	err = rsa.VerifyPKCS1v15(d.publicKey, crypto.SHA256, hashed[:], signature)
	if err != nil {
		return errors.New("signature verification failed")
	}

	return nil
}

func (d *decoderImpl) private() {}

// parsePrivateKey parses a PEM-encoded RSA private key.
func parsePrivateKey(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("invalid PEM block for private key")
	}
	if block.Type != "RSA PRIVATE KEY" && block.Type != "PRIVATE KEY" {
		return nil, errors.New("unsupported private key type")
	}

	var parsedKey interface{}
	var err error
	if block.Type == "PRIVATE KEY" {
		parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	} else {
		parsedKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	}
	if err != nil {
		return nil, err
	}

	privateKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an RSA private key")
	}
	return privateKey, nil
}

// parsePublicKey parses a PEM-encoded RSA public key.
func parsePublicKey(pemStr string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("invalid PEM block for public key")
	}

	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	publicKey, ok := pubInterface.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}
	return publicKey, nil
}
