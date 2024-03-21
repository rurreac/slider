package scrypt

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh"
)

type KeyPair struct {
	PrivateKey  []byte `json:"PrivateKey"`
	FingerPrint string `json:"FingerPrint"`
}

const CertJarFile = "slicer-certs.json"

func NewKeyPair() (ssh.Signer, string, error) {
	keypair, err := NewEd25519KeyPair()
	if err != nil {
		return nil, "", err
	}

	privateKeySigner, prErr := ssh.ParsePrivateKey(keypair.PrivateKey)
	if prErr != nil {
		return nil, "", fmt.Errorf("ParsePrivateKey: %v", err)
	}

	return privateKeySigner, keypair.FingerPrint, nil
}

func GenerateFingerprint(publicKey ssh.PublicKey) (string, error) {
	h := sha256.New()
	h.Write(publicKey.Marshal())

	return base64.RawStdEncoding.EncodeToString(h.Sum(nil)), nil
}

func NewEd25519KeyPair() (*KeyPair, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	// MarshalPKCS8PrivateKey supports ed25519
	pvBytes, mErr := x509.MarshalPKCS8PrivateKey(privateKey)
	if mErr != nil {
		return nil, mErr
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:    "PRIVATE KEY",
		Headers: nil,
		Bytes:   pvBytes,
	})

	pbKey, pbErr := ssh.NewPublicKey(publicKey)
	if pbErr != nil {
		return nil, pbErr
	}

	fingerprint, fErr := GenerateFingerprint(pbKey)
	if fErr != nil {
		return nil, fErr
	}

	return &KeyPair{
		PrivateKey:  pemBytes,
		FingerPrint: fingerprint,
	}, nil
}

func (k *KeyPair) ExtractKeyFromPem() string {
	// Extract only the key from the Pem and base64 encode it
	block, _ := pem.Decode(k.PrivateKey)
	return base64.StdEncoding.EncodeToString(block.Bytes)
}
