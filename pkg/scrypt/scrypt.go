package scrypt

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh"
	"os"
	"path"
)

type KeyPair struct {
	PrivateKey  string `json:"PrivateKey"`
	FingerPrint string `json:"FingerPrint"`
}

func NewSSHSigner() (ssh.Signer, error) {
	keypair, err := NewEd25519KeyPair()
	if err != nil {
		return nil, err
	}

	privateKeySigner, prErr := SignerFromKey(keypair.PrivateKey)
	if prErr != nil {
		return nil, fmt.Errorf("ParsePrivateKey: %v", err)
	}

	return privateKeySigner, nil
}

func NewSSHSignerFromFile(keyPath string) (ssh.Signer, error) {
	var keyPair *KeyPair
	var err error

	if _, sErr := os.Stat(keyPath); os.IsNotExist(sErr) {
		keyPair, err = NewEd25519KeyPair()
		if err != nil {
			return nil, err
		}
		if mkErr := os.MkdirAll(path.Dir(keyPath), os.ModePerm); mkErr != nil {
			return nil, fmt.Errorf("failed to create directory - %v", mkErr)
		}
		file, oErr := os.Create(keyPath)
		if oErr != nil {
			return nil, fmt.Errorf("failed to open file %s", keyPath)
		}
		defer func() { _ = file.Close() }()
		keyPairBytes, jErr := json.Marshal(keyPair)
		if jErr != nil {
			return nil, fmt.Errorf("failed to marshal keypair - %v", jErr)
		}
		if _, wErr := file.Write(keyPairBytes); wErr != nil {
			return nil, fmt.Errorf("failed to save keypair in %s - %v", keyPath, wErr)
		}
	} else {
		file, oErr := os.ReadFile(keyPath)
		if oErr != nil {
			return nil, fmt.Errorf("failed to open file %s", keyPath)
		}

		if jErr := json.Unmarshal(file, &keyPair); jErr != nil {
			return nil, fmt.Errorf("failed to unmarshal file - %v", jErr)
		}
	}

	privateKeySigner, prErr := SignerFromKey(keyPair.PrivateKey)
	if prErr != nil {
		return nil, fmt.Errorf("ParsePrivateKey: %v", prErr)
	}

	return privateKeySigner, nil
}

func SignerFromKey(key string) (ssh.Signer, error) {
	keyBytes, dErr := base64.RawStdEncoding.DecodeString(key)
	if dErr != nil {
		return nil, dErr
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:    "PRIVATE KEY",
		Headers: nil,
		Bytes:   keyBytes,
	})

	privateKeySigner, prErr := ssh.ParsePrivateKey(pemBytes)
	if prErr != nil {
		return nil, fmt.Errorf("ParsePrivateKey: %v", prErr)
	}

	return privateKeySigner, prErr
}

func GenerateFingerprint(publicKey ssh.PublicKey) (string, error) {
	h := sha256.New()
	if _, hErr := h.Write(publicKey.Marshal()); hErr != nil {
		return "", fmt.Errorf("failed to generate hash - %v", hErr)
	}

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

	pbKey, pbErr := ssh.NewPublicKey(publicKey)
	if pbErr != nil {
		return nil, pbErr
	}

	fingerprint, fErr := GenerateFingerprint(pbKey)
	if fErr != nil {
		return nil, fErr
	}

	return &KeyPair{
		PrivateKey:  base64.RawStdEncoding.EncodeToString(pvBytes),
		FingerPrint: fingerprint,
	}, nil
}
