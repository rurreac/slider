package scrypt

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"golang.org/x/crypto/ssh"
	"os"
	"path"
)

type ServerKeyPair struct {
	*CertificateAuthority `json:"CertificateAuthority"`
	*KeyPair              `json:"KeyPair"`
}
type KeyPair struct {
	PrivateKey    string `json:"PrivateKey"`
	SSHPrivateKey string `json:"SSHPrivateKey"`
	SSHPublicKey  string `json:"SSHPublicKey"`
	FingerPrint   string `json:"FingerPrint"`
}

type CertTrack struct {
	CertCount  int64
	CertActive int64
	Certs      map[int64]*KeyPair
}

func NewServerKeyPair() (*ServerKeyPair, error) {
	ca, cErr := CreateCA()
	if cErr != nil {
		return nil, fmt.Errorf("failed to create CA: %v", cErr)
	}

	// MarshalPKCS8PrivateKey supports ed25519
	pvBytes, xErr := x509.MarshalPKCS8PrivateKey(ca.CAPrivateKey)
	if xErr != nil {
		return nil, xErr
	}

	pvBlock, mErr := ssh.MarshalPrivateKey(crypto.PrivateKey(ca.CAPrivateKey), "")
	if mErr != nil {
		return nil, mErr
	}

	pbKey, pbErr := ssh.NewPublicKey(ca.CAPublicKey)
	if pbErr != nil {
		return nil, pbErr
	}

	fingerprint, fErr := GenerateFingerprint(pbKey)
	if fErr != nil {
		return nil, fErr
	}

	return &ServerKeyPair{
		CertificateAuthority: ca,
		KeyPair: &KeyPair{
			PrivateKey:    base64.RawStdEncoding.EncodeToString(pvBytes),
			SSHPrivateKey: string(pem.EncodeToMemory(pvBlock)),
			SSHPublicKey:  string(ssh.MarshalAuthorizedKey(pbKey)),
			FingerPrint:   fingerprint,
		},
	}, nil
}

func ServerKeyPairFromFile(keyPath string) (*ServerKeyPair, error) {
	var serverKeyPair *ServerKeyPair
	var err error

	if _, sErr := os.Stat(keyPath); os.IsNotExist(sErr) {
		serverKeyPair, err = NewServerKeyPair()
		if err != nil {
			return nil, err
		}

		if mkErr := os.MkdirAll(path.Dir(keyPath), 0700); mkErr != nil {
			return nil, fmt.Errorf("failed to create directory - %v", mkErr)
		}
		file, oErr := os.OpenFile(keyPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
		if oErr != nil {
			return nil, fmt.Errorf("failed to open file %s", keyPath)
		}
		defer func() { _ = file.Close() }()
		keyPairBytes, jErr := json.Marshal(serverKeyPair)
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

		if jErr := json.Unmarshal(file, &serverKeyPair); jErr != nil {
			return nil, fmt.Errorf("failed to unmarshal file - %v", jErr)
		}
	}

	return serverKeyPair, nil
}

func SignerFromKey(key string) (ssh.Signer, error) {
	keyBytes, dErr := base64.RawStdEncoding.DecodeString(key)
	if dErr != nil {
		return nil, fmt.Errorf("failed to decode key - %v", dErr)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:    "PRIVATE KEY",
		Headers: nil,
		Bytes:   keyBytes,
	})

	privateKeySigner, prErr := ssh.ParsePrivateKey(pemBytes)
	if prErr != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", prErr)
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
	pvBytes, xErr := x509.MarshalPKCS8PrivateKey(privateKey)
	if xErr != nil {
		return nil, xErr
	}

	pvBlock, mErr := ssh.MarshalPrivateKey(crypto.PrivateKey(privateKey), "")
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
		PrivateKey:    base64.RawStdEncoding.EncodeToString(pvBytes),
		SSHPrivateKey: string(pem.EncodeToMemory(pvBlock)),
		SSHPublicKey:  string(ssh.MarshalAuthorizedKey(pbKey)),
		FingerPrint:   fingerprint,
	}, nil
}

func IsAllowedFingerprint(fp string, ct map[int64]*KeyPair) (int64, bool) {
	for i, k := range ct {
		if k.FingerPrint == fp {
			return i, true
		}
	}

	return 0, false
}
