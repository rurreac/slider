package scrypt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"golang.org/x/crypto/ssh"
)

// TODO: This should be set according to config flags default to TEMP or cwd otherwise
var (
	temp           = os.Getenv("TEMP")
	PrivateKeyFile = temp + "./sshi-rsa.pem"
	PublicKeyFile  = temp + "./sshi-rsa.pub"
)

// EncodePrivateKeyToPEM converts a private key to PEM format
func EncodePrivateKeyToPEM(privateKey *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
}

// GeneratePrivateKey generate an RSA key of a given length
func GeneratePrivateKey(keyLength int) (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, keyLength)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

// GeneratePublicKey generate an RSA Public Key from an RSA Private Key
func GeneratePublicKey(privateKey *rsa.PrivateKey) ([]byte, error) {
	publicRsaKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}
	publicRsaKeyBytes := ssh.MarshalAuthorizedKey(publicRsaKey)
	return publicRsaKeyBytes, nil
}

// EncodePublicKeyToPEM converts a public key to PEM format
func EncodePublicKeyToPEM(publicKey *rsa.PublicKey) ([]byte, error) {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	return publicKeyBytes, nil
}

// CreateKeyPairFiles creates Private and Public Key files from bytes
func CreateKeyPairFiles(privateKeyBytes []byte, publicKeyBytes []byte) error {
	err := os.WriteFile(PrivateKeyFile, privateKeyBytes, 0600)
	if err != nil {
		return err
	}
	err = os.WriteFile(PublicKeyFile, publicKeyBytes, 0600)
	if err != nil {
		return err
	}
	return nil
}

func CreateSSHKeys(sshConfig ssh.ServerConfig, keyGen bool) (ssh.Signer, error) {
	// Generate SSH Keys
	privateKey, err := GeneratePrivateKey(4096)
	if err != nil {
		return nil, fmt.Errorf("generatePrivateKey: %s", err)
	}

	privateKeyBytes := EncodePrivateKeyToPEM(privateKey)
	privateKeySigner, err := ssh.ParsePrivateKey(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("ParsePrivateKey: %s", err)
	}

	sshConfig.AddHostKey(privateKeySigner)

	publicKeyBytes, err := GeneratePublicKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("generatePublicKey: %s", err)
	}
	if keyGen {
		err = CreateKeyPairFiles(privateKeyBytes, publicKeyBytes)
		if err != nil {
			return nil, fmt.Errorf("createKeyPairFiles: %s", err)
		}
	}
	return privateKeySigner, nil
}
