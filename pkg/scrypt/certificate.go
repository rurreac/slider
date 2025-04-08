package scrypt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

// CertificateAuthority holds the CA certificate and private key
type CertificateAuthority struct {
	Template     *x509.Certificate  `json:"Template"`
	CAPrivateKey ed25519.PrivateKey `json:"CAPrivateKey"`
	CAPublicKey  ed25519.PublicKey  `json:"CAPublicKey"`
	CertPEM      []byte             `json:"CertPEM"`
	KeyPEM       []byte             `json:"KeyPEM"`
}

// GeneratedCertificate holds a generated certificate and its details
type GeneratedCertificate struct {
	Cert       *x509.Certificate  `json:"Cert"`
	PrivateKey ed25519.PrivateKey `json:"PrivateKey"`
	CertPEM    []byte             `json:"CertPEM"`
	KeyPEM     []byte             `json:"KeyPEM"`
	TLSCert    tls.Certificate    `json:"TLSCert"`
}

// CreateCA creates a new certificate authority
func CreateCA() (*CertificateAuthority, error) {
	// Generate Ed25519 key pair for the CA
	publicKey, privateKey, gErr := ed25519.GenerateKey(rand.Reader)
	if gErr != nil {
		return nil, fmt.Errorf("failed to generate CA key pair: %v", gErr)
	}

	// Create a certificate template for the CA
	serialNumber, rErr := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if rErr != nil {
		return nil, fmt.Errorf("failed to generate serial number: %v", rErr)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(99, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Self-sign the CA certificate
	caCertDER, cErr := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, publicKey, privateKey)
	if cErr != nil {
		return nil, fmt.Errorf("failed to create CA certificate: %v", cErr)
	}

	// Encode the CA certificate in PEM format
	caCertPEM := new(bytes.Buffer)
	peErr := pem.Encode(caCertPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCertDER,
	})
	if peErr != nil {
		return nil, fmt.Errorf("failed to encode CA certificate to PEM: %v", peErr)
	}

	// Encode the CA private key in PEM format
	pvKeyBytes, mErr := x509.MarshalPKCS8PrivateKey(privateKey)
	if mErr != nil {
		return nil, fmt.Errorf("failed to marshal private key: %v", mErr)
	}

	caKeyPEM := new(bytes.Buffer)
	keErr := pem.Encode(caKeyPEM, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pvKeyBytes,
	})
	if keErr != nil {
		return nil, fmt.Errorf("failed to encode CA key to PEM: %v", keErr)
	}

	return &CertificateAuthority{
		Template:     caTemplate,
		CAPrivateKey: privateKey,
		CAPublicKey:  publicKey,
		CertPEM:      caCertPEM.Bytes(),
		KeyPEM:       caKeyPEM.Bytes(),
	}, nil
}

// CreateCertificate creates a new certificate signed by the CA
func (ca *CertificateAuthority) CreateCertificate(isServer bool) (*GeneratedCertificate, error) {
	// Generate Ed25519 key pair for the new certificate
	publicKey, privateKey, gErr := ed25519.GenerateKey(rand.Reader)
	if gErr != nil {
		return nil, fmt.Errorf("failed to generate key pair: %v", gErr)
	}

	// Create a certificate template
	serialNumber, rErr := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if rErr != nil {
		return nil, fmt.Errorf("failed to generate serial number: %v", rErr)
	}

	notBefore := time.Now()
	// Set the notAfter time to 1 minute from now for client certs
	// to give a short-lived certificate only for performing the authentication
	notAfter := notBefore.Add(time.Minute)
	if isServer {
		notAfter = notBefore.AddDate(10, 0, 0)
	}

	certTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		IsCA:                  false,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}

	// Add appropriate ExtKeyUsage fields based on whether it's a server or client cert
	if isServer {
		certTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	} else {
		certTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}

	// Sign the certificate with the CA
	certDER, ccErr := x509.CreateCertificate(rand.Reader, certTemplate, ca.Template, publicKey, ca.CAPrivateKey)
	if ccErr != nil {
		return nil, fmt.Errorf("failed to create certificate: %v", ccErr)
	}

	// Parse the certificate to get the x509.Certificate object
	cert, pcErr := x509.ParseCertificate(certDER)
	if pcErr != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", pcErr)
	}

	// Encode the certificate in PEM format
	certPEM := new(bytes.Buffer)
	peErr := pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	if peErr != nil {
		return nil, fmt.Errorf("failed to encode certificate to PEM: %v", peErr)
	}

	// Encode the private key in PEM format
	privKeyBytes, mErr := x509.MarshalPKCS8PrivateKey(privateKey)
	if mErr != nil {
		return nil, fmt.Errorf("failed to marshal private key: %v", mErr)
	}

	keyPEM := new(bytes.Buffer)
	keErr := pem.Encode(keyPEM, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privKeyBytes,
	})
	if keErr != nil {
		return nil, fmt.Errorf("failed to encode key to PEM: %v", keErr)
	}

	// Create a TLS certificate
	tlsCert, tErr := tls.X509KeyPair(certPEM.Bytes(), keyPEM.Bytes())
	if tErr != nil {
		return nil, fmt.Errorf("failed to create TLS certificate: %v", tErr)
	}

	return &GeneratedCertificate{
		Cert:       cert,
		PrivateKey: privateKey,
		CertPEM:    certPEM.Bytes(),
		KeyPEM:     keyPEM.Bytes(),
		TLSCert:    tlsCert,
	}, nil
}

// GetTLSClientConfig returns a TLS config for a client using the CA and client certificate
func (ca *CertificateAuthority) GetTLSClientConfig(clientCert *GeneratedCertificate) *tls.Config {
	// Create a cert pool and add the CA's cert to it
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(ca.CertPEM)

	return &tls.Config{
		RootCAs:      certPool,
		Certificates: []tls.Certificate{clientCert.TLSCert},
		MinVersion:   tls.VersionTLS13,
		ServerName:   "localhost",
	}
}

// GetTLSServerConfig returns a TLS config for a server using the CA and server certificate
func (ca *CertificateAuthority) GetTLSServerConfig(serverCert *GeneratedCertificate, verifyClientCert bool) *tls.Config {
	// Create a cert pool and add the CA's cert to it
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(ca.CertPEM)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert.TLSCert},
		MinVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384,
		},
	}

	if verifyClientCert {
		tlsConfig.ClientCAs = certPool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return tlsConfig
}
