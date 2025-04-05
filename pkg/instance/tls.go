package instance

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"golang.org/x/crypto/ed25519"
	"log"
	"math/big"
	"net"
	"time"
)

func (si *Config) StartTLSEndpoint(port int) error {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("Failed to generate serial number: %v", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		NotBefore:    now,
		NotAfter:     now.AddDate(1, 0, 0), // Valid for 1 year
		KeyUsage: x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	host := net.ParseIP("127.0.0.1")
	template.IPAddresses = append(template.IPAddresses, host)
	template.DNSNames = append(template.DNSNames, "localhost")

	//priv, err := rsa.GenerateKey(rand.Reader, 2048)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, priv.Public(), priv)
	if err != nil {
		log.Fatalf("Failed to create certificate: %v", err)
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}

	tlsConfig := tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS13,
	}

	tlsListener, err := tls.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port), &tlsConfig)
	if err != nil {
		return err
	}

	if !si.isExposed() {
		_ = tlsListener.Close()
		tlsListener, err = tls.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port), &tlsConfig)
		if err != nil {
			return err
		}
	}

	si.setControls()
	port = tlsListener.Addr().(*net.TCPAddr).Port
	si.setPort(port)

	go func() {
		if <-si.stopSignal; true {
			close(si.stopSignal)
			_ = tlsListener.Close()
		}
	}()

	for {
		conn, err := tlsListener.Accept()
		if err != nil {
			si.Logger.Errorf("Failed to accept connection: %v", err)
			break
		}
		//conn.SetDeadline(time.Now().Add(30 * time.Second))
		go si.runShellComm(conn)
	}

	si.done <- true

	return nil
}
