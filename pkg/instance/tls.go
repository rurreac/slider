package instance

import (
	"crypto/tls"
	"fmt"
	"net"
	"slider/pkg/scrypt"
)

func (si *Config) StartTLSEndpoint(port int) error {
	var cert *scrypt.GeneratedCertificate
	if !si.certExists {
		var ccErr error
		cert, ccErr = si.CertificateAuthority.CreateCertificate(true)
		if ccErr != nil {
			return fmt.Errorf("failed to create client TLS certificate - %v", ccErr)
		}
		si.setServerCertificate(cert)
		si.Logger.Debugf(si.LogPrefix + "Created new TLS server certificate")
	} else {
		si.Logger.Debugf(si.LogPrefix + "Using existing TLS server certificate")
		cert = si.serverCertificate
	}
	tlsConfig := si.CertificateAuthority.GetTLSServerConfig(cert, si.interactiveOn)

	tlsListener, lErr := tls.Listen("tcp", fmt.Sprintf(":%d", port), tlsConfig)
	if lErr != nil {
		return fmt.Errorf("can not listen for connections - %v", lErr)
	}

	if !si.isExposed() {
		_ = tlsListener.Close()
		tlsListener, lErr = tls.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port), tlsConfig)
		if lErr != nil {
			return fmt.Errorf("can not listen for localhost connections - %v", lErr)
		}
	}
	defer func() { _ = tlsListener.Close() }()

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
		conn, aErr := tlsListener.Accept()
		if aErr != nil {
			break
		}

		go si.runShellComm(conn)
	}

	si.done <- true

	return nil
}
