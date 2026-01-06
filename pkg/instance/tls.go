package instance

import (
	"crypto/tls"
	"fmt"
	"net"
	"slider/pkg/scrypt"
	"slider/pkg/slog"
)

func (si *Config) StartTLSEndpoint(port int) error {
	var cert *scrypt.GeneratedCertificate
	if !si.certExists {
		var ccErr error
		cert, ccErr = si.CertificateAuthority.CreateCertificate(true)
		if ccErr != nil {
			return fmt.Errorf("failed to create Server TLS certificate - %v", ccErr)
		}
		si.setServerCertificate(cert)
		si.Logger.DebugWith("Created new TLS server certificate",
			slog.F("session_id", si.SessionID))
	} else {
		si.Logger.DebugWith("Using existing TLS server certificate",
			slog.F("session_id", si.SessionID))
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

		// For interactive mode (server console connection), use runShellComm
		// which gets the server's terminal size and opens channels to the client
		if si.interactiveOn {
			go si.runShellComm(conn)
		} else {
			// For external connections, use service handler
			go si.handleServiceConnection("shell", conn)
		}
	}

	si.done <- true

	return nil
}
