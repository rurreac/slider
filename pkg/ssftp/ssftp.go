package ssftp

import (
	"fmt"
	"net"
	"slider/pkg/scrypt"
	"slider/pkg/sio"
	"slider/pkg/slog"
	"sync"

	"golang.org/x/crypto/ssh"
)

type InstanceConfig struct {
	Logger             *slog.Logger
	LogID              string
	port               int
	sshConn            ssh.Conn
	ServerKey          ssh.Signer
	AuthOn             bool
	allowedFingerprint string
}

type Instance struct {
	*InstanceConfig
	sftpEnabled bool
	stopSignal  chan bool
	done        chan bool
	sftpMutex   sync.Mutex
}

func New(config *InstanceConfig) *Instance {
	return &Instance{
		InstanceConfig: config,
	}
}

func (si *Instance) SetControls() {
	si.sftpMutex.Lock()
	si.stopSignal = make(chan bool, 1)
	si.done = make(chan bool, 1)
	si.sftpMutex.Unlock()
}

func (si *Instance) SetSSHConn(conn ssh.Conn) {
	si.sftpMutex.Lock()
	si.sshConn = conn
	si.sftpMutex.Unlock()
}

func (si *Instance) SetPort(port int) {
	si.sftpMutex.Lock()
	si.port = port
	si.sftpEnabled = true
	si.sftpMutex.Unlock()
}

func (si *Instance) SetAllowedFingerprint(fp string) {
	si.sftpMutex.Lock()
	si.allowedFingerprint = fp
	si.sftpMutex.Unlock()
}

func (si *Instance) StartEndpoint(port int) error {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return err
	}
	si.SetControls()
	si.SetPort(listener.Addr().(*net.TCPAddr).Port)

	go func() {
		if <-si.stopSignal; true {
			close(si.stopSignal)
			_ = listener.Close()
		}
	}()

	si.Logger.Debugf("%sSFTP Triggering Listener", si.LogID)
	for {
		conn, lErr := listener.Accept()
		if lErr != nil {
			break
		}
		go si.runComm(conn)
	}

	si.done <- true
	return nil
}

func (si *Instance) runComm(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	sshConf := &ssh.ServerConfig{NoClientAuth: true}
	if si.AuthOn {
		sshConf.NoClientAuth = false
		sshConf.PublicKeyCallback = si.clientVerification
	}
	sshConf.AddHostKey(si.ServerKey)

	_, newChan, reqChan, cErr := ssh.NewServerConn(conn, sshConf)
	if cErr != nil {
		si.Logger.Errorf("Failed SFTP handshake - %v", cErr)
		return
	}

	// Service incoming SSH Request channel
	go ssh.DiscardRequests(reqChan)

	for nc := range newChan {
		if nc.ChannelType() != "session" {
			si.Logger.Warnf("SFTP Rejected channel type %s", nc.ChannelType())
			_ = nc.Reject(ssh.UnknownChannelType, "")
			continue
		}
		channel, request, aErr := nc.Accept()
		if aErr != nil {
			si.Logger.Errorf("Could not accept channel - %v", aErr)
		}

		go func(in <-chan *ssh.Request) {
			for req := range in {
				ok := false
				switch req.Type {
				// SFTP session type is "subsystem" with a payload string of "<length=4>sftp"
				case "subsystem":
					if string(req.Payload[4:]) == "sftp" {
						ok = true
					}
				}
				si.Logger.Debugf("SFTP Request status: %v - type: %s - payload: \"%s\"\n", ok, req.Type, req.Payload)
				if req.WantReply {
					go func() { _ = req.Reply(ok, nil) }()
				}
			}
		}(request)

		sftpChan, sftpReq, oErr := si.sshConn.OpenChannel("sftp", nil)
		if oErr != nil {
			si.Logger.Errorf("Failed to open SFTP channel: %v", oErr)
			return
		}
		// Discard requests from the SFTP channel
		go ssh.DiscardRequests(sftpReq)

		// Pipe SFTP channel with SSH channel
		_, _ = sio.PipeWithCancel(channel, sftpChan)
		_ = sftpChan.Close()
	}
}

func (si *Instance) IsEnabled() bool {
	si.sftpMutex.Lock()
	enabled := si.sftpEnabled
	si.sftpMutex.Unlock()
	return enabled
}

func (si *Instance) GetEndpointPort() (int, error) {
	si.sftpMutex.Lock()
	defer si.sftpMutex.Unlock()

	if !si.sftpEnabled {
		return 0, fmt.Errorf("sftp is not running")
	}

	return si.port, nil
}

func (si *Instance) Stop() error {
	if !si.sftpEnabled {
		return fmt.Errorf("sftp is not running")
	}
	si.Logger.Debugf("%sSFTP Triggering Shutdown", si.LogID)

	si.stopSignal <- true
	<-si.done
	close(si.done)

	si.sftpMutex.Lock()
	si.port = 0
	si.sftpEnabled = false
	si.sftpMutex.Unlock()

	si.Logger.Debugf("%sSFTP Endpoint down", si.LogID)

	return nil
}

func (si *Instance) clientVerification(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	fp, fErr := scrypt.GenerateFingerprint(key)
	if fErr != nil {
		return nil, fmt.Errorf("failed to generate fingerprint from public key - %s", fErr)
	}

	if fp == si.allowedFingerprint {
		si.Logger.Debugf("Authenticated Client %s fingerprint: %s", conn.RemoteAddr(), fp)
		return &ssh.Permissions{Extensions: map[string]string{"fingerprint": fp}}, nil
	}
	si.Logger.Warnf("Rejected client %s, due to bad key authentication", conn.RemoteAddr())

	return nil, fmt.Errorf("client key not authorized")
}
