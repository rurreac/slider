package ssocks

import (
	"fmt"
	"io"
	"log"
	"net"
	"slider/pkg/sconn"
	"slider/pkg/sio"
	"slider/pkg/slog"
	"strings"

	"github.com/armon/go-socks5"
	"golang.org/x/crypto/ssh"
)

type InstanceConfig struct {
	*slog.Logger
	Port         int
	SSHConn      ssh.Conn
	SocksChannel ssh.Channel
	IsEndpoint   bool
	IsServer     bool
}

type Instance struct {
	*InstanceConfig
	socksEnabled bool
	stopSignal   chan bool
	done         chan bool
}

func New(config *InstanceConfig) *Instance {
	return &Instance{
		InstanceConfig: config,
		stopSignal:     make(chan bool, 1),
		done:           make(chan bool, 1),
	}
}

func (si *Instance) StartEndpoint() error {
	// Make Endpoints to listen only localhost due to security, but can be configured in the future
	addr, rErr := net.ResolveTCPAddr("tcp", fmt.Sprintf("127.0.0.1:%d", si.Port))
	if rErr != nil {
		return fmt.Errorf("can not resolve address [:%d] - %s", si.Port, rErr)
	}

	listener, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return err
	}

	si.Port = listener.Addr().(*net.TCPAddr).Port
	si.socksEnabled = true

	go func() {
		if <-si.stopSignal; true {
			si.socksEnabled = false
			close(si.stopSignal)
			_ = listener.Close()
		}
	}()

	for {
		TCPConn, lErr := listener.AcceptTCP()
		if lErr != nil {
			break
		}
		go si.runComm(TCPConn)
	}

	si.done <- true
	return nil
}

func (si *Instance) StartServer() error {
	var err error

	si.socksEnabled = true

	for {
		if err = si.runSocks(); err != nil {
			break
		}
	}

	si.socksEnabled = false

	return err
}

func (si *Instance) runSocks() error {
	socksConn := sconn.SSHChannelToNetConn(si.SocksChannel)

	// socks5 logger logs by default and it's very chatty
	socksServer, snErr := socks5.New(
		&socks5.Config{
			Logger: log.New(io.Discard, "", 0),
		})
	if snErr != nil {
		return fmt.Errorf("failed to create new socks server - %s", snErr)
	}

	sErr := socksServer.ServeConn(socksConn)
	if sErr != nil && !strings.Contains(fmt.Sprintf("%s", sErr), "EOF") {
		return fmt.Errorf("connection error - %s", sErr)
	}

	return nil
}

func (si *Instance) runComm(conn *net.TCPConn) {
	defer func() { _ = conn.Close() }()
	socksChan, reqs, oErr := si.SSHConn.OpenChannel("socks5", nil)
	if oErr != nil {
		si.Errorf("SOCKS - failed to open \"socks5\" channel - %s", oErr)
	}
	defer func() { _ = socksChan.Close() }()
	go ssh.DiscardRequests(reqs)
	_, _ = sio.PipeWithCancel(socksChan, conn)
}

func (si *Instance) IsEnabled() bool {
	return si.socksEnabled
}

func (si *Instance) GetEndpointPort() (int, error) {
	if !si.IsEndpoint {
		return 0, fmt.Errorf("socks instance is not an endpoint")
	}
	return si.Port, nil
}

func (si *Instance) Stop() error {
	if !si.socksEnabled {
		return fmt.Errorf("socks is not running")
	}
	si.Debugf("SOCKS - Triggering Shutdown")
	si.stopSignal <- true
	<-si.done
	close(si.done)
	si.Debugf("SOCKS - Endpoint down")

	return nil
}
