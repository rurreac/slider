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
	"sync"

	"github.com/armon/go-socks5"
	"golang.org/x/crypto/ssh"
)

type InstanceConfig struct {
	Logger       *slog.Logger
	LogID        string
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
	socksMutex   sync.Mutex
}

func New(config *InstanceConfig) *Instance {
	return &Instance{
		InstanceConfig: config,
		stopSignal:     make(chan bool, 1),
		done:           make(chan bool, 1),
	}
}

func (si *Instance) StartEndpoint() error {
	// TODO: Endpoints listen only localhost due to security, but can be configured in the future + authentication?
	addr, rErr := net.ResolveTCPAddr("tcp", fmt.Sprintf("127.0.0.1:%d", si.Port))
	if rErr != nil {
		return fmt.Errorf("can not resolve address [:%d] - %v", si.Port, rErr)
	}

	listener, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return err
	}

	si.socksMutex.Lock()
	si.Port = listener.Addr().(*net.TCPAddr).Port
	si.socksEnabled = true
	si.socksMutex.Unlock()

	go func() {
		if <-si.stopSignal; true {
			si.socksMutex.Lock()
			si.socksEnabled = false
			si.Port = 0
			si.socksMutex.Unlock()
			close(si.stopSignal)
			_ = listener.Close()
		}
	}()

	si.Logger.Debugf("%sSocks Triggering Listener", si.LogID)
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
	si.socksMutex.Lock()
	si.socksEnabled = true
	si.socksMutex.Unlock()
	for {
		if err = si.runSocks(); err != nil {
			break
		}
	}
	si.socksMutex.Lock()
	si.socksEnabled = false
	si.socksMutex.Unlock()
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
		return fmt.Errorf("failed to create new socks server - %v", snErr)
	}

	sErr := socksServer.ServeConn(socksConn)
	if sErr != nil && !strings.Contains(fmt.Sprintf("%v", sErr), "EOF") {
		return fmt.Errorf("connection error - %v", sErr)
	}

	return nil
}

func (si *Instance) runComm(conn *net.TCPConn) {
	defer func() { _ = conn.Close() }()
	socksChan, reqs, oErr := si.SSHConn.OpenChannel("socks5", nil)
	if oErr != nil {
		si.Logger.Errorf("%sFailed to open \"socks5\" channel - %v", si.LogID, oErr)
	}
	defer func() { _ = socksChan.Close() }()
	go ssh.DiscardRequests(reqs)
	_, _ = sio.PipeWithCancel(socksChan, conn)
}

func (si *Instance) IsEnabled() bool {
	si.socksMutex.Lock()
	defer si.socksMutex.Unlock()
	return si.socksEnabled
}

func (si *Instance) GetEndpointPort() (int, error) {
	si.socksMutex.Lock()
	defer si.socksMutex.Unlock()

	if !si.IsEndpoint {
		return 0, fmt.Errorf("socks instance is not an endpoint")
	}
	return si.Port, nil
}

func (si *Instance) Stop() error {
	if !si.socksEnabled {
		return fmt.Errorf("socks is not running")
	}
	si.Logger.Debugf("%sSocks Triggering Shutdown", si.LogID)
	si.stopSignal <- true
	<-si.done
	close(si.done)
	si.Logger.Debugf("%sSocks Endpoint down", si.LogID)

	return nil
}
