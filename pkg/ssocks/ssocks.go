package ssocks

import (
	"fmt"
	"net"
	"slider/pkg/sio"
	"slider/pkg/slog"
	"sync"

	"golang.org/x/crypto/ssh"
)

type InstanceConfig struct {
	Logger       *slog.Logger
	LogID        string
	port         int
	sshConn      ssh.Conn
	SocksChannel ssh.Channel
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
	}
}

func (si *Instance) SetControls() {
	si.socksMutex.Lock()
	si.stopSignal = make(chan bool, 1)
	si.done = make(chan bool, 1)
	si.socksMutex.Unlock()
}

func (si *Instance) SetSSHConn(conn ssh.Conn) {
	si.socksMutex.Lock()
	si.sshConn = conn
	si.socksMutex.Unlock()
}

func (si *Instance) SetPort(port int) {
	si.socksMutex.Lock()
	si.port = port
	si.socksEnabled = true
	si.socksMutex.Unlock()
}

func (si *Instance) StartEndpoint(port int) error {
	// TODO: Endpoints listen only localhost due to security, but can be configured in the future + authentication?
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

	si.Logger.Debugf("%sSocks Triggering Listener", si.LogID)
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
	socksChan, reqs, oErr := si.sshConn.OpenChannel("socks5", nil)
	if oErr != nil {
		si.Logger.Errorf("%sFailed to open \"socks5\" channel - %v", si.LogID, oErr)
	}
	defer func() { _ = socksChan.Close() }()
	go ssh.DiscardRequests(reqs)

	_, _ = sio.PipeWithCancel(socksChan, conn)
}

func (si *Instance) IsEnabled() bool {
	si.socksMutex.Lock()
	enabled := si.socksEnabled
	si.socksMutex.Unlock()
	return enabled
}

func (si *Instance) GetEndpointPort() (int, error) {
	si.socksMutex.Lock()
	defer si.socksMutex.Unlock()

	if !si.socksEnabled {
		return 0, fmt.Errorf("sftp is not running")
	}

	return si.port, nil
}

func (si *Instance) Stop() error {
	if !si.socksEnabled {
		return fmt.Errorf("socks is not running")
	}
	si.Logger.Debugf("%sSocks Triggering Shutdown", si.LogID)

	si.stopSignal <- true
	<-si.done
	close(si.done)

	si.socksMutex.Lock()
	si.port = 0
	si.socksEnabled = false
	si.socksMutex.Unlock()

	si.Logger.Debugf("%sSocks Endpoint down", si.LogID)

	return nil
}
