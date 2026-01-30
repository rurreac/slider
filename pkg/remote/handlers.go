package remote

import (
	"encoding/json"
	"fmt"
	"io"
	"slider/pkg/conf"
	"slider/pkg/session"
	"slider/pkg/slog"
	"sync"

	"golang.org/x/crypto/ssh"
)

// HandleSliderConnect handles "slider-connect" SSH channels
// This is the ONLY application-specific handler that stays in server/remote
// All standard SSH protocol handlers have been moved to pkg/session/handlers.go
func HandleSliderConnect(nc ssh.NewChannel, sess session.Session, srv session.ApplicationServer) error {
	defer func() {
		if r := recover(); r != nil {
			sess.GetLogger().ErrorWith("Panic in HandleSliderConnect", slog.F("panic", r))
			_ = nc.Reject(ssh.ConnectionFailed, "internal server error")
		}
	}()

	// Parse payload
	var req ConnectRequest
	if err := json.Unmarshal(nc.ExtraData(), &req); err != nil {
		_ = nc.Reject(ssh.ConnectionFailed, fmt.Sprintf("failed to parse payload: %v", err))
		return err
	}

	if len(req.Target) == 0 {
		return sess.RouteChannel(nc, req.ChannelType)
	}

	return routeToNextHop(nc, sess, srv, &req)
}

func routeToNextHop(nc ssh.NewChannel, sess session.Session, srv session.ApplicationServer, req *ConnectRequest) error {
	proxy := NewProxy(sess, req.Target)
	nextHopID, remainingTarget, err := proxy.ParsePath()
	if err != nil {
		_ = nc.Reject(ssh.ConnectionFailed, err.Error())
		return err
	}

	nextHopSession, err := srv.GetSession(nextHopID)
	if err != nil {
		_ = nc.Reject(ssh.ConnectionFailed, fmt.Sprintf("session not found: %d", nextHopID))
		return err
	}

	// Final destination reached (no more hops)
	// Always use GetSSHConn() - the inbound connection where shell/exec handlers live
	if len(remainingTarget) == 0 {
		channelType := req.ChannelType

		targetChan, reqs, err := nextHopSession.GetSSHConn().OpenChannel(channelType, req.Payload)
		if err != nil {
			_ = nc.Reject(ssh.ConnectionFailed, fmt.Sprintf("failed to open target channel: %v", err))
			return err
		}

		localChan, localReqs, err := nc.Accept()
		if err != nil {
			_ = targetChan.Close()
			return err
		}

		pipeChannels(localChan, targetChan, localReqs, reqs)
		return nil
	}

	// More hops remaining - forward through the next hop
	// This requires the next hop to be a promiscuous session (has an outbound connection)
	if nextHopSession.GetSSHClient() == nil {
		_ = nc.Reject(ssh.ConnectionFailed, fmt.Sprintf("session %d is not a gateway, cannot forward", nextHopID))
		return fmt.Errorf("session %d is not a gateway", nextHopID)
	}

	// Forward to the next hop
	fwdReq := ConnectRequest{
		Target:      remainingTarget,
		ChannelType: req.ChannelType,
		Payload:     req.Payload,
	}
	fwdPayload, _ := json.Marshal(fwdReq)

	targetChan, reqs, err := nextHopSession.GetSSHClient().OpenChannel(conf.SSHChannelSliderConnect, fwdPayload)
	if err != nil {
		_ = nc.Reject(ssh.ConnectionFailed, fmt.Sprintf("failed to open next hop channel: %v", err))
		return err
	}

	localChan, localReqs, err := nc.Accept()
	if err != nil {
		_ = targetChan.Close()
		return err
	}

	pipeChannels(localChan, targetChan, localReqs, reqs)
	return nil
}

func pipeChannels(local, remote ssh.Channel, localReqs, remoteReqs <-chan *ssh.Request) {
	var wg sync.WaitGroup
	wg.Add(4)

	// Remote -> Local
	go func() {
		defer wg.Done()
		_, _ = io.Copy(local, remote)
		_ = local.CloseWrite()
	}()

	// Local -> Remote
	go func() {
		defer wg.Done()
		_, _ = io.Copy(remote, local)
		_ = remote.CloseWrite()
	}()

	// Local -> Remote requests
	go func() {
		defer wg.Done()
		for req := range localReqs {
			ok, _ := remote.SendRequest(req.Type, req.WantReply, req.Payload)
			if req.WantReply {
				_ = req.Reply(ok, nil)
			}
		}
	}()

	// Remote -> Local requests
	go func() {
		defer wg.Done()
		for req := range remoteReqs {
			ok, _ := local.SendRequest(req.Type, req.WantReply, req.Payload)
			if req.WantReply {
				_ = req.Reply(ok, nil)
			}
		}
	}()

	go func() {
		wg.Wait()
		_ = local.Close()
		_ = remote.Close()
	}()
}
