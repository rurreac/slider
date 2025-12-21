package remote

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slider/pkg/instance"
	"slider/pkg/interpreter"
	"slider/pkg/slog"
	"slider/pkg/types"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// HandleSession handles the "session" SSH channel
func HandleSession(nc ssh.NewChannel, sess Session, srv Server) error {
	sshChan, chanReq, err := nc.Accept()
	if err != nil {
		sess.GetLogger().DErrorWith(
			"Failed to accept the session channel",
			slog.F("session_id", sess.GetID()),
			slog.F("err", err),
		)
		return err
	}
	sess.AddSessionChannel(sshChan)
	sess.GetLogger().DebugWith(
		"Accepted SSH Channel Connection",
		slog.F("session_id", sess.GetID()),
		slog.F("channel_type", nc.ChannelType()),
	)

	// Note: handleChanRequests is still on the server side or handled via session
	// For now, we expect the caller to handle the requests if we don't have a common way.
	// But actually, we should probably handle them here or provide a handler.
	// In the original code, it was: go s.handleChanRequests(session, chanReq)
	// We'll need a way for the handler to process requests.
	go handleChanRequests(sess, chanReq)
	return nil
}

// handleChanRequests processes channel requests for a session
func handleChanRequests(sess Session, chanReq <-chan *ssh.Request) {
	for r := range chanReq {
		ok := false
		switch r.Type {
		case "pty-req":
			ok = true
			// Note: session.rawTerm is unexported. We might need a setter.
			// For now, we'll assume it's set via a method if needed.
			// sess.SetRawTerm(true)
			_ = replyConnRequest(sess, r, ok, nil)
			sess.GetLogger().DebugWith("Client Requested Raw Terminal",
				slog.F("session_id", sess.GetID()),
			)
		case "reverse-shell":
			ok = true
			_ = replyConnRequest(sess, r, ok, nil)
			sess.GetLogger().DebugWith("Client will send Reverse Shell",
				slog.F("session_id", sess.GetID()),
			)
			return
		default:
			_ = replyConnRequest(sess, r, ok, nil)
			sess.GetLogger().DebugWith("Unknown channel request",
				slog.F("session_id", sess.GetID()),
				slog.F("request_type", r.Type),
			)
			return
		}
	}
}

// replyConnRequest is a helper to reply to connection requests
func replyConnRequest(sess Session, request *ssh.Request, ok bool, payload []byte) error {
	var pMsg string
	if len(payload) != 0 {
		pMsg = fmt.Sprintf("%v", payload)
	}
	sess.GetLogger().DebugWith("Replying Connection Request",
		slog.F("session_id", sess.GetID()),
		slog.F("request_type", request.Type),
		slog.F("ok", ok),
		slog.F("payload", pMsg),
	)
	return request.Reply(ok, payload)
}

// HandleForwardedTcpIp handles "forwarded-tcpip" channels
func HandleForwardedTcpIp(nc ssh.NewChannel, sess Session, srv Server) error {
	go sess.HandleForwardedTcpIpChannel(nc)
	return nil
}

// HandleSftp handles "sftp" SSH channels
func HandleSftp(nc ssh.NewChannel, sess Session, srv Server) error {
	sshChan, chanReq, err := nc.Accept()
	if err != nil {
		sess.GetLogger().DErrorWith(
			"Failed to accept SFTP channel",
			slog.F("session_id", sess.GetID()),
			slog.F("err", err),
		)
		return err
	}
	go ssh.DiscardRequests(chanReq)

	go func() {
		// Serve SFTP
		opts := []sftp.ServerOption{}
		interp := srv.GetInterpreter()
		if interp != nil && interp.HomeDir != "" {
			opts = append(opts, sftp.WithServerWorkingDirectory(interp.HomeDir))
		}

		server, err := sftp.NewServer(sshChan, opts...)
		if err != nil {
			sess.GetLogger().DErrorWith("Failed to create SFTP server", slog.F("err", err))
			return
		}
		if err := server.Serve(); err != nil && err != io.EOF {
			sess.GetLogger().DErrorWith("SFTP server error", slog.F("err", err))
		}
		_ = server.Close()
	}()
	return nil
}

// HandleInitSize handles "init-size" SSH channels
func HandleInitSize(nc ssh.NewChannel, sess Session, _ Server) error {
	sshChan, chanReq, err := nc.Accept()
	if err != nil {
		return err
	}
	payload := nc.ExtraData()
	if len(payload) > 0 {
		var winSize types.TermDimensions
		if jErr := json.Unmarshal(payload, &winSize); jErr == nil {
			sess.SetInitTermSize(winSize)
		}
	}
	go ssh.DiscardRequests(chanReq)
	_ = sshChan.Close()
	return nil
}

// HandleShell handles "shell" SSH channels
func HandleShell(nc ssh.NewChannel, sess Session, srv Server) error {
	sshChan, chanReq, err := nc.Accept()
	if err != nil {
		sess.GetLogger().DErrorWith("Failed to accept shell channel", slog.F("err", err))
		return err
	}
	sess.AddSessionChannel(sshChan)

	go func() {
		interp := srv.GetInterpreter()
		var envVars []string
		var startOnce sync.Once
		startChan := make(chan struct{}, 1)

		// Determine initial size
		rows, cols := uint32(24), uint32(80)
		initSize := sess.GetInitTermSize()
		if initSize.Width != 0 {
			cols = initSize.Width
		}
		if initSize.Height != 0 {
			rows = initSize.Height
		}

		var ptyF interpreter.Pty
		var ptyMutex sync.Mutex

		// Handle requests first
		go func() {
			for req := range chanReq {
				ok := false
				switch req.Type {
				case "window-change":
					if len(req.Payload) >= 8 {
						c, r := instance.ParseSizePayload(req.Payload)
						ptyMutex.Lock()
						if ptyF != nil {
							_ = ptyF.Resize(c, r)
						} else {
							cols, rows = c, r
						}
						ptyMutex.Unlock()
						ok = true
					}
				case "env":
					var kv struct{ Key, Value string }
					if err := ssh.Unmarshal(req.Payload, &kv); err == nil {
						if kv.Key == "SLIDER_ENV" && kv.Value == "true" {
							startOnce.Do(func() { close(startChan) })
							ok = true
						} else {
							envVars = append(envVars, fmt.Sprintf("%s=%s", kv.Key, kv.Value))
							ok = true
						}
					}
				}
				if req.WantReply {
					_ = req.Reply(ok, nil)
				}
			}
			// Connection closed, make sure we trigger start if not started
			startOnce.Do(func() { close(startChan) })
		}()

		// Wait for SLIDER_ENV or timeout
		select {
		case <-startChan:
		case <-time.After(2 * time.Second):
			startOnce.Do(func() { close(startChan) })
		}

		// Determine shell command and args
		shellCmd := "/bin/sh"
		var shellArgs []string
		if interp != nil {
			if interp.Shell != "" {
				shellCmd = interp.Shell
			}
			shellArgs = interp.ShellArgs
		}

		sess.GetLogger().DebugWith("Starting shell process",
			slog.F("cmd", shellCmd),
			slog.F("args", shellArgs),
			slog.F("cols", cols),
			slog.F("rows", rows),
			slog.F("env_count", len(envVars)))

		cmd := exec.Command(shellCmd, shellArgs...)
		// Do not use os.Environ() to avoid leaking parent console handles or sensitive env vars
		// Only pass the collected env vars and a default PATH if needed
		cmd.Env = envVars
		if len(cmd.Env) == 0 {
			cmd.Env = os.Environ()
		}

		if interp != nil && interp.System != "windows" {
			cmd.Env = append(cmd.Env, "TERM=xterm")
		}

		ptyMutex.Lock()
		var pErr error
		ptyF, pErr = interpreter.StartPty(cmd, cols, rows)
		ptyMutex.Unlock()

		if pErr != nil {
			sess.GetLogger().ErrorWith("Failed to start PTY for shell channel", slog.F("err", pErr))
			_ = sshChan.Close()
			return
		}

		// Use a channel to signal when PTY process exits
		ptyDone := make(chan struct{})

		// Wait for process in background and close PTY to break the data pipe
		go func() {
			if ptyF != nil {
				waitErr := ptyF.Wait()
				if waitErr != nil {
					sess.GetLogger().DebugWith("Shell process exited with error",
						slog.F("session_id", sess.GetID()),
						slog.F("err", waitErr))
				} else {
					sess.GetLogger().DebugWith("Shell process exited normally", slog.F("session_id", sess.GetID()))
				}
				_ = ptyF.Close()
				close(ptyDone)
			}
		}()

		sess.GetLogger().DebugWith("Piping I/O for shell channel", slog.F("session_id", sess.GetID()))

		var wg sync.WaitGroup
		wg.Add(2)

		// Copy from PTY to SSH channel
		go func() {
			defer wg.Done()
			_, copyErr := io.Copy(sshChan, ptyF)
			if copyErr != nil && copyErr != io.EOF {
				sess.GetLogger().DebugWith("Error copying from PTY to SSH",
					slog.F("session_id", sess.GetID()),
					slog.F("err", copyErr))
			}
			// When PTY output is done, send EOF to SSH channel
			_ = sshChan.CloseWrite()
		}()

		// Copy from SSH channel to PTY
		go func() {
			defer wg.Done()
			_, copyErr := io.Copy(ptyF, sshChan)
			if copyErr != nil && copyErr != io.EOF {
				sess.GetLogger().DebugWith("Error copying from SSH to PTY",
					slog.F("session_id", sess.GetID()),
					slog.F("err", copyErr))
			}
		}()

		wg.Wait()
		<-ptyDone // Ensure PTY cleanup is complete
		sess.GetLogger().DebugWith("Shell I/O piping completed", slog.F("session_id", sess.GetID()))
		_ = sshChan.Close()
	}()
	return nil
}

// HandleSliderConnect handles "slider-connect" SSH channels
func HandleSliderConnect(nc ssh.NewChannel, sess Session, srv Server) error {
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
		return routeToLocal(nc, sess, srv, &req)
	}

	return routeToNextHop(nc, sess, srv, &req)
}

func routeToLocal(nc ssh.NewChannel, sess Session, srv Server, req *ConnectRequest) error {
	channelType := req.ChannelType
	if channelType == "" {
		channelType = "sftp"
	}

	switch channelType {
	case "sftp":
		sshChan, reqs, err := nc.Accept()
		if err != nil {
			return err
		}
		go ssh.DiscardRequests(reqs)
		go func() {
			opts := []sftp.ServerOption{}
			interp := srv.GetInterpreter()
			if interp != nil && interp.HomeDir != "" {
				opts = append(opts, sftp.WithServerWorkingDirectory(interp.HomeDir))
			}
			sftpSrv, err := sftp.NewServer(sshChan, opts...)
			if err != nil {
				return
			}
			_ = sftpSrv.Serve()
			_ = sftpSrv.Close()
		}()
		return nil
	case "shell":
		return HandleShell(nc, sess, srv)
	default:
		_ = nc.Reject(ssh.ConnectionFailed, "unsupported channel type for server")
		return fmt.Errorf("unsupported channel type: %s", channelType)
	}
}

func routeToNextHop(nc ssh.NewChannel, sess Session, srv Server, req *ConnectRequest) error {
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

	// 1. Next hop is a standard client session
	if nextHopSession.GetSSHClient() == nil {
		channelType := req.ChannelType
		if channelType == "" {
			channelType = "sftp"
		}

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

	// 2. Next hop is a promiscuous client (Server)
	if nextHopSession.GetSSHClient() != nil {
		if len(remainingTarget) == 0 {
			channelType := req.ChannelType
			if channelType == "" {
				channelType = "sftp"
			}

			targetChan, reqs, err := nextHopSession.GetSSHClient().OpenChannel(channelType, req.Payload)
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

		// Recursively forward
		fwdReq := ConnectRequest{
			Target:      remainingTarget,
			ChannelType: req.ChannelType,
			Payload:     req.Payload,
		}
		fwdPayload, _ := json.Marshal(fwdReq)

		targetChan, reqs, err := nextHopSession.GetSSHClient().OpenChannel("slider-connect", fwdPayload)
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
