package sio

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"

	"slider/pkg/conf"
	"slider/pkg/slog"
	"slider/pkg/types"

	"golang.org/x/crypto/ssh"
)

// HandleForwardedUDPChannel handles incoming forwarded-udp SSH channels by establishing
// a bidirectional packet-based copy between the SSH channel and a local UDP connection.
// This is used by instance and session paths.
func HandleForwardedUDPChannel(
	nc ssh.NewChannel,
	logger *slog.Logger,
	sessionID int64,
	protocol string,
) error {
	var tcpIpMsg types.TcpIpChannelMsg
	customMsg := &types.CustomTcpIpChannelMsg{}

	// UDP reverse forward from client (always CustomTcpIpChannelMsg format)
	if jErr := json.Unmarshal(nc.ExtraData(), customMsg); jErr == nil && customMsg.TcpIpChannelMsg != nil {
		tcpIpMsg = *customMsg.TcpIpChannelMsg
	} else {
		logger.ErrorWith("Failed to unmarshal forwarded-udp data",
			slog.F("session_id", sessionID),
			slog.F("err", jErr))
		_ = nc.Reject(ssh.UnknownChannelType, "Failed to decode forwarded-udp data")
		return fmt.Errorf("failed to unmarshal forwarded-udp data: %w", jErr)
	}

	logger.DebugWith("Forwarded-udp channel request",
		slog.F("session_id", sessionID),
		slog.F("dst_host", tcpIpMsg.DstHost),
		slog.F("dst_port", tcpIpMsg.DstPort),
		slog.F("src_host", tcpIpMsg.SrcHost),
		slog.F("src_port", tcpIpMsg.SrcPort),
		slog.F("protocol", protocol))

	channel, requests, aErr := nc.Accept()
	if aErr != nil {
		logger.ErrorWith("Failed to accept forwarded-udp channel",
			slog.F("session_id", sessionID),
			slog.F("err", aErr))
		return fmt.Errorf("failed to accept channel: %w", aErr)
	}
	defer func() { _ = channel.Close() }()
	go ssh.DiscardRequests(requests)

	// Dial the local destination (Server side)
	dstHost := tcpIpMsg.DstHost
	dstPort := tcpIpMsg.DstPort
	host := net.JoinHostPort(dstHost, strconv.Itoa(int(dstPort)))

	udpConn, cErr := net.Dial(protocol, host)
	if cErr != nil {
		logger.ErrorWith("Failed to connect to local destination",
			slog.F("session_id", sessionID),
			slog.F("host", host),
			slog.F("protocol", protocol),
			slog.F("err", cErr))
		return fmt.Errorf("failed to dial %s: %w", host, cErr)
	}
	defer func() { _ = udpConn.Close() }()

	logger.DebugWith("Bridged forwarded-udp channel",
		slog.F("session_id", sessionID),
		slog.F("target", host),
		slog.F("protocol", protocol))

	// UDP requires packet-based copying, not stream piping
	done := make(chan struct{}, 2)

	// Channel -> UDP (forward traffic)
	go func() {
		defer func() {
			logger.DebugWith("Channel->UDP goroutine exiting",
				slog.F("session_id", sessionID))
			done <- struct{}{}
		}()
		buf := make([]byte, conf.MaxUDPPacketSize)
		for {
			n, rErr := channel.Read(buf)
			if rErr != nil {
				logger.DebugWith("Channel read error",
					slog.F("session_id", sessionID),
					slog.F("err", rErr))
				return
			}
			if n > 0 {
				logger.DebugWith("Forwarding packet Channel->UDP",
					slog.F("session_id", sessionID),
					slog.F("bytes", n))
				_, wErr := udpConn.Write(buf[:n])
				if wErr != nil {
					logger.ErrorWith("UDP write error",
						slog.F("session_id", sessionID),
						slog.F("err", wErr))
					return
				}
			}
		}
	}()

	// UDP -> Channel (return traffic)
	go func() {
		defer func() {
			logger.DebugWith("UDP->Channel goroutine exiting",
				slog.F("session_id", sessionID))
			done <- struct{}{}
		}()
		buf := make([]byte, conf.MaxUDPPacketSize)
		for {
			n, rErr := udpConn.Read(buf)
			if rErr != nil {
				logger.DebugWith("UDP read error",
					slog.F("session_id", sessionID),
					slog.F("err", rErr))
				return
			}
			if n > 0 {
				logger.DebugWith("Forwarding packet UDP->Channel",
					slog.F("session_id", sessionID),
					slog.F("bytes", n))
				_, wErr := channel.Write(buf[:n])
				if wErr != nil {
					logger.ErrorWith("Channel write error",
						slog.F("session_id", sessionID),
						slog.F("err", wErr))
					return
				}
			}
		}
	}()

	// Wait for either direction to close
	<-done
	logger.DebugWith("UDP channel handler completing",
		slog.F("session_id", sessionID))
	return nil
}
