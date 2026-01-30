package conf

// Standard SSH Channel Types
const (
	SSHChannelSession        = "session"
	SSHChannelDirectTCPIP    = "direct-tcpip"
	SSHChannelForwardedTCPIP = "forwarded-tcpip"
)

// Standard SSH Request Types
const (
	SSHRequestExec               = "exec"
	SSHRequestShell              = "shell"
	SSHRequestSubsystem          = "subsystem"
	SSHRequestPTY                = "pty-req"
	SSHRequestWindowChange       = "window-change"
	SSHRequestEnv                = "env"
	SSHRequestExitStatus         = "exit-status"
	SSHRequestExitSignal         = "exit-signal"
	SSHRequestKeepAlive          = "keep-alive"
	SSHRequestTcpIpForward       = "tcpip-forward"
	SSHRequestCancelTcpIpForward = "cancel-tcpip-forward"
)

// Slider Specific Channel Types
const (
	SSHChannelSFTP          = "sftp"
	SSHChannelSocks5        = "socks5"
	SSHChannelInitSize      = "init-size" // payload: json.Marshal(types.TermDimensions)
	SSHChannelSliderConnect = "slider-connect"
	SSHChannelSliderBeacon  = "slider-beacon"
)

// Slider Specific Request Types
const (
	SSHRequestClientInfo     = "client-info"            // payload: json.Marshal(interpreter.Info)
	SSHRequestWindowSize     = "window-size"            // payload: json.Marshal(types.TermDimensions)
	SSHRequestSliderSessions = "slider-sessions"        // payload: json.Marshal(GetRemoteSessionsRequest)
	SSHRequestSliderForward  = "slider-forward-request" // payload: json.Marshal(types.ForwardRequestPayload)
	SSHRequestSliderEvent    = "slider-event"           // payload: json.Marshal(eventRequest)
	SSHRequestShutdown       = "shutdown"
)
