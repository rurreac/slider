package server

const (
	// Console CyanBold Commands
	bgCmd    = "bg"
	bgDesc   = "Puts Console into background and returns to logging output"
	exitCmd  = "exit"
	exitDesc = "Exits Console and terminates the Server"
	helpCmd  = "help"
	helpDesc = "Shows this output"

	// Console Execute Command
	executeCmd   = "execute"
	executeDesc  = "Runs a command remotely and returns the output"
	executeUsage = "Usage: execute [flags] [command]"

	// Console Sessions Command
	sessionsCmd   = "sessions"
	sessionsDesc  = "Interacts with Client Sessions"
	sessionsUsage = "When run without parameters, all available Sessions are listed." +
		"\n\n\rUsage: sessions [flags]"

	// Console Socks Command
	socksCmd   = "socks"
	socksDesc  = "Creates a TCP Endpoint bound to a client SOCKSv5 server"
	socksUsage = "Usage: socks [flags]"

	// Console SSH Command
	sshCmd   = "ssh"
	sshDesc  = "Creates an SSH Endpoint that binds to a client"
	sshUsage = "Usage: ssh [flags]"

	// Console Shell Command
	shellCmd   = "shell"
	shellDesc  = "Binds to a client Shell"
	shellUsage = "Usage: shell [flags]"

	// Console Cert Command
	certsCmd   = "certs"
	certsDesc  = "Interacts with the Server Certificate Jar"
	certsUsage = "When run without parameters, all available Slider key pairs are listed." +
		"\n\n\rUsage: certs [flags]"

	// Console Client Connect Command
	connectCmd   = "connect"
	connectDesc  = "Receives the address of a Client to connect to"
	connectUsage = "Usage: connect [flags] <[client_address]:port>"

	// Console Port Forwarding Command
	portFwdCmd   = "portfwd"
	portFwdDesc  = "Creates a port forwarding tunnel to / from a client"
	portFwdUsage = "Usage: portfwd [flags] <[addressA]:portA:[addressB]:portB>"
)

func (s *server) initRegistry() {
	s.commandRegistry = NewCommandRegistry()
	s.commandRegistry.Register(&BgCommand{})
	s.commandRegistry.Register(&ExitCommand{})
	s.commandRegistry.Register(&HelpCommand{})
	s.commandRegistry.Register(&ExecuteCommand{})
	s.commandRegistry.Register(&SessionsCommand{})
	s.commandRegistry.Register(&SocksCommand{})
	s.commandRegistry.Register(&SSHCommand{})
	s.commandRegistry.Register(&ConnectCommand{})
	s.commandRegistry.Register(&ShellCommand{})
	s.commandRegistry.Register(&PortFwdCommand{})
	if s.authOn {
		s.commandRegistry.Register(&CertsCommand{})
	}
	// Register other commands here as they are refactored
}
