package server

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

var (
	// ErrExitConsole indicates the console should exit
	ErrExitConsole = errors.New("exit console")
	// ErrBackgroundConsole indicates the console should go to background
	ErrBackgroundConsole = errors.New("background console")
)

// ExecutionContext provides execution environment for commands
type ExecutionContext struct {
	server  *server
	session *Session // nil for non-session commands
	ui      UserInterface
}

// Server returns the server instance
func (c *ExecutionContext) getServer() *server {
	return c.server
}

// Session returns the session instance (may be nil)
func (c *ExecutionContext) Session() *Session {
	return c.session
}

// UI returns the user interface
func (c *ExecutionContext) UI() UserInterface {
	return c.ui
}

// RequireSession returns session or error if nil
func (c *ExecutionContext) RequireSession() (*Session, error) {
	if c.session == nil {
		return nil, fmt.Errorf("command requires an active session")
	}
	return c.session, nil
}

// Command interface defines the structure for all console commands
type Command interface {
	Name() string
	Description() string
	Usage() string
	Run(ctx *ExecutionContext, args []string) error
	IsRemoteCompletion() bool
}

// CommandRegistry holds the registered commands
type CommandRegistry struct {
	commands map[string]Command
	aliases  map[string][]string // Maps command name to its aliases
}

// NewCommandRegistry creates a new CommandRegistry
func NewCommandRegistry() *CommandRegistry {
	return &CommandRegistry{
		commands: make(map[string]Command),
		aliases:  make(map[string][]string),
	}
}

// Register adds a command to the registry
func (r *CommandRegistry) Register(cmd Command) {
	r.commands[cmd.Name()] = cmd
	r.aliases[cmd.Name()] = []string{cmd.Name()} // Primary name is first alias
}

// RegisterAlias adds an alias for an existing command
func (r *CommandRegistry) RegisterAlias(alias, commandName string) {
	if cmd, ok := r.commands[commandName]; ok {
		r.commands[alias] = cmd
		r.aliases[commandName] = append(r.aliases[commandName], alias)
	}
}

// initRegistry initializes the command registry. Commands will be unavailable until registered
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

// Get retrieves a command by name
func (r *CommandRegistry) Get(name string) (Command, bool) {
	cmd, ok := r.commands[name]
	return cmd, ok
}

// List returns a sorted list of command names
func (r *CommandRegistry) List() []string {
	var names []string
	for name := range r.commands {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Execute runs a command with the given context
func (r *CommandRegistry) Execute(ctx *ExecutionContext, name string, args []string) error {
	if cmd, ok := r.commands[name]; ok {
		return cmd.Run(ctx, args)
	}
	return fmt.Errorf("unknown command: %s", name)
}

// GetPrimaryCommands returns a map of primary command names to their aliases
func (r *CommandRegistry) GetPrimaryCommands() map[string][]string {
	return r.aliases
}

// Autocomplete suggests commands based on input
func (r *CommandRegistry) Autocomplete(input string) (string, int) {
	var cmd string
	var substring string
	var count int

	cmdList := r.List()
	for _, c := range cmdList {
		if strings.HasPrefix(c, input) {
			cmd = c
			substring = strings.SplitAfter(c, input)[0]
			count++
		} else if count == 1 {
			return cmd, len(cmd)
		}
	}

	if count == 1 {
		return cmd, len(cmd)
	}

	if count == 0 {
		substring = input
	}

	return substring, len(substring)
}

// BaseCommand is a helper struct to embed in commands to avoid implementing all methods if not needed
// (Though currently all methods are needed, this is just a placeholder for future extensibility)
type BaseCommand struct{}

// Compile-time check to ensure Console implements UserInterface
var _ UserInterface = (*Console)(nil)
