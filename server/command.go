package server

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

var (
	// ErrExitConsole indicates the console should exit
	ErrExitConsole = errors.New("exit console")
	// ErrBackgroundConsole indicates the console should go to background
	ErrBackgroundConsole = errors.New("background console")
)

// Command interface defines the structure for all console commands
type Command interface {
	Name() string
	Description() string
	Usage() string
	// Run executes the command.
	// args: the arguments passed to the command
	// out: writer for command output (decoupling from direct console access)
	Run(s *server, args []string, out io.Writer) error
}

// CommandRegistry holds the registered commands
type CommandRegistry struct {
	commands map[string]Command
}

// NewCommandRegistry creates a new CommandRegistry
func NewCommandRegistry() *CommandRegistry {
	return &CommandRegistry{
		commands: make(map[string]Command),
	}
}

// Register adds a command to the registry
func (r *CommandRegistry) Register(cmd Command) {
	r.commands[cmd.Name()] = cmd
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

// Execute runs a command if found
func (r *CommandRegistry) Execute(s *server, name string, args []string, out io.Writer) error {
	if cmd, ok := r.commands[name]; ok {
		return cmd.Run(s, args, out)
	}
	return fmt.Errorf("unknown command: %s", name)
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
