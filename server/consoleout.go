package server

import (
	"flag"
	"fmt"
	"io"
	"slider/pkg/escseq"
	"slider/pkg/interpreter"
	"strings"
)

var (
	yellowBright   = string(escseq.Console.YellowBright)
	yellow         = string(escseq.Console.Yellow)
	blueBrightBold = string(escseq.Console.BlueBrightBold)
	redBold        = string(escseq.Console.RedBold)
	greenBold      = string(escseq.Console.GreenBold)
	cyanBold       = string(escseq.Console.CyanBold)
	greyBold       = string(escseq.Console.GreyBold)
	resetColor     = string(escseq.ResetColor)
	cursorClear    = string(escseq.CursorClear)
	cursorHome     = string(escseq.CursorHome)
)

func setConsoleColors() {
	if !interpreter.IsPtyOn() {
		yellowBright = ""
		yellow = ""
		blueBrightBold = ""
		redBold = ""
		greenBold = ""
		cyanBold = ""
		greyBold = ""
		resetColor = ""
		cursorClear = ""
		cursorHome = "\n"
	}
}

func getPrompt() string {
	return fmt.Sprintf("\rSlider%s#%s ", cyanBold, resetColor)
}

func (c *Console) PrintlnWarn(m string, args ...interface{}) {
	msg := fmt.Sprintf(m, args...)
	fmt.Printf(
		"\r%s%s%s\r\n",
		yellow,
		msg,
		resetColor,
	)
}

func (c *Console) PrintlnInfo(m string, args ...interface{}) {
	msg := fmt.Sprintf(m, args...)
	fmt.Printf(
		"\r%s%s%s\r\n",
		greyBold,
		msg,
		resetColor,
	)
}

func (c *Console) clearScreen() {
	fmt.Printf("%s%s", cursorClear, cursorHome)
}

func (c *Console) PrintWarnSelect(selected string, args ...string) {
	msg := fmt.Sprintf("%s%s%s",
		yellowBright,
		selected,
		resetColor)
	c.Output.Printf("\r%s%s\r\n", msg, strings.Join(args, " "))
}

// UserInterface implementation - new interface methods

// PrintInfo displays an informational message with [*] prefix
func (c *Console) PrintInfo(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	c.Output.Printf(
		"\r[%s*%s] %s\r\n",
		blueBrightBold,
		resetColor,
		msg,
	)
}

// PrintWarn displays a warning message with [!] prefix
func (c *Console) PrintWarn(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	c.Output.Printf(
		"\r[%s!%s] %s\r\n",
		yellowBright,
		resetColor,
		msg,
	)
}

// PrintError displays an error message with [-] prefix
func (c *Console) PrintError(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	c.Output.Printf(
		"\r[%s-%s] %s\r\n",
		redBold,
		resetColor,
		msg,
	)
}

// PrintSuccess displays a success message with [+] prefix
func (c *Console) PrintSuccess(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	c.Output.Printf(
		"\r[%s+%s] %s\r\n",
		greenBold,
		resetColor,
		msg,
	)
}

// PrintDebug displays a debug message (alias for PrintInfo)
func (c *Console) PrintDebug(format string, args ...interface{}) {
	c.PrintInfo(format, args...)
}

// Writer returns the underlying writer for structured output
func (c *Console) Writer() io.Writer {
	return c.Term
}

// Deprecated methods - kept temporarily for backward compatibility
// These will be removed in a follow-up PR

// Deprecated: Use PrintInfo instead
func (c *Console) PrintlnDebugStep(m string, args ...interface{}) {
	c.PrintInfo(m, args...)
}

// Deprecated: Use PrintWarn instead
func (c *Console) PrintlnWarnStep(m string, args ...interface{}) {
	c.PrintWarn(m, args...)
}

// Deprecated: Use PrintError instead
func (c *Console) PrintlnErrorStep(m string, args ...interface{}) {
	c.PrintError(m, args...)
}

// Deprecated: Use PrintSuccess instead
func (c *Console) PrintlnOkStep(m string, args ...interface{}) {
	c.PrintSuccess(m, args...)
}

func (c *Console) Println(m string) {
	c.Output.Printf("\r%s\n", m)
}

func (c *Console) Printf(format string, args ...interface{}) {
	c.Output.Printf(fmt.Sprintf("\r%s", format), args...)
}

func (c *Console) TermPrintf(format string, args ...interface{}) {
	fmt.Printf(fmt.Sprintf("\r%s", format), args...)
}

func (c *Console) PrintCommandUsage(f *flag.FlagSet, h string) {
	c.Output.Printf("%s", h)
	f.PrintDefaults()
	c.Output.Printf("\n")
}
