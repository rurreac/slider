package server

import (
	"flag"
	"fmt"
	"slider/pkg/colors"
	"slider/pkg/interpreter"
	"strings"
)

var (
	warnColor   = colors.Console.Warn
	debugColor  = colors.Console.Debug
	errorColor  = colors.Console.Error
	okColor     = colors.Console.Ok
	resetColor  = colors.ResetColor
	systemColor = colors.Console.System
	infoColor   = colors.Console.Info
	clearScreen = colors.Clear
	home        = colors.Home
	reset       = colors.Reset
)

func setConsoleColors() {
	if !interpreter.IsPtyOn() {
		warnColor = []byte{}
		debugColor = []byte{}
		errorColor = []byte{}
		okColor = []byte{}
		systemColor = []byte{}
		resetColor = []byte{}
	}
}

func getPrompt() string {
	return fmt.Sprintf("\rSlider%s>%s ", string(systemColor), string(resetColor))
}

func (c *Console) PrintlnWarn(m string, args ...interface{}) {
	msg := fmt.Sprintf(m, args...)
	fmt.Printf(
		"\r%s%s%s\r\n",
		string(warnColor),
		msg,
		string(resetColor),
	)
}

func (c *Console) PrintlnInfo(m string, args ...interface{}) {
	msg := fmt.Sprintf(m, args...)
	fmt.Printf(
		"\r%s%s%s\r\n",
		string(infoColor),
		msg,
		string(resetColor),
	)
}

func (c *Console) clearScreen() {
	fmt.Printf("%s%s", clearScreen, home)
}

func (c *Console) resetScreen() {
	fmt.Printf("%s", reset)
}

func (c *Console) PrintWarnSelect(selected string, args ...string) {
	msg := fmt.Sprintf("%s%s%s",
		string(warnColor),
		selected,
		string(resetColor))
	c.Output.Printf("\r%s%s\r\n", msg, strings.Join(args, " "))
}

func (c *Console) PrintlnDebugStep(m string, args ...interface{}) {
	msg := fmt.Sprintf(m, args...)
	c.Output.Printf(
		"\r[%s*%s] %s\r\n",
		string(debugColor),
		string(resetColor),
		msg,
	)
}

func (c *Console) PrintlnErrorStep(m string, args ...interface{}) {
	msg := fmt.Sprintf(m, args...)
	c.Output.Printf(
		"\r[%s-%s] %s\r\n",
		string(errorColor),
		string(resetColor),
		msg,
	)
}

func (c *Console) PrintlnOkStep(m string, args ...interface{}) {
	msg := fmt.Sprintf(m, args...)
	c.Output.Printf(
		"\r[%s+%s] %s\r\n",
		string(okColor),
		string(resetColor),
		msg,
	)
}

func (c *Console) Println(m string) {
	c.Output.Printf("\r%s\n", m)
}

func (c *Console) TermPrintln(format string, args ...interface{}) {
	_, _ = fmt.Fprintf(c.Term, fmt.Sprintf("\r%s", format), args...)
}

func (c *Console) PrintCommandUsage(f *flag.FlagSet, h string) {
	c.Output.Printf("%s", h)
	f.PrintDefaults()
	c.Output.Printf("\n")
}
