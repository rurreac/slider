package server

import (
	"flag"
	"fmt"
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

func (c *Console) PrintlnDebugStep(m string, args ...interface{}) {
	msg := fmt.Sprintf(m, args...)
	c.Output.Printf(
		"\r[%s*%s] %s\r\n",
		blueBrightBold,
		resetColor,
		msg,
	)
}

func (c *Console) PrintlnWarnStep(m string, args ...interface{}) {
	msg := fmt.Sprintf(m, args...)
	c.Output.Printf(
		"\r[%s!%s] %s\r\n",
		yellowBright,
		resetColor,
		msg,
	)
}

func (c *Console) PrintlnErrorStep(m string, args ...interface{}) {
	msg := fmt.Sprintf(m, args...)
	c.Output.Printf(
		"\r[%s-%s] %s\r\n",
		redBold,
		resetColor,
		msg,
	)
}

func (c *Console) PrintlnOkStep(m string, args ...interface{}) {
	msg := fmt.Sprintf(m, args...)
	c.Output.Printf(
		"\r[%s+%s] %s\r\n",
		greenBold,
		resetColor,
		msg,
	)
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
