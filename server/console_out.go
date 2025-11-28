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
	yellowBright   = string(escseq.YellowBright)
	yellow         = string(escseq.Yellow)
	blueBrightBold = string(escseq.BlueBrightBold)
	redBrightBold  = string(escseq.RedBrightBold)
	greenBold      = string(escseq.GreenBold)
	cyanBold       = string(escseq.CyanBold)
	greyBold       = string(escseq.GreyBold)
	resetColor     = string(escseq.ResetColor)
	eraseLine      = string(escseq.EraseLine)
	eraseScreen    = string(escseq.EraseScreen)
	cursorClear    = string(escseq.CursorClear)
	cursorUp       = string(escseq.CursorUp)
	cursorHome     = string(escseq.CursorHome)
)

func setConsoleColors() {
	if !interpreter.IsPtyOn() {
		yellowBright = ""
		yellow = ""
		blueBrightBold = ""
		redBrightBold = ""
		greenBold = ""
		cyanBold = ""
		greyBold = ""
		resetColor = ""
		cursorClear = ""
		cursorUp = ""
		cursorHome = "\n"
	}
}

func yellowText(m string) string {
	return fmt.Sprintf("%s%s%s", yellow, m, resetColor)
}

func yellowBrightText(m string) string {
	return fmt.Sprintf("%s%s%s", yellowBright, m, resetColor)
}

func greyBoldText(m string) string {
	return fmt.Sprintf("%s%s%s", greyBold, m, resetColor)
}

func redBoldText(m string) string {
	return fmt.Sprintf("%s%s%s", redBrightBold, m, resetColor)
}

func greenBoldText(m string) string {
	return fmt.Sprintf("%s%s%s", greenBold, m, resetColor)
}

func cyanBoldText(m string) string {
	return fmt.Sprintf("%s%s%s", cyanBold, m, resetColor)
}

func blueBrightBoldText(m string) string {
	return fmt.Sprintf("%s%s%s", blueBrightBold, m, resetColor)
}

func blinkText(m string) string {
	return fmt.Sprintf("%s%s%s", escseq.Blink, m, escseq.ResetBlink)
}

func getPrompt() string {
	return fmt.Sprintf("\rSlider%s ", cyanBoldText("#"))
}

func (c *Console) PrintlnWarn(m string, args ...interface{}) {
	msg := fmt.Sprintf(m, args...)
	_, _ = fmt.Printf(yellowText("\r%s%s%s\r\n"), msg)
}

func (c *Console) PrintlnInfo(m string, args ...interface{}) {
	msg := fmt.Sprintf(m, args...)
	_, _ = fmt.Printf(greyBoldText("\r%s%s%s\r\n"), msg)
}

func (c *Console) clearScreen() {
	_, _ = fmt.Printf("%s%s", eraseScreen, cursorHome)
}

func (c *Console) PrintWarnSelect(selected string, args ...string) {
	msg := fmt.Sprintf(yellowBrightText("%s"), selected)
	_, _ = fmt.Fprintf(c.Term, "\r%s%s\r\n", msg, strings.Join(args, " "))
}

// PrintInfo displays an informational message with [*] prefix
func (c *Console) PrintInfo(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	_, _ = fmt.Fprintf(c.Term, "\r[%s] %s\r\n", blueBrightBoldText("*"), msg)
}

// PrintWarn displays a warning message with [!] prefix
func (c *Console) PrintWarn(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	_, _ = fmt.Fprintf(c.Term, "\r[%s] %s\r\n", yellowBrightText("!"), msg)
}

// PrintError displays an error message with [-] prefix
func (c *Console) PrintError(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	_, _ = fmt.Fprintf(c.Term, "\r[%s] %s\r\n", redBoldText("-"), msg)
}

// PrintSuccess displays a success message with [+] prefix
func (c *Console) PrintSuccess(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	_, _ = fmt.Fprintf(c.Term, "\r[%s] %s\r\n", greenBoldText("+"), msg)
}

// PrintDebug displays a debug message (alias for PrintInfo)
func (c *Console) PrintDebug(format string, args ...interface{}) {
	c.PrintInfo(format, args...)
}

// Writer returns the underlying writer for structured output
func (c *Console) Writer() io.Writer {
	return c.Term
}

func (c *Console) Println(m string) {
	_, _ = fmt.Fprintf(c.Term, "\r%s\n", m)
}

func (c *Console) Printf(format string, args ...interface{}) {
	_, _ = fmt.Fprintf(c.Term, "\r%s", fmt.Sprintf(format, args...))
}

func (c *Console) TermPrintf(format string, args ...interface{}) {
	fmt.Printf(fmt.Sprintf("\r%s", format), args...)
}

func (c *Console) PrintCommandUsage(f *flag.FlagSet, h string) {
	_, _ = fmt.Fprintf(c.Term, "%s", h)
	f.PrintDefaults()
	_, _ = fmt.Fprintf(c.Term, "\n")
}
