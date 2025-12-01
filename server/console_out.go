package server

import (
	"flag"
	"fmt"
	"io"
	"slider/pkg/escseq"
	"strings"
)

func getPrompt() string {
	return fmt.Sprintf("\rSlider%s ", escseq.CyanBoldText("#"))
}

func (c *Console) PrintlnWarn(m string, args ...interface{}) {
	msg := fmt.Sprintf(m, args...)
	_, _ = fmt.Printf(escseq.YellowText("\r%s%s%s\r\n"), msg)
}

func (c *Console) PrintlnInfo(m string, args ...interface{}) {
	msg := fmt.Sprintf(m, args...)
	_, _ = fmt.Printf(escseq.GreyBoldText("\r%s%s%s\r\n"), msg)
}

func (c *Console) clearScreen() {
	_, _ = fmt.Printf("%s", escseq.ClearScreen())
}

func (c *Console) PrintWarnSelect(selected string, args ...string) {
	msg := fmt.Sprintf(escseq.YellowBrightText("%s"), selected)
	_, _ = fmt.Fprintf(c.Term, "\r%s%s\r\n", msg, strings.Join(args, " "))
}

// PrintInfo displays an informational message with [*] prefix
func (c *Console) PrintInfo(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	_, _ = fmt.Fprintf(c.Term, "\r[%s] %s\r\n", escseq.BlueBrightBoldText("*"), msg)
}

// PrintWarn displays a warning message with [!] prefix
func (c *Console) PrintWarn(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	_, _ = fmt.Fprintf(c.Term, "\r[%s] %s\r\n", escseq.YellowBrightText("!"), msg)
}

// PrintError displays an error message with [-] prefix
func (c *Console) PrintError(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	_, _ = fmt.Fprintf(c.Term, "\r[%s] %s\r\n", escseq.RedBoldText("-"), msg)
}

// PrintSuccess displays a success message with [+] prefix
func (c *Console) PrintSuccess(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	_, _ = fmt.Fprintf(c.Term, "\r[%s] %s\r\n", escseq.GreenBoldText("+"), msg)
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
