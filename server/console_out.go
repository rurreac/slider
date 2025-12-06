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

func (c *Console) PrintlnWarn(m string, args ...any) {
	msg := fmt.Sprintf(m, args...)
	_, _ = fmt.Fprintf(c.Term, "\r%s\r\n", escseq.YellowText(msg))
}

func (c *Console) PrintlnGreyOut(m string, args ...any) {
	msg := fmt.Sprintf(m, args...)
	_, _ = fmt.Fprintf(c.Term, "\r%s\r\n", escseq.GreyBoldText(msg))
}

func (c *Console) clearScreen() {
	_, _ = fmt.Fprint(c.Term, escseq.ClearScreen())
}

func (c *Console) PrintWarnSelect(selected string, args ...string) {
	msg := fmt.Sprintf(escseq.YellowBrightText("%s"), selected)
	_, _ = fmt.Fprintf(c.Term, "\r%s%s\r\n", msg, strings.Join(args, " "))
}

// PrintInfo displays an informational message with [*] prefix
func (c *Console) PrintInfo(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	_, _ = fmt.Fprintf(c.Term, "\r[%s] %s\r\n", escseq.BlueBrightBoldText("*"), msg)
}

// PrintWarn displays a warning message with [!] prefix
func (c *Console) PrintWarn(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	_, _ = fmt.Fprintf(c.Term, "\r[%s] %s\r\n", escseq.YellowBrightText("!"), msg)
}

// PrintError displays an error message with [-] prefix
func (c *Console) PrintError(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	_, _ = fmt.Fprintf(c.Term, "\r[%s] %s\r\n", escseq.RedBoldText("-"), msg)
}

// PrintSuccess displays a success message with [+] prefix
func (c *Console) PrintSuccess(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	_, _ = fmt.Fprintf(c.Term, "\r[%s] %s\r\n", escseq.GreenBoldText("+"), msg)
}

// PrintDebug displays a debug message (alias for PrintInfo)
func (c *Console) PrintDebug(format string, args ...any) {
	c.PrintInfo(format, args...)
}

// Writer returns the underlying writer for structured output
func (c *Console) Writer() io.Writer {
	return c.Term
}

func (c *Console) Println(m string) {
	_, _ = fmt.Fprintf(c.Term, "\r%s\n", m)
}

func (c *Console) Printf(format string, args ...any) {
	_, _ = fmt.Fprintf(c.Term, "\r%s", fmt.Sprintf(format, args...))
}

func (c *Console) TermPrintf(format string, args ...any) {
	fmt.Printf(fmt.Sprintf("\r%s", format), args...)
}

func (c *Console) PrintCommandUsage(f *flag.FlagSet, h string) {
	_, _ = fmt.Fprintf(c.Term, "%s", h)
	f.PrintDefaults()
	_, _ = fmt.Fprintf(c.Term, "\n")
}
