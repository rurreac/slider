package server

import (
	"flag"
	"fmt"
	"strings"
)

func (c *Console) PrintlnWarn(m string, args ...interface{}) {
	msg := fmt.Sprintf(m, args...)
	c.Output.Printf(
		"\r%s%s%s\r\n",
		string(c.Term.Escape.Yellow),
		msg,
		string(c.Term.Escape.Reset),
	)
}

func (c *Console) PrintWarnSelect(selected string, args ...string) {
	msg := fmt.Sprintf("%s%s%s",
		string(c.Term.Escape.Yellow),
		selected,
		string(c.Term.Escape.Reset))
	c.Output.Printf("\r%s%s\r\n", msg, strings.Join(args, " "))
}

func (c *Console) PrintlnInfoStep(m string, args ...interface{}) {
	msg := fmt.Sprintf(m, args...)
	c.Output.Printf(
		"\r[%s*%s] %s\r\n",
		string(c.Term.Escape.Blue),
		string(c.Term.Escape.Reset),
		msg,
	)
}

func (c *Console) PrintlnErrorStep(m string, args ...interface{}) {
	msg := fmt.Sprintf(m, args...)
	c.Output.Printf(
		"\r[%s!%s] %s\r\n",
		string(c.Term.Escape.Red),
		string(c.Term.Escape.Reset),
		msg,
	)
}

func (c *Console) PrintlnOkStep(m string, args ...interface{}) {
	msg := fmt.Sprintf(m, args...)
	c.Output.Printf(
		"\r[%s+%s] %s\r\n",
		string(c.Term.Escape.Green),
		string(c.Term.Escape.Reset),
		msg,
	)
}

func (c *Console) Println(m string) {
	c.Output.Printf("\r%s\n", m)
}

func (c *Console) Printf(m string, args ...interface{}) {
	c.Output.Printf("\r"+m+"\r\n", args...)
}

func (c *Console) PrintCommandUsage(f *flag.FlagSet, h string) {
	c.Output.Printf(h)
	f.PrintDefaults()
	c.Output.Printf("\n")
}
