package server

import (
	"flag"
	"fmt"
	"slider/pkg/colors"
	"strings"
)

func (c *Console) PrintlnWarn(m string, args ...interface{}) {
	msg := fmt.Sprintf(m, args...)
	c.Output.Printf(
		"\r%s%s%s\r\n",
		string(colors.Console.Warn),
		msg,
		string(colors.Reset),
	)
}

func (c *Console) PrintWarnSelect(selected string, args ...string) {
	msg := fmt.Sprintf("%s%s%s",
		string(colors.Console.Warn),
		selected,
		string(colors.Reset))
	c.Output.Printf("\r%s%s\r\n", msg, strings.Join(args, " "))
}

func (c *Console) PrintlnDebugStep(m string, args ...interface{}) {
	msg := fmt.Sprintf(m, args...)
	c.Output.Printf(
		"\r[%s*%s] %s\r\n",
		string(colors.Console.Debug),
		string(colors.Reset),
		msg,
	)
}

func (c *Console) PrintlnErrorStep(m string, args ...interface{}) {
	msg := fmt.Sprintf(m, args...)
	c.Output.Printf(
		"\r[%s-%s] %s\r\n",
		string(colors.Console.Error),
		string(colors.Reset),
		msg,
	)
}

func (c *Console) PrintlnOkStep(m string, args ...interface{}) {
	msg := fmt.Sprintf(m, args...)
	c.Output.Printf(
		"\r[%s+%s] %s\r\n",
		string(colors.Console.Ok),
		string(colors.Reset),
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
	c.Output.Printf("%s", h)
	f.PrintDefaults()
	c.Output.Printf("\n")
}
