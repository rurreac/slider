package conf

import (
	"fmt"
	"os"
	"runtime"
	"text/tabwriter"
)

const banner = `
  ███████╗██╗     ██╗██████╗ ███████╗██████╗ 
  ██╔════╝██║     ██║██╔══██╗██╔════╝██╔══██╗
  ███████╗██║     ██║██║  ██║█████╗  ██████╔╝
  ╚════██║██║     ██║██║  ██║██╔══╝  ██╔══██╗
  ███████║███████╗██║██████╔╝███████╗██║  ██║
  ╚══════╝╚══════╝╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝`

var (
	Version = "development"
	binOS   = runtime.GOOS
	binArch = runtime.GOARCH
	Commit  = "undefined"
	Date    = "undefined"
	GoVer   = "undefined"
)

func PrintVersion() {
	fmt.Printf("%s\n\n", banner)
	twl := new(tabwriter.Writer)
	twl.Init(os.Stdout, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintf(twl, "\tVersion:\t%s\t\n", Version)
	_, _ = fmt.Fprintf(twl, "\tSystem:\t%s/%s\t\n", binOS, binArch)
	_, _ = fmt.Fprintf(twl, "\tGit Commit:\t%s\t\n", Commit)
	_, _ = fmt.Fprintf(twl, "\tRelease Date:\t%s\t\n", Date)
	_, _ = fmt.Fprintf(twl, "\tGo Version:\t%s\t\n\n\n", GoVer)
	_ = twl.Flush()
}
