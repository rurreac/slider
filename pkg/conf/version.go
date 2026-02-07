package conf

import (
	"fmt"
	"os"
	"runtime"
	"text/tabwriter"
)

const Banner = `
  ███████╗██╗     ██╗██████╗ ███████╗██████╗ 
  ██╔════╝██║     ██║██╔══██╗██╔════╝██╔══██╗
  ███████╗██║     ██║██║  ██║█████╗  ██████╔╝
  ╚════██║██║     ██║██║  ██║██╔══╝  ██╔══██╗
  ███████║███████╗██║██████╔╝███████╗██║  ██║
  ╚══════╝╚══════╝╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝`

var (
	Version = "development"
	Proto   = "slider-v2"
	binOS   = runtime.GOOS
	binArch = runtime.GOARCH
	commit  = "undefined"
	date    = "undefined"
	goVer   = "undefined"
)

func PrintVersion() {
	fmt.Printf("%s\n\n", Banner)
	twl := new(tabwriter.Writer)
	twl.Init(os.Stdout, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintf(twl, "\tVersion:\t%s\t\n", Version)
	_, _ = fmt.Fprintf(twl, "\tProto:\t%s\t\n", Proto)
	_, _ = fmt.Fprintf(twl, "\tTarget System:\t%s/%s\t\n", binOS, binArch)
	_, _ = fmt.Fprintf(twl, "\tGit Commit:\t%s\t\n", commit)
	_, _ = fmt.Fprintf(twl, "\tRelease Date:\t%s\t\n", date)
	_, _ = fmt.Fprintf(twl, "\tGo Version:\t%s\t\n\n\n", goVer)
	_ = twl.Flush()
}
