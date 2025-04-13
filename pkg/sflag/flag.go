package sflag

import (
	"flag"
	"fmt"
	"io"
	"text/tabwriter"
)

type FlagSetPack struct {
	Set            *flag.FlagSet
	cmdDescription string
	cmdUsage       string
	CmdAlias       []string
	flgInfo        []flagInfo
}

type flagInfo struct {
	shortFlag string
	longFlag  string
	defValue  string
	flagUsage string
}

func NewFlagPack(commands []string, usage string, description string, writerOut io.Writer) *FlagSetPack {
	flagSet := flag.NewFlagSet(commands[0], flag.ContinueOnError)
	flagSet.SetOutput(writerOut)
	return &FlagSetPack{
		Set:            flagSet,
		cmdUsage:       usage,
		cmdDescription: description,
		CmdAlias:       commands,
		flgInfo:        make([]flagInfo, 0),
	}
}

func (fsp *FlagSetPack) newFlag(shortFlag string, longFlag string, usage string, value any) (any, error) {
	switch value.(type) {
	case bool:
		holder := new(bool)
		*holder = value.(bool)
		if shortFlag == "" && longFlag == "" {
			return nil, fmt.Errorf("one of short flag or long flag is required")
		}
		if shortFlag != "" {
			fsp.Set.BoolVar(holder, shortFlag, value.(bool), usage)
		}
		if longFlag != "" {
			fsp.Set.BoolVar(holder, longFlag, value.(bool), usage)
		}
		fsp.flgInfo = append(fsp.flgInfo, flagInfo{shortFlag, longFlag, fmt.Sprintf("%v", value), usage})
		return holder, nil
	case string:
		holder := new(string)
		*holder = value.(string)
		if shortFlag == "" && longFlag == "" {
			return nil, fmt.Errorf("one of short flag or long flag is required")
		}
		if shortFlag != "" {
			fsp.Set.StringVar(holder, shortFlag, value.(string), usage)
		}
		if longFlag != "" {
			fsp.Set.StringVar(holder, longFlag, value.(string), usage)
		}
		fsp.flgInfo = append(fsp.flgInfo, flagInfo{shortFlag, longFlag, fmt.Sprintf("%v", value), usage})
		return holder, nil
	case int:
		holder := new(int)
		*holder = value.(int)
		if shortFlag == "" && longFlag == "" {
			return nil, fmt.Errorf("one of short flag or long flag is required")
		}
		if shortFlag != "" {
			fsp.Set.IntVar(holder, shortFlag, value.(int), usage)
		}
		if longFlag != "" {
			fsp.Set.IntVar(holder, longFlag, value.(int), usage)
		}
		fsp.flgInfo = append(fsp.flgInfo, flagInfo{shortFlag, longFlag, fmt.Sprintf("%v", value), usage})
		return holder, nil
	case int64:
		holder := new(int64)
		*holder = value.(int64)
		if shortFlag == "" && longFlag == "" {
			return nil, fmt.Errorf("one of short flag or long flag is required")
		}
		if shortFlag != "" {
			fsp.Set.Int64Var(holder, shortFlag, value.(int64), usage)
		}
		if longFlag != "" {
			fsp.Set.Int64Var(holder, longFlag, value.(int64), usage)
		}
		fsp.flgInfo = append(fsp.flgInfo, flagInfo{shortFlag, longFlag, fmt.Sprintf("%v", value), usage})
		return holder, nil
	case float64:
		holder := new(float64)
		*holder = value.(float64)
		if shortFlag == "" && longFlag == "" {
			return nil, fmt.Errorf("one of short flag or long flag is required")
		}
		if shortFlag != "" {
			fsp.Set.Float64Var(holder, shortFlag, value.(float64), usage)
		}
		if longFlag != "" {
			fsp.Set.Float64Var(holder, longFlag, value.(float64), usage)
		}
		fsp.flgInfo = append(fsp.flgInfo, flagInfo{shortFlag, longFlag, fmt.Sprintf("%v", value), usage})
		return holder, nil
	}

	return nil, fmt.Errorf("unknown type for flag: %T", value)
}

func (fsp *FlagSetPack) NewBoolFlag(shortFlag string, longFlag string, usage string, value bool) (*bool, error) {
	result, err := fsp.newFlag(shortFlag, longFlag, usage, value)
	if err != nil {
		return nil, err
	}

	return result.(*bool), nil
}

func (fsp *FlagSetPack) NewStringFlag(shortFlag string, longFlag string, usage string, value string) (*string, error) {
	result, err := fsp.newFlag(shortFlag, longFlag, usage, value)
	if err != nil {
		return nil, err
	}

	return result.(*string), nil
}

func (fsp *FlagSetPack) NewIntFlag(shortFlag string, longFlag string, usage string, value int) (*int, error) {
	result, err := fsp.newFlag(shortFlag, longFlag, usage, value)
	if err != nil {
		return nil, err
	}

	return result.(*int), nil
}

func (fsp *FlagSetPack) NewInt64Flag(shortFlag string, longFlag string, usage string, value int64) (*int64, error) {
	result, err := fsp.newFlag(shortFlag, longFlag, usage, value)
	if err != nil {
		return nil, err
	}

	return result.(*int64), nil
}

func FlagIsDefined(flagSet *flag.FlagSet, flagName string) bool {
	var flagIsUsed bool
	flagSet.Visit(func(f *flag.Flag) {
		if f.Name == flagName {
			flagIsUsed = true
		}
	})
	return flagIsUsed
}

func (fsp *FlagSetPack) PrintUsage(compact bool) {
	fmt.Printf("\r%s\n\n", fsp.cmdUsage)
	tw := new(tabwriter.Writer)
	tw.Init(fsp.Set.Output(), 0, 4, 2, ' ', 0)
	for _, item := range fsp.flgInfo {
		flags := fmt.Sprintf("-%s, --%s", item.shortFlag, item.longFlag)
		if item.shortFlag == "" {
			flags = fmt.Sprintf("--%s", item.longFlag)
		}
		if item.longFlag == "" {
			flags = fmt.Sprintf("-%s", item.shortFlag)
		}
		defValue := item.defValue
		if item.defValue == "" {
			defValue = "\"\""
		}
		if compact {
			_, _ = fmt.Fprintf(tw, "\r\t%s\t%s (default %v)\t\n", flags, item.flagUsage, defValue)
		} else {
			_, _ = fmt.Fprintf(tw, "\r\t%s\n\r\t\t\t\t%s (default %v)\t\n", flags, item.flagUsage, defValue)
		}

	}
	_ = tw.Flush()
	fmt.Printf("\n")
}
