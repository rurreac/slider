package sflag

import (
	"flag"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"
)

type FlagSetPack struct {
	Set            *flag.FlagSet
	cmdDescription string
	cmdUsage       string
	CmdAlias       []string
	flagList       []flagInfo
	exclusionGrp   [][]string
	requiredOneGrp [][]string
	conditionGrp   []flagCondition
	minArgs        int
	maxArgs        int
}

type flagInfo struct {
	shortFlag string
	longFlag  string
	defValue  string
	flagUsage string
}

type flagCondition struct {
	conditionFlag string
	isEnabled     bool
	excludeFlags  []string
}

func NewFlagPack(commands []string, usage string, description string, writerOut io.Writer) *FlagSetPack {
	flagSet := flag.NewFlagSet(commands[0], flag.ContinueOnError)
	flagSet.SetOutput(writerOut)
	return &FlagSetPack{
		Set:            flagSet,
		cmdUsage:       usage,
		cmdDescription: description,
		CmdAlias:       commands,
		flagList:       make([]flagInfo, 0),
		exclusionGrp:   make([][]string, 0),
		requiredOneGrp: make([][]string, 0),
		conditionGrp:   make([]flagCondition, 0),
		minArgs:        0,
		maxArgs:        0,
	}
}

// SetMinArgs sets the minimum number of non-flag arguments required.
// Returns the FlagSetPack to allow method chaining.
func (fsp *FlagSetPack) SetMinArgs(min int) *FlagSetPack {
	fsp.minArgs = min
	return fsp
}

// SetMaxArgs sets the maximum number of non-flag arguments allowed.
// A value of 0 means unlimited.
// Returns the FlagSetPack to allow method chaining.
func (fsp *FlagSetPack) SetMaxArgs(max int) *FlagSetPack {
	fsp.maxArgs = max
	return fsp
}

// SetExactArgs sets both minimum and maximum to the same value,
// requiring exactly that number of arguments.
func (fsp *FlagSetPack) SetExactArgs(count int) {
	fsp.minArgs = count
	fsp.maxArgs = count
}

func (fsp *FlagSetPack) newFlag(shortFlag string, longFlag string, usage string, value any) (any, error) {
	// Assign the result of type assertion to a variable
	switch typedValue := value.(type) {
	case bool:
		holder := new(bool)
		*holder = typedValue
		if shortFlag == "" && longFlag == "" {
			return nil, fmt.Errorf("one of short flag or long flag is required")
		}
		if shortFlag != "" {
			fsp.Set.BoolVar(holder, shortFlag, typedValue, usage)
		}
		if longFlag != "" {
			fsp.Set.BoolVar(holder, longFlag, typedValue, usage)
		}
		fsp.flagList = append(fsp.flagList, flagInfo{shortFlag, longFlag, fmt.Sprintf("%v", value), usage})
		return holder, nil
	case string:
		holder := new(string)
		*holder = typedValue
		if shortFlag == "" && longFlag == "" {
			return nil, fmt.Errorf("one of short flag or long flag is required")
		}
		if shortFlag != "" {
			fsp.Set.StringVar(holder, shortFlag, typedValue, usage)
		}
		if longFlag != "" {
			fsp.Set.StringVar(holder, longFlag, typedValue, usage)
		}
		fsp.flagList = append(fsp.flagList, flagInfo{shortFlag, longFlag, fmt.Sprintf("%v", value), usage})
		return holder, nil
	case int:
		holder := new(int)
		*holder = typedValue
		if shortFlag == "" && longFlag == "" {
			return nil, fmt.Errorf("one of short flag or long flag is required")
		}
		if shortFlag != "" {
			fsp.Set.IntVar(holder, shortFlag, typedValue, usage)
		}
		if longFlag != "" {
			fsp.Set.IntVar(holder, longFlag, typedValue, usage)
		}
		fsp.flagList = append(fsp.flagList, flagInfo{shortFlag, longFlag, fmt.Sprintf("%v", value), usage})
		return holder, nil
	case int64:
		holder := new(int64)
		*holder = typedValue
		if shortFlag == "" && longFlag == "" {
			return nil, fmt.Errorf("one of short flag or long flag is required")
		}
		if shortFlag != "" {
			fsp.Set.Int64Var(holder, shortFlag, typedValue, usage)
		}
		if longFlag != "" {
			fsp.Set.Int64Var(holder, longFlag, typedValue, usage)
		}
		fsp.flagList = append(fsp.flagList, flagInfo{shortFlag, longFlag, fmt.Sprintf("%v", value), usage})
		return holder, nil
	case time.Duration:
		holder := new(time.Duration)
		*holder = typedValue
		if shortFlag == "" && longFlag == "" {
			return nil, fmt.Errorf("one of short flag or long flag is required")
		}
		if shortFlag != "" {
			fsp.Set.DurationVar(holder, shortFlag, typedValue, usage)
		}
		if longFlag != "" {
			fsp.Set.DurationVar(holder, longFlag, typedValue, usage)
		}
		fsp.flagList = append(fsp.flagList, flagInfo{shortFlag, longFlag, fmt.Sprintf("%v", value), usage})
		return holder, nil
	case float64:
		holder := new(float64)
		*holder = typedValue
		if shortFlag == "" && longFlag == "" {
			return nil, fmt.Errorf("one of short flag or long flag is required")
		}
		if shortFlag != "" {
			fsp.Set.Float64Var(holder, shortFlag, typedValue, usage)
		}
		if longFlag != "" {
			fsp.Set.Float64Var(holder, longFlag, typedValue, usage)
		}
		fsp.flagList = append(fsp.flagList, flagInfo{shortFlag, longFlag, fmt.Sprintf("%v", value), usage})
		return holder, nil
	}

	return nil, fmt.Errorf("unknown type for flag: %T", value)
}

func (fsp *FlagSetPack) NewBoolFlag(shortFlag string, longFlag string, value bool, usage string) (*bool, error) {
	result, err := fsp.newFlag(shortFlag, longFlag, usage, value)
	if err != nil {
		return nil, err
	}

	return result.(*bool), nil
}

func (fsp *FlagSetPack) NewStringFlag(shortFlag string, longFlag string, value string, usage string) (*string, error) {
	result, err := fsp.newFlag(shortFlag, longFlag, usage, value)
	if err != nil {
		return nil, err
	}

	return result.(*string), nil
}

func (fsp *FlagSetPack) NewIntFlag(shortFlag string, longFlag string, value int, usage string) (*int, error) {
	result, err := fsp.newFlag(shortFlag, longFlag, usage, value)
	if err != nil {
		return nil, err
	}

	return result.(*int), nil
}

func (fsp *FlagSetPack) NewDurationFlag(shortFlag string, longFlag string, value time.Duration, usage string) (*time.Duration, error) {
	result, err := fsp.newFlag(shortFlag, longFlag, usage, value)
	if err != nil {
		return nil, err
	}

	return result.(*time.Duration), nil
}

func (fsp *FlagSetPack) NewInt64Flag(shortFlag string, longFlag string, value int64, usage string) (*int64, error) {
	result, err := fsp.newFlag(shortFlag, longFlag, usage, value)
	if err != nil {
		return nil, err
	}

	return result.(*int64), nil
}

// MarkFlagsMutuallyExclusive marks a group of flags as mutually exclusive.
// If more than one flag in this group is set, validation will fail.
// Panics if validation fails (e.g., if a flag doesn't exist), as this indicates a programming error.
func (fsp *FlagSetPack) MarkFlagsMutuallyExclusive(flagNames ...string) {
	if len(flagNames) < 2 {
		panic("At least two flags are required to form a mutually exclusive group")
	}

	// Validate that all flag names exist
	for _, name := range flagNames {
		found := false
		for _, info := range fsp.flagList {
			if info.shortFlag == name || info.longFlag == name {
				found = true
				break
			}
		}
		if !found {
			panic(fmt.Sprintf("cannot create mutex group: flag %q not found", name))
		}
	}

	// Add the flags to the mutex groups
	fsp.exclusionGrp = append(fsp.exclusionGrp, flagNames)
}

// MarkFlagsOneRequired marks a group of flags where exactly one flag must be set.
// If none of the flags in this group is set, validation will fail.
// Panics if validation fails (e.g., if a flag doesn't exist), as this indicates a programming error.
func (fsp *FlagSetPack) MarkFlagsOneRequired(flagNames ...string) {
	if len(flagNames) < 2 {
		panic("at least two flags are required to form a required-one group")
	}

	// Validate that all flag names exist
	for _, name := range flagNames {
		found := false
		for _, info := range fsp.flagList {
			if info.shortFlag == name || info.longFlag == name {
				found = true
				break
			}
		}
		if !found {
			panic(fmt.Sprintf("cannot create required-one group: flag %q not found", name))
		}
	}

	// Add the flags to the required-one groups
	fsp.requiredOneGrp = append(fsp.requiredOneGrp, flagNames)
}

func (fsp *FlagSetPack) MarkFlagsConditionExclusive(conditionFlag string, isEnabled bool, excludeFlags ...string) {
	if len(excludeFlags) < 1 {
		panic("At least one flag is required to form a condition exclusive group")
	}

	// Validate that all flag names exist
	for _, name := range excludeFlags {
		found := false
		for _, info := range fsp.flagList {
			if info.shortFlag == name || info.longFlag == name {
				found = true
				break
			}
		}
		if !found {
			panic(fmt.Sprintf("cannot create mutex group: flag %q not found", name))
		}
	}
	condition := flagCondition{
		conditionFlag: conditionFlag,
		isEnabled:     isEnabled,
		excludeFlags:  excludeFlags,
	}

	// Add the flags to the mutex groups
	fsp.conditionGrp = append(fsp.conditionGrp, condition)
}

// validateMutualExclusion checks if any mutually exclusive constraints are violated.
// It returns an error if multiple flags from the same mutex group are set.
func (fsp *FlagSetPack) validateMutualExclusion() error {
	for _, flagNames := range fsp.exclusionGrp {
		// Track which logical flags are set (by index in the flagNames slice)
		setFlagIndices := make(map[int]bool)
		formattedNames := make([]string, 0)

		// For each flag in the mutex group
		for i, name := range flagNames {
			// Find the corresponding flagInfo
			for _, info := range fsp.flagList {
				// If this info matches our flag name (either short or long form)
				if info.shortFlag == name || info.longFlag == name {
					// Check if either the short or long form is set
					if (info.shortFlag != "" && flagIsDefined(fsp.Set, info.shortFlag)) ||
						(info.longFlag != "" && flagIsDefined(fsp.Set, info.longFlag)) {

						setFlagIndices[i] = true

						// Format the flag name for error messages
						var formatted string
						if info.shortFlag != "" && info.longFlag != "" {
							formatted = fmt.Sprintf("-%s/--%s", info.shortFlag, info.longFlag)
						} else if info.shortFlag != "" {
							formatted = fmt.Sprintf("-%s", info.shortFlag)
						} else {
							formatted = fmt.Sprintf("--%s", info.longFlag)
						}
						formattedNames = append(formattedNames, formatted)
					}
					break
				}
			}
		}

		// If more than one logical flag is set
		if len(setFlagIndices) > 1 {
			return fmt.Errorf("flags %s cannot be used together",
				strings.Join(formattedNames, ", "))
		}
	}

	return nil
}

// validateRequiredOne checks if any required-one flag constraints are violated.
// It returns an error if none of the flags from a required-one group is set.
func (fsp *FlagSetPack) validateRequiredOne() error {
	for _, flagNames := range fsp.requiredOneGrp {
		anyFlagSet := false
		formattedNames := make([]string, 0)

		// For each flag in the required-one group
		for _, name := range flagNames {
			// Find the corresponding flagInfo
			for _, info := range fsp.flagList {
				// If this info matches our flag name (either short or long form)
				if info.shortFlag == name || info.longFlag == name {
					// Check if either the short or long form is set
					if (info.shortFlag != "" && flagIsDefined(fsp.Set, info.shortFlag)) ||
						(info.longFlag != "" && flagIsDefined(fsp.Set, info.longFlag)) {
						anyFlagSet = true
						break
					}

					// Format the flag name for error messages
					var formatted string
					if info.shortFlag != "" && info.longFlag != "" {
						formatted = fmt.Sprintf("-%s/--%s", info.shortFlag, info.longFlag)
					} else if info.shortFlag != "" {
						formatted = fmt.Sprintf("-%s", info.shortFlag)
					} else {
						formatted = fmt.Sprintf("--%s", info.longFlag)
					}
					formattedNames = append(formattedNames, formatted)
					break
				}
			}

			if anyFlagSet {
				break
			}
		}

		// If no flag from this group is set
		if !anyFlagSet {
			return fmt.Errorf("one of the flags %s must be set",
				strings.Join(formattedNames, ", "))
		}
	}

	return nil
}

func (fsp *FlagSetPack) validateConditionExclusion() error {
	for _, condition := range fsp.conditionGrp {
		setFlagIndices := make(map[int]bool)
		formattedNames := make([]string, 0)

		// For each flag in the exclusion
		for i, name := range condition.excludeFlags {
			// Find the corresponding flagInfo
			for _, info := range fsp.flagList {
				// If this info matches our flag name (either short or long form)
				if info.shortFlag == name || info.longFlag == name {
					// Check if either the short or long form is set
					if (info.shortFlag != "" && flagIsDefined(fsp.Set, info.shortFlag)) ||
						(info.longFlag != "" && flagIsDefined(fsp.Set, info.longFlag)) {

						setFlagIndices[i] = true

						// Format the flag name for error messages
						var formatted string
						if info.shortFlag != "" && info.longFlag != "" {
							formatted = fmt.Sprintf("-%s/--%s", info.shortFlag, info.longFlag)
						} else if info.shortFlag != "" {
							formatted = fmt.Sprintf("-%s", info.shortFlag)
						} else {
							formatted = fmt.Sprintf("--%s", info.longFlag)
						}
						formattedNames = append(formattedNames, formatted)
					}
					break
				}
			}
		}

		if len(setFlagIndices) < 1 {
			return nil
		}

		if condition.isEnabled {
			return fmt.Errorf("flag(s) %s require flag %s enabled",
				strings.Join(formattedNames, ", "), condition.conditionFlag)
		} else {
			return fmt.Errorf("flag(s) %s require flag %s disabled",
				strings.Join(formattedNames, ", "), condition.conditionFlag)
		}
	}

	return nil
}

// Parse wraps the standard flag.Parse method and validates mutually exclusive flag constraints.
// Returns:
// - (true, nil) if help is requested (-h or --help)
// - (false, error) if there's a parsing error, mutual exclusion violation, or argument count constraint violation
// - (false, nil) if parsing succeeded without any issues
func (fsp *FlagSetPack) Parse(arguments []string) error {
	// Parse the arguments
	if err := fsp.Set.Parse(arguments); err != nil {
		return err
	}

	// Check for mutual exclusion violations
	if err := fsp.validateMutualExclusion(); err != nil {
		return err
	}

	// Check for required-one violations
	if err := fsp.validateRequiredOne(); err != nil {
		return err
	}

	if err := fsp.validateConditionExclusion(); err != nil {
		return err
	}

	// Validate argument count
	argsCount := len(fsp.Set.Args())
	if fsp.minArgs > 0 && argsCount < fsp.minArgs {
		return fmt.Errorf("at least %d argument(s) required, got %d", fsp.minArgs, argsCount)
	}

	if fsp.maxArgs > 0 && argsCount > fsp.maxArgs {
		return fmt.Errorf("at most %d argument(s) allowed, got %d", fsp.maxArgs, argsCount)
	}

	return nil
}

func flagIsDefined(flagSet *flag.FlagSet, flagName string) bool {
	var flagIsUsed bool
	flagSet.Visit(func(f *flag.Flag) {
		if f.Name == flagName {
			flagIsUsed = true
		}
	})
	return flagIsUsed
}

func (fsp *FlagSetPack) PrintUsage(compact bool) {
	tw := new(tabwriter.Writer)
	tw.Init(fsp.Set.Output(), 0, 4, 2, ' ', 0)

	// Print Command Usage
	fmt.Printf("\r%s\n\n", fsp.cmdUsage)
	for _, item := range fsp.flagList {
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
	fmt.Println()

	// Print argument count requirements if any
	if fsp.minArgs > 0 || fsp.maxArgs > 0 {
		if fsp.minArgs == fsp.maxArgs && fsp.minArgs > 0 {
			fmt.Printf("\rRequires exactly %d argument(s)\n\n", fsp.minArgs)
		} else if fsp.minArgs > 0 && fsp.maxArgs > 0 {
			fmt.Printf("\rRequires between %d and %d argument(s)\n\n", fsp.minArgs, fsp.maxArgs)
		} else if fsp.minArgs > 0 {
			fmt.Printf("\rRequires at least %d argument(s)\n\n", fsp.minArgs)
		} else if fsp.maxArgs > 0 {
			fmt.Printf("\rRequires at most %d argument(s)\n\n", fsp.maxArgs)
		}
	}

	// Print required-one flags information
	if len(fsp.requiredOneGrp) > 0 {
		fmt.Printf("\rOne flag required from each group:\n\n")

		for _, flagNames := range fsp.requiredOneGrp {
			var flagsStr []string
			for _, name := range flagNames {
				for _, info := range fsp.flagList {
					if info.shortFlag == name || info.longFlag == name {
						if info.shortFlag != "" && info.longFlag != "" {
							flagsStr = append(flagsStr, fmt.Sprintf("-%s/--%s", info.shortFlag, info.longFlag))
						} else if info.shortFlag != "" {
							flagsStr = append(flagsStr, fmt.Sprintf("-%s", info.shortFlag))
						} else {
							flagsStr = append(flagsStr, fmt.Sprintf("--%s", info.longFlag))
						}
						break
					}
				}
			}
			_, _ = fmt.Fprintf(tw, "\r\t%s\t\n", strings.Join(flagsStr, ", "))
		}
		_ = tw.Flush()
		fmt.Println()
	}

	// Print mutually exclusive flags information
	if len(fsp.exclusionGrp) > 0 {
		fmt.Printf("\rMutually exclusive flags:\n\n")

		for _, flagNames := range fsp.exclusionGrp {
			var flagsStr []string
			for _, name := range flagNames {
				for _, info := range fsp.flagList {
					if info.shortFlag == name || info.longFlag == name {
						if info.shortFlag != "" && info.longFlag != "" {
							flagsStr = append(flagsStr, fmt.Sprintf("-%s/--%s", info.shortFlag, info.longFlag))
						} else if info.shortFlag != "" {
							flagsStr = append(flagsStr, fmt.Sprintf("-%s", info.shortFlag))
						} else {
							flagsStr = append(flagsStr, fmt.Sprintf("--%s", info.longFlag))
						}
						break
					}
				}
			}
			_, _ = fmt.Fprintf(tw, "\r\t%s\t\n", strings.Join(flagsStr, ", "))
		}
		_ = tw.Flush()
		fmt.Println()
	}

	if len(fsp.conditionGrp) > 0 {
		for _, condition := range fsp.conditionGrp {
			var flagsCondStr string
			for _, info := range fsp.flagList {
				if info.shortFlag == condition.conditionFlag || info.longFlag == condition.conditionFlag {
					if info.shortFlag != "" && info.longFlag != "" {
						flagsCondStr = fmt.Sprintf("-%s/--%s", info.shortFlag, info.longFlag)
					} else if info.shortFlag != "" {
						flagsCondStr = fmt.Sprintf("-%s", info.shortFlag)
					} else {
						flagsCondStr = fmt.Sprintf("--%s", info.longFlag)
					}
					break
				}
			}
			fmt.Printf(
				"\rFlag \"%s\" with status \"%v\" is incompatible with flags:\n\n",
				flagsCondStr,
				condition.isEnabled,
			)
			for _, name := range condition.excludeFlags {
				var flagsStr []string
				for _, info := range fsp.flagList {
					if info.shortFlag == name || info.longFlag == name {
						if info.shortFlag != "" && info.longFlag != "" {
							flagsStr = append(flagsStr, fmt.Sprintf("-%s/--%s", info.shortFlag, info.longFlag))
						} else if info.shortFlag != "" {
							flagsStr = append(flagsStr, fmt.Sprintf("-%s", info.shortFlag))
						} else {
							flagsStr = append(flagsStr, fmt.Sprintf("--%s", info.longFlag))
						}
						break
					}
				}
				_, _ = fmt.Fprintf(tw, "\r\t%s\t\n", strings.Join(flagsStr, ", "))
			}
		}
		_ = tw.Flush()
		fmt.Println()
	}
}
