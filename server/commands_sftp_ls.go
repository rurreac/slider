package server

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slider/pkg/spath"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/pflag"
)

const (
	lsCmd    = "ls"
	lsDesc   = "List remote directory contents"
	lsUsage  = "ls [-l] [path]"
	lLsCmd   = "lls"
	lLsDesc  = "List local directory contents"
	lLsUsage = "lls [-l] [path]"
)

// SftpLsCommand implements the 'ls' and 'lls' commands
type SftpLsCommand struct {
	isRemote bool
}

func (c *SftpLsCommand) Name() string {
	if c.isRemote {
		return lsCmd
	}
	return lLsCmd
}

func (c *SftpLsCommand) Description() string {
	if c.isRemote {
		return lsDesc
	}
	return lLsDesc
}

func (c *SftpLsCommand) Usage() string {
	return fmt.Sprintf("Usage: %s [flags] [path]", c.Name())
}

func (c *SftpLsCommand) IsRemote() bool {
	return c.isRemote
}

func (c *SftpLsCommand) Run(s *server, args []string, ui UserInterface) error {
	ctx := s.sftpContext
	if ctx == nil {
		return fmt.Errorf("SFTP context not initialized")
	}

	lsFlags := pflag.NewFlagSet(c.Name(), pflag.ContinueOnError)
	lsFlags.SetOutput(ui.Writer())

	lsFlags.Usage = func() {
		_, _ = fmt.Fprintf(ui.Writer(), "Usage: %s\n\n", c.Usage())
		_, _ = fmt.Fprintf(ui.Writer(), "%s\n\n", c.Description())
		lsFlags.PrintDefaults()
	}

	if pErr := lsFlags.Parse(args); pErr != nil {
		if errors.Is(pErr, pflag.ErrHelp) {
			return nil
		}
		return fmt.Errorf("flag error: %w", pErr)
	}

	if lsFlags.NArg() > 1 {
		return fmt.Errorf("too many arguments")
	}

	path := ctx.getCwd(c.isRemote)
	if lsFlags.NArg() == 1 {
		path = lsFlags.Args()[0]
	}

	system := ctx.getContextSystem(c.isRemote)
	cwd := ctx.getCwd(c.isRemote)
	if !spath.IsAbs(system, path) && path != "." {
		path = spath.Join(system, []string{cwd, path})
	}

	// List directory contents
	var entries []fs.FileInfo
	var err error

	entries, err = ctx.readDir(path, c.isRemote)
	if err != nil {
		return fmt.Errorf("failed to list directory: %w", err)
	}

	if len(entries) == 0 {
		ui.PrintInfo("Directory is empty")
		return nil
	}

	// Order files in *nix style
	sort.Slice(entries, func(i, j int) bool {
		return strings.ToLower(strings.TrimPrefix(entries[i].Name(), ".")) <
			strings.ToLower(strings.TrimPrefix(entries[j].Name(), "."))
	})

	tw := new(tabwriter.Writer)
	tw.Init(ui.Writer(), 0, 4, 2, ' ', 0)

	for _, entry := range entries {
		// Format name field (colors, symlinks, etc)
		nameField := c.formatFileName(ctx, entry, path)

		// Format size for better readability
		var size string
		if entry.IsDir() {
			size = "<DIR>"
		} else {
			size = formatSize(entry.Size())
		}

		modTime := entry.ModTime().Format("Jan 02 15:04")
		perms := entry.Mode().String()

		// Do not output uid, gid on Windows as it is always 0
		if ctx.getContextSystem(c.isRemote) != "windows" {
			uid, gid := ctx.getFileIdInfo(entry, c.isRemote)
			_, _ = fmt.Fprintf(tw, "%s\t%d\t%d\t%s\t%s\t%s\t\n",
				perms,
				uid,
				gid,
				size,
				modTime,
				nameField)
		} else {
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t\n",
				perms,
				size,
				modTime,
				nameField)
		}
	}
	_, _ = fmt.Fprintln(tw)
	_ = tw.Flush()

	return nil
}

func (c *SftpLsCommand) formatFileName(ctx *SftpCommandContext, entry fs.FileInfo, path string) string {
	var nameField string
	if entry.IsDir() {
		nameField = fmt.Sprintf("%s", blueBrightBoldText(entry.Name()))
	} else if entry.Mode()&os.ModeSymlink != 0 {
		nameField = fmt.Sprintf("%s", cyanBoldText(entry.Name()))
		target, lErr := ctx.readLink(
			spath.Join(ctx.getContextSystem(c.isRemote), []string{path, entry.Name()}),
			c.isRemote,
		)

		// If we can't read the symlink, just show the name without error
		if lErr != nil {
			return nameField
		}
		// Check if target exists
		tI, tErr := ctx.pathStat(target, c.isRemote)
		if tErr != nil {
			target = fmt.Sprintf("%s", blinkText(redBoldText(target)))
		} else {
			if tI.IsDir() {
				target = fmt.Sprintf("%s", blueBrightBoldText(target))
			}
		}
		nameField = fmt.Sprintf("%s -> %s", cyanBoldText(entry.Name()), target)
	} else {
		nameField = entry.Name()
	}
	return nameField
}

// formatSize formats a file size human readable
func formatSize(size int64) string {
	switch {
	case size < 1024:
		return fmt.Sprintf("%d B", size)
	case size < 1024*1024:
		return fmt.Sprintf("%.1f KB", float64(size)/1024)
	case size < 1024*1024*1024:
		return fmt.Sprintf("%.1f MB", float64(size)/(1024*1024))
	default:
		return fmt.Sprintf("%.1f GB", float64(size)/(1024*1024*1024))
	}
}
