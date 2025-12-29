package completion

import (
	"context"
	"slider/pkg/spath"
	"strings"

	"github.com/pkg/sftp"
)

// RemotePathCompleter completes paths on remote systems via SFTP
type RemotePathCompleter struct {
	sftpClient *sftp.Client
}

// NewRemotePathCompleter creates a new remote path completer
func NewRemotePathCompleter(sftpClient *sftp.Client) *RemotePathCompleter {
	return &RemotePathCompleter{
		sftpClient: sftpClient,
	}
}

// Complete performs remote path completion
// For remote paths, we need to handle SFTP format conversion
func (rpc *RemotePathCompleter) Complete(ctx context.Context, input string, cwd string, system string, homeDir string) ([]string, string, error) {
	if rpc.sftpClient == nil {
		return nil, input, nil
	}

	// Convert user input to SFTP format if needed
	sftpInput := input
	sftpCwd := cwd

	if system == "windows" {
		// Convert Windows-style input to SFTP format
		if input != "" {
			sftpInput = spath.UserInputToSFTPPath(input, cwd, system)
		}
		// cwd should already be in SFTP format from the session
	}

	// Parse input (SFTP paths are always Unix-style internally)
	dir, prefix, _ := parsePathInput(sftpInput, sftpCwd, "linux", homeDir)

	// Read remote directory
	entries, err := rpc.sftpClient.ReadDir(dir)
	if err != nil {
		// Directory doesn't exist or no permission
		return nil, input, nil
	}

	// Filter by prefix
	filtered := filterEntries(entries, prefix, maxEntries)

	// Build result (always use Unix-style for SFTP)
	result := buildResult(filtered, prefix, "linux")

	// If remote system is Windows, convert results back to display format
	if system == "windows" {
		matches := make([]string, len(result.Matches))
		for i, match := range result.Matches {
			// Keep the trailing slash/backslash indicator
			isDir := strings.HasSuffix(match, "/")
			matchName := strings.TrimSuffix(match, "/")

			// Convert to Windows display format
			matchName = spath.SFTPPathForDisplay(matchName, system)

			if isDir {
				matchName += "\\"
			}

			matches[i] = matchName
		}
		result.Matches = matches

		// Convert common prefix
		isDir := strings.HasSuffix(result.CommonPrefix, "/")
		commonName := strings.TrimSuffix(result.CommonPrefix, "/")
		commonName = spath.SFTPPathForDisplay(commonName, system)
		if isDir {
			commonName += "\\"
		}
		result.CommonPrefix = commonName
	}

	return result.Matches, result.CommonPrefix, nil
}
