package completion

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestParsePathInput(t *testing.T) {
	cwd := "/Users/test/projects"
	homeDir := "/Users/test"

	tests := []struct {
		name           string
		input          string
		system         string
		expectedDir    string
		expectedPrefix string
	}{
		{
			name:           "Empty input",
			input:          "",
			system:         "linux",
			expectedDir:    cwd,
			expectedPrefix: "",
		},
		{
			name:           "Simple prefix",
			input:          "fil",
			system:         "linux",
			expectedDir:    cwd,
			expectedPrefix: "fil",
		},
		{
			name:           "Home expansion",
			input:          "~",
			system:         "linux",
			expectedDir:    homeDir,
			expectedPrefix: "",
		},
		{
			name:           "Home sub-path",
			input:          "~/doc",
			system:         "linux",
			expectedDir:    homeDir + "/",
			expectedPrefix: "doc",
		},
		{
			name:           "Absolute path",
			input:          "/etc/p",
			system:         "linux",
			expectedDir:    "/etc/",
			expectedPrefix: "p",
		},
		{
			name:           "Windows relative",
			input:          "data\\f",
			system:         "windows",
			expectedDir:    "C:\\projects\\data",
			expectedPrefix: "f",
		},
		{
			name:           "Windows absolute",
			input:          "C:\\Users\\t",
			system:         "windows",
			expectedDir:    "C:\\Users\\",
			expectedPrefix: "t",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			testCwd := cwd
			if tc.system == "windows" {
				testCwd = "C:\\projects"
			}
			dir, prefix, _ := parsePathInput(tc.input, testCwd, tc.system, homeDir)
			if dir != tc.expectedDir {
				t.Errorf("Dir: expected %q, got %q", tc.expectedDir, dir)
			}
			if prefix != tc.expectedPrefix {
				t.Errorf("Prefix: expected %q, got %q", tc.expectedPrefix, prefix)
			}
		})
	}
}

func TestFindCommonPrefix(t *testing.T) {
	tests := []struct {
		name     string
		matches  []string
		expected string
	}{
		{
			name:     "Empty",
			matches:  []string{},
			expected: "",
		},
		{
			name:     "Single",
			matches:  []string{"file1"},
			expected: "file1",
		},
		{
			name:     "Multiple matches",
			matches:  []string{"file1", "file2", "file_abc"},
			expected: "file",
		},
		{
			name:     "No common prefix",
			matches:  []string{"abc", "def"},
			expected: "",
		},
		{
			name:     "Case insensitive (common in windows)",
			matches:  []string{"File1", "file2"},
			expected: "File", // Should return first match's case or common part
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := findCommonPrefix(tc.matches)
			if got != tc.expected {
				t.Errorf("Expected %q, got %q", tc.expected, got)
			}
		})
	}
}

func TestLocalPathCompleter(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "slider-completion-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Create some files and directories
	files := []string{"test1.txt", "test2.log", "other.txt"}
	dirs := []string{"subdir1", "subdir2"}

	for _, f := range files {
		_ = os.WriteFile(filepath.Join(tmpDir, f), []byte("test"), 0644)
	}
	for _, d := range dirs {
		_ = os.Mkdir(filepath.Join(tmpDir, d), 0755)
	}

	completer := NewLocalPathCompleter()
	system := runtime.GOOS

	t.Run("Complete files by prefix", func(t *testing.T) {
		matches, common, err := completer.Complete("tes", tmpDir, system, "/home/test")
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		if len(matches) != 2 { // test1.txt, test2.log
			t.Errorf("Expected 2 matches, got %d: %v", len(matches), matches)
		}
		if common != "test" {
			t.Errorf("Expected common prefix 'test', got %q", common)
		}
	})

	t.Run("Complete directory with separator", func(t *testing.T) {
		matches, _, _ := completer.Complete("sub", tmpDir, system, "/home/test")

		found := false
		for _, m := range matches {
			if m == "subdir1/" || m == "subdir1\\" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected subdir matches to have trailing separator, got %v", matches)
		}
	})
}
