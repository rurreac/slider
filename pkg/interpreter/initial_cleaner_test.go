package interpreter

import (
	"bytes"
	"testing"
)

func TestInitialScreenClearer(t *testing.T) {
	tests := []struct {
		name     string
		chunks   [][]byte
		expected []byte
	}{
		{
			name: "Simple Clear and Home",
			chunks: [][]byte{
				[]byte("\x1b[2J\x1b[HContent"),
			},
			// 2J -> stripped (initial), H -> stripped (initial). So just Content
			expected: []byte("Content"),
		},
		{
			name: "Split Sequence",
			chunks: [][]byte{
				[]byte("\x1b[2"),
				[]byte("J\x1b[HContent"),
			},
			expected: []byte("Content"),
		},
		{
			name: "Leading Newlines and Spaces",
			chunks: [][]byte{
				// \r\n + Space (skipped as whitespace) + 2J(\r\n, but !seenContent so stripped) + Content
				[]byte("\r\n \x1b[2JContent"),
			},
			// Expect: Content. Initial whitespace is skipped.
			expected: []byte("Content"),
		},
		{
			name: "OSC Window Title then Clear",
			chunks: [][]byte{
				// OSC 0;Window Title\007 (BEL) then Clear
				[]byte("\x1b]0;Window Title\x07\x1b[2J\x1b[HContent"),
			},
			// OSC stripped, 2J (initial) -> strip, H (initial) -> strip
			expected: []byte("Content"),
		},
		{
			name: "OSC with ST",
			chunks: [][]byte{
				// OSC 0;Title\x1b\\ (ST) then Content
				[]byte("\x1b]0;Title\x1b\\Content"),
			},
			expected: []byte("Content"),
		},
		{
			name: "Split OSC",
			chunks: [][]byte{
				[]byte("\x1b]0;Title"),
				[]byte("\x07Content"),
			},
			expected: []byte("Content"),
		},
		{
			name: "Complex Windows Sequence",
			chunks: [][]byte{
				// ?25h (show cursor -> stripped if not alt buffer), 2J (clear -> stripped initial), H (home -> stripped initial)
				[]byte("\x1b[?25h\x1b[2J\x1b[HContent"),
			},
			expected: []byte("Content"),
		},
		{
			name: "Sequence then Unknown CSI",
			chunks: [][]byte{
				// 2J (clear -> stripped initial) then Z (unknown to whitelist) -> should keep Z
				[]byte("\x1b[2J\x1b[ZContent"),
			},
			expected: []byte("\x1b[ZContent"),
		},
		{
			name: "Interleaved Content continues stripping with newline",
			chunks: [][]byte{
				// Header -> Content (seenContent=true)
				// 2J -> Stripped (Single \r\n)
				// OSC -> Stripped
				[]byte("Header\x1b[2J\x1b]0;Late Title\x07Content"),
			},
			// J -> \r\n
			expected: []byte("Header\r\nContent"),
		},
		{
			name: "Interleaved Cursor Jump",
			chunks: [][]byte{
				// Header -> H (Stripped because homeCount=1 < 2) -> Content
				[]byte("Header\x1b[HContent"),
			},
			expected: []byte("Header\r\nContent"),
		},
		{
			name: "Partial Split across multiple chunks",
			chunks: [][]byte{
				[]byte("\x1b"),
				[]byte("["),
				[]byte("2"),
				[]byte("J"),
				[]byte("Content"),
			},
			expected: []byte("Content"), // 2J is initial
		},
		{
			name: "Very long partial buffer within limit",
			chunks: [][]byte{
				[]byte("\x1b["),
				bytes.Repeat([]byte("?"), 100), // Lots of params
				[]byte("h"),                    // h (?...) -> stripped (initial) as not ?1049
				[]byte("Content"),
			},
			expected: []byte("Content"),
		},
		{
			name: "Initial Color then Clear",
			chunks: [][]byte{
				// [31m (Red) -> should NOT set seenContent
				// [2J] -> stripped (initial)
				// [H] -> stripped (initial)
				// Content
				[]byte("\x1b[31m\x1b[2J\x1b[HContent"),
			},
			// Expect: [31m + Content
			expected: []byte("\x1b[31mContent"),
		},
		{
			name: "Heuristic Pass Through",
			chunks: [][]byte{
				// 1. [2J][H] -> Stripped, homeCount=0 (part of clear)
				// 2. [H] -> Stripped, homeCount=1
				// 3. Content
				// 4. [H] -> Stripped, homeCount=2 (replaced by newline)
				// 5. [H] -> Filter Disabled -> Passed Raw, homeCount=3
				[]byte("\x1b[2J\x1b[H\x1b[HContent\x1b[H\x1b[HMore"),
			},
			expected: []byte("Content\r\n\x1b[HMore"),
		},
		{
			name: "Alt Buffer Trigger",
			chunks: [][]byte{
				// 1. [?1049h] -> Alt Buffer -> DISABLE FILTER + PASS RAW
				// 2. [?25l] -> Passed Raw
				// 3. [2J] -> Passed Raw
				// 4. [H] -> Passed Raw
				[]byte("\x1b[?1049h\x1b[?25l\x1b[2J\x1b[HContent"),
			},
			// Everything passed because ?1049h triggers Pass-Through mode immediately
			// Note: ?1049h itself IS passed in current logic (shouldStrip=false).
			expected: []byte("\x1b[?1049h\x1b[?25l\x1b[2J\x1b[HContent"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isc := NewInitialScreenClearer()
			var output []byte
			for _, chunk := range tt.chunks {
				out := isc.Process(chunk)
				if out != nil {
					output = append(output, out...)
				}
			}

			if !bytes.Equal(output, tt.expected) {
				t.Errorf("expected %q, got %q", tt.expected, output)
			}
		})
	}
}

// TestWindowsVerification simulates real-world scenarios for Windows command execution
// to properly verify the InitialScreenClearer logic.
func TestWindowsVerification(t *testing.T) {
	tests := []struct {
		name          string
		inputStream   [][]byte
		expectedMatch []byte // Substring we expect to see
		mustNotHave   []byte // Substring we must NOT see
		exactExpect   []byte // Exact match if non-nil
	}{
		{
			name: "Execute dir - Batch Command with Shell Init",
			// Simulates: cmd.exe startup (Clear+Home), Banner, Prompt, then 'dir' output
			inputStream: [][]byte{
				[]byte("\x1b[2J\x1b[H"), // Shell init often clears screen
				[]byte("Microsoft Windows [Version 10.0.19045.3693]\r\n"),
				[]byte("(c) Microsoft Corporation. All rights reserved.\r\n\r\n"),
				[]byte("C:\\Users\\User>dir\r\n"),
				[]byte(" Volume in drive C has no label.\r\n"),
				[]byte(" Directory of C:\\Users\\User\r\n"),
			},
			// Expectation: Initial Clear/Home stripped. Text intact.
			// Result should start with "Microsoft..."
			exactExpect: []byte("Microsoft Windows [Version 10.0.19045.3693]\r\n(c) Microsoft Corporation. All rights reserved.\r\n\r\nC:\\Users\\User>dir\r\n Volume in drive C has no label.\r\n Directory of C:\\Users\\User\r\n"),
		},
		{
			name: "Execute htop - Interactive App with Alt Buffer",
			// Simulates: htop startup. usually enters alt buffer, hides cursor, clears, homes, draws.
			inputStream: [][]byte{
				[]byte("\x1b[?1049h"),   // Enter Alt Buffer -> Should trigger PassThrough
				[]byte("\x1b[?25l"),     // Hide Cursor
				[]byte("\x1b[H\x1b[2J"), // Clear and Home
				[]byte("  1  [|||||||||||||         25.0%]   Tasks: 76, 126 thr; 1 running\r\n"),
				[]byte("  2  [||||||||              15.0%]   Load average: 0.15 0.12 0.09\r\n"),
			},
			// Expectation: All sequences passed through because of ?1049h
			exactExpect: []byte("\x1b[?1049h\x1b[?25l\x1b[H\x1b[2J  1  [|||||||||||||         25.0%]   Tasks: 76, 126 thr; 1 running\r\n  2  [||||||||              15.0%]   Load average: 0.15 0.12 0.09\r\n"),
		},
		{
			name: "TUI app without Alt Buffer (Heuristic)",
			// Simulates an app that redraws the screen using Home [H] but doesn't use Alt Buffer
			inputStream: [][]byte{
				[]byte("\x1b[2J\x1b[H"), // Init Clear - Stripped (homeCount=0)
				[]byte("Loading..."),
				[]byte("\x1b[H"), // homeCount=1 (replaced by newline because seen content)
				[]byte("Redrawing..."),
				[]byte("\x1b[H"), // homeCount=2 (replaced by newline)
				[]byte("More..."),
				[]byte("\x1b[H"), // homeCount=3 (triggers pass-through)
				[]byte("Dashboard Updated"),
			},
			exactExpect: []byte("Loading...\r\nRedrawing...\r\nMore...\x1b[HDashboard Updated"),
		},
		{
			name: "Batch Command with Mid-stream Clear",
			// Simulates: echo A && cls && echo B
			inputStream: [][]byte{
				[]byte("A\r\n"),
				[]byte("\x1b[2J"), // CLS mid-stream -> Should be converted to newline
				[]byte("B\r\n"),
			},
			// Expectation: "A\r\n\r\nB\r\n"
			// Note: 2J with seenContent replaces with \r\n
			exactExpect: []byte("A\r\n\r\nB\r\n"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isc := NewInitialScreenClearer()
			var output []byte
			for _, chunk := range tt.inputStream {
				out := isc.Process(chunk)
				output = append(output, out...)
			}

			if tt.exactExpect != nil {
				if !bytes.Equal(output, tt.exactExpect) {
					t.Errorf("Mismatch.\nExpected:\n%q\nGot:\n%q", tt.exactExpect, output)
				}
			} else {
				if tt.expectedMatch != nil {
					if !bytes.Contains(output, tt.expectedMatch) {
						t.Errorf("Expected output to contain %q, got %q", tt.expectedMatch, output)
					}
				}
				if tt.mustNotHave != nil {
					if bytes.Contains(output, tt.mustNotHave) {
						t.Errorf("Expected output NOT to contain %q, but it did. Output: %q", tt.mustNotHave, output)
					}
				}
			}
		})
	}
}
