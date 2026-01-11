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
				// ?25h (show cursor -> stripped), 2J (clear -> stripped initial), H (home -> stripped initial)
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
				// Header -> H (Double \r\n) -> Content
				[]byte("Header\x1b[HContent"),
			},
			expected: []byte("Header\r\n\r\nContent"),
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
				[]byte("h"),                    // h -> stripped (initial)
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
