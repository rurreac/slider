package interpreter

import (
	"fmt"
	"io"
	"os"
	"time"
)

// InitialScreenClearer (now acting more like a WindowsExecutionFilter)
// continuously filters out specific escape sequences that cause "mangled output"
// or unwanted cursor movements during non-interactive 'execute' commands on Windows.
// It aggressively strips sequences like Clear Screen, Cursor Home, and private modes
// that are typically emitted by ConPTY/cmd.exe, even if they appear mid-stream.
type InitialScreenClearer struct {
	buffer         []byte
	maxStripBytes  int
	hasSeenContent bool
	debugWriter    io.Writer
}

// NewInitialScreenClearer creates a new cleaner.
func NewInitialScreenClearer() *InitialScreenClearer {
	return &InitialScreenClearer{
		buffer:        make([]byte, 0, 1024),
		maxStripBytes: 4096,
	}
}

// EnableLogging enables debug logging to the specified file path.
func (isc *InitialScreenClearer) EnableLogging(path string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	isc.debugWriter = f
	return nil
}

func (isc *InitialScreenClearer) log(format string, args ...interface{}) {
	if isc.debugWriter == nil {
		return
	}
	timestamp := time.Now().Format("15:04:05.000")
	msg := fmt.Sprintf(format, args...)
	_, _ = fmt.Fprintf(isc.debugWriter, "%s: %s\n", timestamp, msg)
}

// Process takes a chunk of data and filters out unwanted sequences continuously.
func (isc *InitialScreenClearer) Process(data []byte) []byte {
	// If buffer gets ridiculously large (stuck partial sequence?), flush it to avoid OOM
	if len(isc.buffer) > 8192 {
		out := make([]byte, len(isc.buffer))
		// Log buffer before flush
		if isc.debugWriter != nil {
			isc.log("Buffer full, flushing raw. len=%d", len(isc.buffer))
		}

		copy(out, isc.buffer)
		isc.buffer = isc.buffer[:0]

		if len(data) > 0 {
			out = append(out, data...)
		}

		// Flushing counts as content
		if len(out) > 0 {
			isc.hasSeenContent = true
		}
		return out
	}

	if isc.debugWriter != nil && len(data) > 0 {
		isc.log("Recv chunk len=%d", len(data))
	}

	isc.buffer = append(isc.buffer, data...)

	var output []byte
	output = make([]byte, 0, len(isc.buffer))

	offset := 0
	bufLen := len(isc.buffer)

	for offset < bufLen {
		if isc.buffer[offset] == '\x1b' {
			if bufLen-offset < 2 {
				goto WaitMore
			}

			// CSI: ESC [
			if isc.buffer[offset+1] == '[' {
				j := offset + 2
				for j < bufLen {
					b := isc.buffer[j]
					if b >= 0x40 && b <= 0x7E {
						// Final byte of CSI
						cmd := b

						// Blacklist of commands to ALWAYS strip during execution
						shouldStrip := false
						replaceWithDoubleNewline := false
						replaceWithSingleNewline := false

						switch cmd {
						case 'H', 'f': // Cursor Positioning (redraws) - e.g. [4;1H
							shouldStrip = true
							// ConPTY uses this to jump lines.
							// Using \r\n\r\n gives better separation (preserves "blank lines" often implied by absolute jumps).
							if isc.hasSeenContent {
								replaceWithDoubleNewline = true
							}
						case 'J': // Erase Display
							shouldStrip = true
							// Clear screen usually acts as a page separator, so single newline is often enough.
							if isc.hasSeenContent {
								replaceWithSingleNewline = true
							}
						// Case 'K' (Erase Line) is debatable.
						case 'K':
							shouldStrip = true
						case 'S', 'T': // Scroll
							shouldStrip = true
						case 's', 'u': // Save/Restore Cursor
							shouldStrip = true
						case 'h', 'l': // Set/Reset Mode (e.g. ?25l Hide Cursor, ?9001h)
							shouldStrip = true
						// case 'm': // Colors - Keep colors.
						case 'c', 'n': // Device Attributes/Status
							shouldStrip = true
						case 'g': // Tab Clear
							shouldStrip = true
						}

						if shouldStrip {
							if isc.debugWriter != nil {
								// Log what we are stripping for verification
								seq := isc.buffer[offset : j+1]
								isc.log("Stripping CSI: %q", seq)
							}
							if replaceWithDoubleNewline {
								output = append(output, []byte("\r\n\r\n")...)
							} else if replaceWithSingleNewline {
								output = append(output, []byte("\r\n")...)
							}
							offset = j + 1
							goto NextLoop
						} else {
							// Keep allowed CSI (e.g. Colors [m, Unknowns)
							// Do NOT set hasSeenContent = true here.
							// Non-printing sequences (like colors) shouldn't trigger "content seen"
							// which would cause subsequent cursor moves to inject newlines.
							chunk := isc.buffer[offset : j+1]
							output = append(output, chunk...)
							offset = j + 1
							goto NextLoop
						}

					} else if b >= 0x20 && b <= 0x3F {
						j++
					} else {
						// Invalid CSI structure
						output = append(output, isc.buffer[offset])
						isc.hasSeenContent = true
						offset++
						goto NextLoop
					}
				}
				goto WaitMore

				// OSC: ESC ]
			} else if isc.buffer[offset+1] == ']' {
				j := offset + 2
				for j < bufLen {
					if isc.buffer[j] == 0x07 { // BEL
						// Strip OSC
						if isc.debugWriter != nil {
							isc.log("Stripping OSC (BEL)")
						}
						offset = j + 1
						goto NextLoop
					}
					if isc.buffer[j] == '\x1b' {
						if j+1 < bufLen {
							if isc.buffer[j+1] == '\\' { // ST
								// Strip OSC
								if isc.debugWriter != nil {
									isc.log("Stripping OSC (ST)")
								}
								offset = j + 2
								goto NextLoop
							}
						} else {
							goto WaitMore
						}
					}
					j++
				}
				goto WaitMore

			} else {
				// Other ESC sequence
				if isc.buffer[offset+1] == 'M' {
					if isc.debugWriter != nil {
						isc.log("Stripping ESC M (Reverse Index)")
					}
					offset += 2
					goto NextLoop
				}

				if isc.buffer[offset+1] == 'E' {
					// ESC E = Next Line.
					if isc.debugWriter != nil {
						isc.log("Normalizing ESC E -> \\r\\n")
					}
					output = append(output, []byte("\r\n")...)
					isc.hasSeenContent = true
					offset += 2
					goto NextLoop
				}

				// Otherwise treat as content
				output = append(output, isc.buffer[offset])
				isc.hasSeenContent = true
				offset++
			}

		} else {
			// Normal char
			// Leading whitespace check - swallow if we haven't seen content yet.
			b := isc.buffer[offset]
			if !isc.hasSeenContent {
				if b == '\r' || b == '\n' || b == ' ' || b == '\t' {
					// Skip initial whitespace
					if isc.debugWriter != nil {
						// isc.log("Skipping initial whitespace: %02x", b) // verbose
					}
					offset++
					continue
				}
			}

			output = append(output, b)
			isc.hasSeenContent = true
			offset++
		}

	NextLoop:
	}

	isc.buffer = isc.buffer[:0]
	return output

WaitMore:
	remaining := isc.buffer[offset:]
	newBuf := make([]byte, len(remaining))
	copy(newBuf, remaining)
	isc.buffer = newBuf
	return output
}
