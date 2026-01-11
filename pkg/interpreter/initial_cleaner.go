package interpreter

import (
	"bytes"
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
	buffer           []byte
	maxStripBytes    int
	hasSeenContent   bool
	homeCount        int
	disableFiltering bool
	lastWasClear     bool
	debugWriter      io.Writer
}

func (isc *InitialScreenClearer) EnableLogging(path string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	isc.debugWriter = f
	return nil
}

// NewInitialScreenClearer creates a new cleaner.
func NewInitialScreenClearer() *InitialScreenClearer {
	return &InitialScreenClearer{
		buffer:        make([]byte, 0, 1024),
		maxStripBytes: 4096,
	}
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
		// Optimization: If filtering is disabled, pass through everything remaining
		if isc.disableFiltering {
			output = append(output, isc.buffer[offset:]...)
			isc.buffer = isc.buffer[:0]
			return output
		}

		if isc.buffer[offset] == '\x1b' {
			if bufLen-offset < 2 {
				goto WaitMore
			}

			switch isc.buffer[offset+1] {
			case '[': // CSI: ESC [
				j := offset + 2
				for j < bufLen {
					b := isc.buffer[j]
					if b >= 0x40 && b <= 0x7E {
						// Final byte of CSI
						cmd := b
						params := isc.buffer[offset+2 : j]

						// Blacklist of commands to ALWAYS strip during execution (initially)
						shouldStrip := false
						replaceWithSingleNewline := false

						// Heuristic: Stop filtering after 2nd occurrences of Clear or Home
						if !isc.disableFiltering {
							switch cmd {
							case 'H', 'f': // Cursor Positioning
								isHome := len(params) == 0 ||
									bytes.Equal(params, []byte("1")) ||
									bytes.Equal(params, []byte("1;1")) ||
									bytes.Equal(params, []byte("1;")) ||
									bytes.Equal(params, []byte(";1")) ||
									bytes.Equal(params, []byte(";"))

								if isHome {
									if !isc.lastWasClear {
										isc.homeCount++
									}
								}
								isc.lastWasClear = false

								if isc.homeCount >= 3 {
									isc.disableFiltering = true
								} else {
									shouldStrip = true
									if isc.hasSeenContent {
										replaceWithSingleNewline = true
									}
								}
							case 'J': // Erase Display
								shouldStrip = true
								isc.lastWasClear = true
								if isc.hasSeenContent {
									replaceWithSingleNewline = true
								}
							case 'h', 'l':
								if bytes.Contains(params, []byte("?1049")) {
									isc.disableFiltering = true
									if isc.debugWriter != nil {
										isc.log("Alt Buffer detected, disabling filtering.")
									}
								} else {
									shouldStrip = true
								}
							}
						}

						if shouldStrip {
							if isc.debugWriter != nil {
								// Log what we are stripping for verification
								seq := isc.buffer[offset : j+1]
								isc.log("Stripping CSI: %q", seq)
							}
							if replaceWithSingleNewline {
								output = append(output, []byte("\r\n")...)
							}
							offset = j + 1
							goto NextLoop
						} else {
							// Keep allowed CSI (e.g. Colors [m, Unknowns, or if filtering disabled)
							// Do NOT set hasSeenContent = true here if it's a non-printing sequence.
							// But if filtering is disabled, we just pass everything.
							chunk := isc.buffer[offset : j+1]
							output = append(output, chunk...)
							offset = j + 1
							goto NextLoop
						}

					} else if b >= 0x20 && b <= 0x3F {
						j++
					} else {
						// Invalid CSI structure or control character during params
						if isc.debugWriter != nil {
							isc.log("Terminating CSI early due to char %d at %d", b, j)
						}
						offset = j // Keep this byte for next loop
						goto NextLoop
					}
				}
				if len(isc.buffer)-offset > 256 {
					if isc.debugWriter != nil {
						isc.log("CSI sequence too long, flushing buffer.")
					}
					output = append(output, isc.buffer[offset:]...)
					isc.buffer = isc.buffer[:0]
					return output
				}
				goto WaitMore

			case ']': // OSC: ESC ]
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
				if len(isc.buffer)-offset > 512 {
					if isc.debugWriter != nil {
						isc.log("OSC sequence too long, flushing buffer.")
					}
					output = append(output, isc.buffer[offset:]...)
					isc.buffer = isc.buffer[:0]
					return output
				}
				goto WaitMore

			case 'M': // Other ESC sequence: Reverse Index
				if isc.debugWriter != nil {
					isc.log("Stripping ESC M (Reverse Index)")
				}
				offset += 2
				goto NextLoop

			case 'E': // Next Line
				if isc.debugWriter != nil {
					isc.log("Normalizing ESC E -> \\r\\n")
				}
				output = append(output, []byte("\r\n")...)
				isc.hasSeenContent = true
				offset += 2
				goto NextLoop

			default:
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
					offset++
					continue
				}
				if isc.debugWriter != nil {
					isc.log("Initial stripping stopped due to content char: %d (%q)", b, b)
				}
			}

			output = append(output, b)
			isc.hasSeenContent = true
			isc.lastWasClear = false
			offset++
		}

	NextLoop:
	}

	isc.buffer = isc.buffer[:0]
	if isc.debugWriter != nil {
		isc.log("Returning output len=%d", len(output))
	}
	return output

WaitMore:
	remaining := isc.buffer[offset:]
	if isc.debugWriter != nil {
		isc.log("WaitMore: buffering %d bytes", len(remaining))
	}
	newBuf := make([]byte, len(remaining))
	copy(newBuf, remaining)
	isc.buffer = newBuf
	return output
}
