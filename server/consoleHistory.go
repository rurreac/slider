package server

import (
	"fmt"
	"strings"
)

type CustomHistory struct {
	entries []string
	maxSize int
}

// Add implements term.History.Add
// Adds a new entry to the history (most recent first)
// If the entry is empty or a duplicate of the most recent entry, it's ignored
func (h *CustomHistory) Add(entry string) {
	// Skip empty entries
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return
	}

	// Skip duplicate of the most recent entry
	if len(h.entries) > 0 && h.entries[0] == entry {
		return
	}

	// Add the new entry at the beginning (most recent first)
	h.entries = append([]string{entry}, h.entries...)

	// Trim the history if it exceeds maxSize
	if len(h.entries) > h.maxSize {
		h.entries = h.entries[:h.maxSize]
	}
}

// Len implements term.History.Len
// Returns the number of entries in the history
func (h *CustomHistory) Len() int {
	return len(h.entries)
}

// At implements term.History.At
// Returns the entry at the given index
// Index 0 is the most recent entry, Len()-1 is the oldest
func (h *CustomHistory) At(idx int) string {
	if idx < 0 || idx >= len(h.entries) {
		panic(fmt.Sprintf("history index out of range: %d", idx))
	}
	return h.entries[idx]
}
