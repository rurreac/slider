package server

import (
	"fmt"
	"slider/pkg/conf"
	"strings"
	"sync"
)

// CustomHistory maintains a list of command history entries.
type CustomHistory struct {
	entries []string
	maxSize int
	mu      sync.Mutex
}

var DefaultHistory = &CustomHistory{
	entries: make([]string, 0),
	maxSize: conf.DefaultHistorySize,
}

// NewCustomHistory creates a new history instance
func NewCustomHistory() *CustomHistory {
	return &CustomHistory{
		entries: make([]string, 0),
		maxSize: conf.DefaultHistorySize,
	}
}

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

	// Lock the history for concurrent access
	h.mu.Lock()
	defer h.mu.Unlock()

	// Add the new entry at the beginning (most recent first)
	h.entries = append([]string{entry}, h.entries...)

	// Trim the history if it exceeds maxSize
	if len(h.entries) > h.maxSize {
		h.entries = h.entries[:h.maxSize]
	}
}

func (h *CustomHistory) Len() int {
	return len(h.entries)
}

func (h *CustomHistory) At(idx int) string {
	if idx < 0 || idx >= len(h.entries) {
		panic(fmt.Sprintf("history index out of range: %d", idx))
	}
	return h.entries[idx]
}
