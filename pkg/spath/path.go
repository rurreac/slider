package spath

import (
	"slices"
	"strings"
)

/*
	Package spath is a wrapper over Go standard path package,
	so we can resolve path independently of runtime.GOOS value.
*/

func IsAbs(system, path string) bool {
	if system == "windows" {
		return winIsAbs(path)
	}
	return unixIsAbs(path)
}

func Join(system string, elem []string) string {
	if system == "windows" {
		return winJoin(elem)
	}
	return unixJoin(elem)
}

func Dir(system, path string) string {
	if system == "windows" {
		return winDir(path)
	}
	return unixDir(path)
}

func Base(system, path string) string {
	if system == "windows" {
		return winBase(path)
	}
	return unixBase(path)
}

func FromToSlash(system, path string) string {
	if system == "windows" {
		return winFromSlash(path)
	}
	return unixToSlash(path)
}

/*
	Bellow, as well as pathwin.go and pathunix.go is mostly taken from:
	- https://go.googlesource.com/go/+/refs/tags/go1.19.2/src/path/filepath/path.go
	- https://go.googlesource.com/go/+/refs/tags/go1.19.2/src/path/filepath/path_windows.go,
	- https://go.googlesource.com/go/+/refs/tags/go1.19.2/src/path/filepath/path_unix.go
*/

type lazybuf struct {
	path       string
	buf        []byte
	w          int
	volAndPath string
	volLen     int
}

func (b *lazybuf) index(i int) byte {
	if b.buf != nil {
		return b.buf[i]
	}
	return b.path[i]
}

func (b *lazybuf) append(c byte) {
	if b.buf == nil {
		if b.w < len(b.path) && b.path[b.w] == c {
			b.w++
			return
		}
		b.buf = make([]byte, len(b.path))
		copy(b.buf, b.path[:b.w])
	}
	b.buf[b.w] = c
	b.w++
}

func (b *lazybuf) prepend(prefix ...byte) {
	b.buf = slices.Insert(b.buf, 0, prefix...)
	b.w += len(prefix)
}

func (b *lazybuf) string() string {
	if b.buf == nil {
		return b.volAndPath[:b.volLen+b.w]
	}
	return b.volAndPath[:b.volLen] + string(b.buf[:b.w])
}

func replaceStringByte(s string, old, new byte) string {
	if strings.IndexByte(s, old) == -1 {
		return s
	}
	n := []byte(s)
	for i := range n {
		if n[i] == old {
			n[i] = new
		}
	}
	return string(n)
}
