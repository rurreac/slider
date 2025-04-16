package spath

import (
	"strings"
)

const (
	WindowsSeparator     = '\\'
	WindowsListSeparator = ';'
)

func winDir(path string) string {
	vol := winVolumeName(path)
	i := len(path) - 1
	for i >= len(vol) && !winIsPathSeparator(path[i]) {
		i--
	}
	d := winClean(path[len(vol) : i+1])
	if d == "." && len(vol) > 2 {
		// must be UNC
		return vol
	}
	return vol + d
}

func winVolumeName(path string) string {
	return replaceStringByte(path[:winVolumeNameLen(path)], '/', WindowsSeparator)
}

// reservedNames lists reserved Windows names. Search for PRN in
// https://docs.microsoft.com/en-us/windows/desktop/fileio/naming-a-file
// for details.
var winReservedNames = []string{
	"CON", "PRN", "AUX", "NUL",
	"COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
	"LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
}

func winIsSlash(c uint8) bool {
	return c == '\\' || c == '/'
}

// winIsReservedName returns true, if path is Windows reserved name.
// See reservedNames for the full list.
func winIsReservedName(path string) bool {
	if len(path) == 0 {
		return false
	}
	for _, reserved := range winReservedNames {
		if strings.EqualFold(path, reserved) {
			return true
		}
	}
	return false
}

// winIsAbs reports whether the path is absolute.
func winIsAbs(path string) (b bool) {
	if winIsReservedName(path) {
		return true
	}
	l := winVolumeNameLen(path)
	if l == 0 {
		return false
	}
	// If the volume name starts with a double slash, this is a UNC path.
	if winIsSlash(path[0]) && winIsSlash(path[1]) {
		return true
	}
	path = path[l:]
	if path == "" {
		return false
	}
	return winIsSlash(path[0])
}

// volumeNameLen returns length of the leading volume name on Windows.
// It returns 0 elsewhere.
func winVolumeNameLen(path string) int {
	if len(path) < 2 {
		return 0
	}
	// with drive letter
	c := path[0]
	if path[1] == ':' && ('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z') {
		return 2
	}
	// is it UNC? https://msdn.microsoft.com/en-us/library/windows/desktop/aa365247(v=vs.85).aspx
	if l := len(path); l >= 5 && winIsSlash(path[0]) && winIsSlash(path[1]) &&
		!winIsSlash(path[2]) && path[2] != '.' {
		// first, leading `\\` and next shouldn't be `\`. its server name.
		for n := 3; n < l-1; n++ {
			// second, next '\' shouldn't be repeated.
			if winIsSlash(path[n]) {
				n++
				// third, following something characters. its share name.
				if !winIsSlash(path[n]) {
					if path[n] == '.' {
						break
					}
					for ; n < l; n++ {
						if winIsSlash(path[n]) {
							break
						}
					}
					return n
				}
				break
			}
		}
	}
	return 0
}

func winJoin(elem []string) string {
	for i, e := range elem {
		if e != "" {
			return joinNonEmpty(elem[i:])
		}
	}
	return ""
}

// joinNonEmpty is like join, but it assumes that the first element is non-empty.
func joinNonEmpty(elem []string) string {
	if len(elem[0]) == 2 && elem[0][1] == ':' {
		// First element is drive letter without terminating slash.
		// Keep path relative to current directory on that drive.
		// Skip empty elements.
		i := 1
		for ; i < len(elem); i++ {
			if elem[i] != "" {
				break
			}
		}
		return winClean(elem[0] + strings.Join(elem[i:], string(WindowsSeparator)))
	}
	// The following logic prevents Join from inadvertently creating a
	// UNC path on Windows. Unless the first element is a UNC path, Join
	// shouldn't create a UNC path. See golang.org/issue/9167.
	p := winClean(strings.Join(elem, string(WindowsSeparator)))
	if !isUNC(p) {
		return p
	}
	// p == UNC only allowed when the first element is a UNC path.
	head := winClean(elem[0])
	if isUNC(head) {
		return p
	}
	// head + tail == UNC, but joining two non-UNC paths should not result
	// in a UNC path. Undo creation of UNC path.
	tail := winClean(strings.Join(elem[1:], string(WindowsSeparator)))
	if head[len(head)-1] == WindowsSeparator {
		return head + tail
	}
	return head + string(WindowsSeparator) + tail
}

// isUNC reports whether path is a UNC path.
func isUNC(path string) bool {
	return winVolumeNameLen(path) > 2
}

func winIsPathSeparator(c uint8) bool {
	// NOTE: Windows accepts / as path separator.
	return c == '\\' || c == '/'
}

func winPostClean(out *lazybuf) {
	if out.volLen != 0 || out.buf == nil {
		return
	}
	// If a ':' appears in the path element at the start of a path,
	// insert a .\ at the beginning to avoid converting relative paths
	// like a/../c: into c:.
	for _, c := range out.buf {
		if winIsPathSeparator(c) {
			break
		}
		if c == ':' {
			out.prepend('.', WindowsSeparator)
			return
		}
	}
	// If a path begins with \??\, insert a \. at the beginning
	// to avoid converting paths like \a\..\??\c:\x into \??\c:\x
	// (equivalent to c:\x).
	if len(out.buf) >= 3 && winIsPathSeparator(out.buf[0]) && out.buf[1] == '?' && out.buf[2] == '?' {
		out.prepend(WindowsSeparator, '.')
	}
}

func WinFromSlash(path string) string {
	return replaceStringByte(path, '/', WindowsSeparator)
}

func winBase(path string) string {
	if path == "" {
		return "."
	}
	// Strip trailing slashes.
	for len(path) > 0 && winIsPathSeparator(path[len(path)-1]) {
		path = path[0 : len(path)-1]
	}
	// Throw away volume name
	path = path[len(winVolumeName(path)):]
	// Find the last element
	i := len(path) - 1
	for i >= 0 && !winIsPathSeparator(path[i]) {
		i--
	}
	if i >= 0 {
		path = path[i+1:]
	}
	// If empty now, it had only slashes.
	if path == "" {
		return string(WindowsSeparator)
	}
	return path
}

func winClean(path string) string {
	originalPath := path
	volLen := winVolumeNameLen(path)
	path = path[volLen:]
	if path == "" {
		if volLen > 1 && winIsPathSeparator(originalPath[0]) && winIsPathSeparator(originalPath[1]) {
			// should be UNC
			return WinFromSlash(originalPath)
		}
		return originalPath + "."
	}
	rooted := winIsPathSeparator(path[0])

	// Invariants:
	//	reading from path; r is index of next byte to process.
	//	writing to buf; w is index of next byte to write.
	//	dotdot is index in buf where .. must stop, either because
	//		it is the leading slash or it is a leading ../../.. prefix.
	n := len(path)
	out := lazybuf{path: path, volAndPath: originalPath, volLen: volLen}
	r, dotdot := 0, 0
	if rooted {
		out.append(WindowsSeparator)
		r, dotdot = 1, 1
	}

	for r < n {
		switch {
		case winIsPathSeparator(path[r]):
			// empty path element
			r++
		case path[r] == '.' && (r+1 == n || winIsPathSeparator(path[r+1])):
			// . element
			r++
		case path[r] == '.' && path[r+1] == '.' && (r+2 == n || winIsPathSeparator(path[r+2])):
			// .. element: remove to last separator
			r += 2
			switch {
			case out.w > dotdot:
				// can backtrack
				out.w--
				for out.w > dotdot && !winIsPathSeparator(out.index(out.w)) {
					out.w--
				}
			case !rooted:
				// cannot backtrack, but not rooted, so append .. element.
				if out.w > 0 {
					out.append(WindowsSeparator)
				}
				out.append('.')
				out.append('.')
				dotdot = out.w
			}
		default:
			// real path element.
			// add slash if needed
			if rooted && out.w != 1 || !rooted && out.w != 0 {
				out.append(WindowsSeparator)
			}
			// copy element
			for ; r < n && !winIsPathSeparator(path[r]); r++ {
				out.append(path[r])
			}
		}
	}

	// Turn empty string into "."
	if out.w == 0 {
		out.append('.')
	}

	winPostClean(&out) // avoid creating absolute paths on Windows
	return WinFromSlash(out.string())
}
