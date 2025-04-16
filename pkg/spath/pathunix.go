package spath

import (
	"strings"
)

const (
	UnixSeparator     = '/'
	UnixListSeparator = ':'
)

func unixJoin(elem []string) string {
	for i, e := range elem {
		if e != "" {
			return unixClean(strings.Join(elem[i:], string(UnixSeparator)))
		}
	}
	return ""
}

func unixVolumeNameLen(path string) int {
	return 0
}

func unixVolumeName(path string) string {
	return replaceStringByte(path[:unixVolumeNameLen(path)], '/', UnixSeparator)
}

func unixIsAbs(path string) bool {
	return strings.HasPrefix(path, "/")
}

func unixIsPathSeparator(c uint8) bool {
	return UnixSeparator == c
}

func unixDir(path string) string {
	vol := unixVolumeName(path)
	i := len(path) - 1
	for i >= len(vol) && !unixIsPathSeparator(path[i]) {
		i--
	}
	d := unixClean(path[len(vol) : i+1])
	if d == "." && len(vol) > 2 {
		// must be UNC
		return vol
	}
	return vol + d
}

func unixPostClean(out *lazybuf) {}

func UnixFromSlash(path string) string {
	return path
}

func UnixToSlash(path string) string {
	return replaceStringByte(path, WindowsSeparator, '/')
}

func unixBase(path string) string {
	if path == "" {
		return "."
	}
	// Strip trailing slashes.
	for len(path) > 0 && unixIsPathSeparator(path[len(path)-1]) {
		path = path[0 : len(path)-1]
	}
	// Throw away volume name
	path = path[len(unixVolumeName(path)):]
	// Find the last element
	i := len(path) - 1
	for i >= 0 && !unixIsPathSeparator(path[i]) {
		i--
	}
	if i >= 0 {
		path = path[i+1:]
	}
	// If empty now, it had only slashes.
	if path == "" {
		return string(UnixSeparator)
	}
	return path
}

func unixClean(path string) string {
	originalPath := path
	volLen := unixVolumeNameLen(path)
	path = path[volLen:]
	if path == "" {
		if volLen > 1 && unixIsPathSeparator(originalPath[0]) && unixIsPathSeparator(originalPath[1]) {
			// should be UNC
			return UnixFromSlash(originalPath)
		}
		return originalPath + "."
	}
	rooted := unixIsPathSeparator(path[0])

	// Invariants:
	//	reading from path; r is index of next byte to process.
	//	writing to buf; w is index of next byte to write.
	//	dotdot is index in buf where .. must stop, either because
	//		it is the leading slash or it is a leading ../../.. prefix.
	n := len(path)
	out := lazybuf{path: path, volAndPath: originalPath, volLen: volLen}
	r, dotdot := 0, 0
	if rooted {
		out.append(UnixSeparator)
		r, dotdot = 1, 1
	}

	for r < n {
		switch {
		case unixIsPathSeparator(path[r]):
			// empty path element
			r++
		case path[r] == '.' && (r+1 == n || unixIsPathSeparator(path[r+1])):
			// . element
			r++
		case path[r] == '.' && path[r+1] == '.' && (r+2 == n || unixIsPathSeparator(path[r+2])):
			// .. element: remove to last separator
			r += 2
			switch {
			case out.w > dotdot:
				// can backtrack
				out.w--
				for out.w > dotdot && !unixIsPathSeparator(out.index(out.w)) {
					out.w--
				}
			case !rooted:
				// cannot backtrack, but not rooted, so append .. element.
				if out.w > 0 {
					out.append(UnixSeparator)
				}
				out.append('.')
				out.append('.')
				dotdot = out.w
			}
		default:
			// real path element.
			// add slash if needed
			if rooted && out.w != 1 || !rooted && out.w != 0 {
				out.append(UnixSeparator)
			}
			// copy element
			for ; r < n && !unixIsPathSeparator(path[r]); r++ {
				out.append(path[r])
			}
		}
	}

	// Turn empty string into "."
	if out.w == 0 {
		out.append('.')
	}

	unixPostClean(&out) // avoid creating absolute paths on Windows
	return UnixFromSlash(out.string())
}
