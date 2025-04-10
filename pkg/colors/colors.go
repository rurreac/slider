package colors

type consoleColors struct {
	Ok, Info, Debug, Warn, Error, System, Clear, Home []byte
}

type logColors struct {
	Info, Debug, Warn, Error, Fatal []byte
}

// All terminals that support Colors will support 8 / 16 colors
const keyEscape = 27

var (
	Reset      = []byte{keyEscape, 'c'}
	ResetColor = []byte{keyEscape, '[', '0', 'm'}
	Clear      = []byte{keyEscape, '[', '2', 'J'}
	Home       = []byte{keyEscape, '[', '2', 'H'}
	Console    = consoleColors{
		Ok:     []byte{keyEscape, '[', '1', ';', '3', '2', 'm'},
		Info:   []byte{keyEscape, '[', '1', ';', '9', '0', 'm'},
		Error:  []byte{keyEscape, '[', '1', ';', '9', '1', 'm'},
		Warn:   []byte{keyEscape, '[', '0', ';', '9', '3', 'm'},
		Debug:  []byte{keyEscape, '[', '1', ';', '9', '4', 'm'},
		System: []byte{keyEscape, '[', '1', ';', '3', '6', 'm'},
	}
	Log = logColors{
		Info:  []byte{keyEscape, '[', '1', ';', '3', '6', 'm'},
		Debug: []byte{keyEscape, '[', '1', ';', '9', '4', 'm'},
		Warn:  []byte{keyEscape, '[', '1', ';', '9', '3', 'm'},
		Error: []byte{keyEscape, '[', '1', ';', '3', '1', 'm'},
		Fatal: []byte{keyEscape, '[', '1', ';', '9', '1', 'm'},
	}
)
