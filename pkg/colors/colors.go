package colors

type consoleColors struct {
	Ok, Debug, Warn, Error, System []byte
}

type logColors struct {
	Info, Debug, Warn, Error, Fatal []byte
}

// All terminals that support Colors will support 8 / 16 colors
const keyEscape = 27

var (
	Reset   = []byte{keyEscape, '[', '0', 'm'}
	Console = consoleColors{
		Ok:     []byte{keyEscape, '[', '1', ';', '3', '2', 'm'}, // 36  37 35 42
		Debug:  []byte{keyEscape, '[', '1', ';', '9', '4', 'm'},
		Warn:   []byte{keyEscape, '[', '0', ';', '3', '3', 'm'},
		Error:  []byte{keyEscape, '[', '1', ';', '9', '1', 'm'},
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
