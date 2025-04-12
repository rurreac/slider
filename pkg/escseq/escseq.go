package escseq

type conEscChars struct {
	GreenBold, GreyBold, BlueBrightBold, YellowBright, Yellow, RedBold, CyanBrightBoldB, CyanBold, Clear, Home []byte
}

type logColors struct {
	Info, Debug, Warn, Error, Fatal []byte
}

// All terminals that support Colors will support 8 / 16 colors
const keyEscape = 27

var (
	ResetScreen = []byte{keyEscape, 'c'}
	ResetColor  = []byte{keyEscape, '[', '0', 'm'}
	EraseLine   = []byte{keyEscape, '[', 'K'}
	CursorClear = []byte{keyEscape, '[', '2', 'J'}
	CursorHome  = []byte{keyEscape, '[', '2', 'H'}
	Console     = conEscChars{
		GreenBold:       []byte{keyEscape, '[', '1', ';', '3', '2', 'm'},
		GreyBold:        []byte{keyEscape, '[', '1', ';', '9', '0', 'm'},
		RedBold:         []byte{keyEscape, '[', '1', ';', '9', '1', 'm'},
		YellowBright:    []byte{keyEscape, '[', '0', ';', '9', '3', 'm'},
		Yellow:          []byte{keyEscape, '[', '0', ';', '3', '3', 'm'},
		BlueBrightBold:  []byte{keyEscape, '[', '1', ';', '9', '4', 'm'},
		CyanBold:        []byte{keyEscape, '[', '1', ';', '3', '6', 'm'},
		CyanBrightBoldB: []byte{keyEscape, '[', '1', ';', '9', '6', 'm'},
	}
	Log = logColors{
		Info:  []byte{keyEscape, '[', '1', ';', '3', '6', 'm'},
		Debug: []byte{keyEscape, '[', '1', ';', '9', '4', 'm'},
		Warn:  []byte{keyEscape, '[', '1', ';', '9', '3', 'm'},
		Error: []byte{keyEscape, '[', '1', ';', '3', '1', 'm'},
		Fatal: []byte{keyEscape, '[', '1', ';', '9', '1', 'm'},
	}
)
