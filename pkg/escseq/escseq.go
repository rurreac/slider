package escseq

type logColors struct {
	Info, Debug, Warn, Error, Fatal []byte
}

const KeyEscape = 27

var (
	// Terminal Escape Sequences
	ResetColor  = []byte{KeyEscape, '[', '0', 'm'}
	EraseLine   = []byte{KeyEscape, '[', '2', 'K'}
	EraseScreen = []byte{KeyEscape, '[', '2', 'J'}
	CursorClear = []byte{KeyEscape, '[', '0', 'J'}
	CursorHome  = []byte{KeyEscape, '[', '2', 'H'}
	CursorUp    = []byte{KeyEscape, '[', '1', 'A'}
	Blink       = []byte{KeyEscape, '[', '5', 'm'}
	ResetBlink  = []byte{KeyEscape, '[', '2', '5', 'm'}
	// Colors
	GreenBold        = []byte{KeyEscape, '[', '1', ';', '3', '2', 'm'}
	GreyBold         = []byte{KeyEscape, '[', '1', ';', '9', '0', 'm'}
	RedBrightBold    = []byte{KeyEscape, '[', '1', ';', '9', '1', 'm'}
	RedBold          = []byte{KeyEscape, '[', '1', ';', '3', '1', 'm'}
	YellowBright     = []byte{KeyEscape, '[', '0', ';', '9', '3', 'm'}
	YellowBrightBold = []byte{KeyEscape, '[', '1', ';', '9', '3', 'm'}
	Yellow           = []byte{KeyEscape, '[', '0', ';', '3', '3', 'm'}
	BlueBrightBold   = []byte{KeyEscape, '[', '1', ';', '9', '4', 'm'}
	CyanBold         = []byte{KeyEscape, '[', '1', ';', '3', '6', 'm'}
	CyanBrightBold   = []byte{KeyEscape, '[', '1', ';', '9', '6', 'm'}
	Log              = logColors{
		Info:  CyanBold,
		Debug: BlueBrightBold,
		Warn:  YellowBrightBold,
		Error: RedBold,
		Fatal: RedBrightBold,
	}
)

func GreyOut(key string, colorOn bool) string {
	if colorOn {
		return string(GreyBold) + key + string(ResetColor)
	}
	return key
}

func LogDebug(colorOn bool) string {
	if colorOn {
		return string(BlueBrightBold) + "DEBU" + string(ResetColor)
	}
	return "DEBU"
}

func LogInfo(colorOn bool) string {
	if colorOn {
		return string(CyanBold) + "INFO" + string(ResetColor)
	}
	return "INFO"
}

func LogWarn(colorOn bool) string {
	if colorOn {
		return string(YellowBrightBold) + "WARN" + string(ResetColor)
	}
	return "WARN"
}

func LogError(colorOn bool) string {
	if colorOn {
		return string(RedBold) + "ERRO" + string(ResetColor)
	}
	return "ERRO"
}

func LogFatal(colorOn bool) string {
	if colorOn {
		return string(RedBrightBold) + "FATA" + string(ResetColor)
	}
	return "FATA"
}
