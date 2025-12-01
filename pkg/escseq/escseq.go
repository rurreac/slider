package escseq

import "fmt"

const KeyEscape = 27

var (
	// Terminal Escape Sequences
	resetColor  = []byte{KeyEscape, '[', '0', 'm'}
	eraseLine   = []byte{KeyEscape, '[', '2', 'K'}
	eraseScreen = []byte{KeyEscape, '[', '2', 'J'}
	cursorClear = []byte{KeyEscape, '[', '0', 'J'}
	cursorHome  = []byte{KeyEscape, '[', '2', 'H'}
	cursorUp    = []byte{KeyEscape, '[', '1', 'A'}
	blink       = []byte{KeyEscape, '[', '5', 'm'}
	resetBlink  = []byte{KeyEscape, '[', '2', '5', 'm'}
	// Colors
	greenBold        = []byte{KeyEscape, '[', '1', ';', '3', '2', 'm'}
	greyBold         = []byte{KeyEscape, '[', '1', ';', '9', '0', 'm'}
	redBrightBold    = []byte{KeyEscape, '[', '1', ';', '9', '1', 'm'}
	redBold          = []byte{KeyEscape, '[', '1', ';', '3', '1', 'm'}
	yellowBright     = []byte{KeyEscape, '[', '0', ';', '9', '3', 'm'}
	yellowBrightBold = []byte{KeyEscape, '[', '1', ';', '9', '3', 'm'}
	yellow           = []byte{KeyEscape, '[', '0', ';', '3', '3', 'm'}
	blueBrightBold   = []byte{KeyEscape, '[', '1', ';', '9', '4', 'm'}
	cyanBold         = []byte{KeyEscape, '[', '1', ';', '3', '6', 'm'}
	cyanBrightBold   = []byte{KeyEscape, '[', '1', ';', '9', '6', 'm'}
)

func SetColors(enabled bool) {
	if !enabled {
		yellowBright = []byte("")
		yellow = []byte("")
		blueBrightBold = []byte("")
		redBrightBold = []byte("")
		greenBold = []byte("")
		cyanBold = []byte("")
		greyBold = []byte("")
		resetColor = []byte("")
		cursorClear = []byte("")
		cursorUp = []byte("")
		cursorHome = []byte("\n")
	}
}

// Cursor

func CursorEraseLine() string {
	return string(eraseLine)
}

func CursorClear() string {
	return string(cursorClear)
}

func CursorUp() string {
	return string(cursorUp)
}

func CursorHome() string {
	return string(cursorHome)
}

func ClearScreen() string {
	return string(eraseScreen) + string(cursorHome)
}

// Colors

func BlinkText(m string) string {
	return fmt.Sprintf("%s%s%s", string(blink), m, string(resetBlink))
}

func YellowText(m string) string {
	return fmt.Sprintf("%s%s%s", string(yellow), m, string(resetColor))
}

func YellowBrightText(m string) string {
	return fmt.Sprintf("%s%s%s", string(yellowBright), m, string(resetColor))
}

func YellowBrightBoldText(m string) string {
	return fmt.Sprintf("%s%s%s", string(yellowBrightBold), m, string(resetColor))
}

func GreyBoldText(m string) string {
	return fmt.Sprintf("%s%s%s", string(greyBold), m, string(resetColor))
}

func RedBoldText(m string) string {
	return fmt.Sprintf("%s%s%s", string(redBold), m, string(resetColor))
}

func RedBrightBoldText(m string) string {
	return fmt.Sprintf("%s%s%s", string(redBrightBold), m, string(resetColor))
}

func GreenBoldText(m string) string {
	return fmt.Sprintf("%s%s%s", string(greenBold), m, string(resetColor))
}

func CyanBoldText(m string) string {
	return fmt.Sprintf("%s%s%s", string(cyanBold), m, string(resetColor))
}

func CyanBrightBoldText(m string) string {
	return fmt.Sprintf("%s%s%s", string(cyanBrightBold), m, string(resetColor))
}

func BlueBrightBoldText(m string) string {
	return fmt.Sprintf("%s%s%s", string(blueBrightBold), m, string(resetColor))
}
