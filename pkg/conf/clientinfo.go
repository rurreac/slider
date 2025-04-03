package conf

import "slider/pkg/interpreter"

type ClientInfo struct {
	Interpreter *interpreter.Interpreter
}

// TermDimensions is the custom structure of a message
// for window size info
type TermDimensions struct {
	Width  uint32
	Height uint32
	X      uint32
	Y      uint32
}
