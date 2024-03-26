package conf

import "slider/pkg/interpreter"

type ClientInfo struct {
	Interpreter *interpreter.Interpreter
	IsListener  bool
}
