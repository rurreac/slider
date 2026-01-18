package conf

import "slider/pkg/interpreter"

type ClientInfo struct {
	Interpreter *interpreter.Interpreter
	Identity    string `json:"identity,omitempty"` // Server identity (fingerprint:port), optional
}
