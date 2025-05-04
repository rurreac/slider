package types

import "net/url"

type VersionHolder struct {
	ProtoVersion string `json:"ProtoVersion"`
	Version      string `json:"Version"`
}

type HttpHandler struct {
	TemplatePath string
	ServerHeader string
	StatusCode   int
	UrlRedirect  *url.URL
	VersionOn    bool
	HealthOn     bool
}
