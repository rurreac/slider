package web

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type Template struct {
	HtmlTemplate string
	ServerHeader string
	StatusCode   int
}

var (
	enabledTemplates = map[string]Template{
		"apache": {
			HtmlTemplate: apacheTemplate,
			ServerHeader: "Apache",
			StatusCode:   http.StatusOK,
		},
		"nginx": {
			HtmlTemplate: nginxTemplate,
			ServerHeader: "nginx",
			StatusCode:   http.StatusOK,
		},
		"iis": {
			HtmlTemplate: iisTemplate,
			ServerHeader: "Microsoft-IIS",
			StatusCode:   http.StatusOK,
		},
		"tomcat": {
			HtmlTemplate: tomcatTemplate,
			ServerHeader: "Apache Tomcat",
			StatusCode:   http.StatusNotFound,
		},
		"default": {
			HtmlTemplate: "OK",
			StatusCode:   http.StatusOK,
			ServerHeader: "",
		},
	}
)

func GetTemplate(n string) (Template, error) {
	t, ok := enabledTemplates[strings.ToLower(n)]
	if !ok {
		return enabledTemplates["default"], fmt.Errorf("template not found, using default")
	}

	return t, nil
}

func CheckURL(u string) error {
	pURL, uErr := url.Parse(u)
	if uErr != nil {
		return fmt.Errorf("not a valid URL")
	}
	if pURL.Scheme == "" || pURL.Host == "" {
		return fmt.Errorf("expecting a full URL including scheme and host")
	}

	return nil
}
