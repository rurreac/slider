package wtemplate

import "fmt"

const (
	apacheTemplate = `<html><body><h1>It works!</h1>
<p>This is the default web page for this server.</p>
<p>The web server software is running but no content has been added, yet.</p>
</body></html>`
	nginxTemplate = `<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
    body {
        width: 35em;
        margin: 0 auto;
        font-family: Tahoma, Verdana, Arial, sans-serif;
    }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>`
)

var (
	knownTemplates = map[string]string{
		"apache": apacheTemplate,
		"nginx":  nginxTemplate,
	}
)

func GetTemplate(b string) (string, error) {
	var err error
	t, ok := knownTemplates[b]
	if !ok {
		err = fmt.Errorf("backend template not found")
	}

	return t, err
}
