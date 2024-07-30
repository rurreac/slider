package web

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
	iisTemplate = `<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
<title>IIS Windows Server</title>
<style type="text/css">
<!--
body {
	color:#000000;
	background-color:#0072C6;
	margin:0;
}

#container {
	margin-left:auto;
	margin-right:auto;
	text-align:center;
	}

a img {
	border:none;
}
-->
</style>
</head>
<body>
<div id="container">
<a href="http://go.microsoft.com/fwlink/?linkid=66138&amp;clcid=0x409"><img src="iisstart.png" alt="IIS" width="960" height="600" /></a>
</div>
</body>
</html>`
	tomcatTemplate = `<!doctype html>
<html lang="en">
<head><title>HTTP Status 404 – Not Found</title>
<style type="text/css">
body {
	font-family:Tahoma,Arial,sans-serif;
} 
h1, h2, h3, b {
	color:white;background-color:#525D76;
} 
h1 {
	font-size:22px;
} 
h2 {
	font-size:16px;
} 
h3 {
	font-size:14px;
} 
p {
	font-size:12px;
} 
a {
	color:black;
} 
.line {
	height:1px;background-color:#525D76;border:none;
}
</style></head>
<body>
<h1>HTTP Status 404 – Not Found</h1>
<hr class="line" />
<p><b>Type</b> Status Report</p>
<p><b>Message</b> The requested resource [&#47;] is not available</p>
<p><b>Description</b> 
The origin server did not find a current representation for the target resource or is not willing to disclose that one exists.</p>
<hr class="line" /><h3>Apache Tomcat</h3></body></html>`
)
