# Package Slider Connection

## Foreground
The final purpose is creating an interactive, encrypted and authenticated connection 
between client and server while using a stealthier usually non-blocked protocol 
such as HTTP.

We are initiating the connection to the server using HTTP and then upgrading the connection 
to a websocket connection ([websocket.Conn](https://pkg.go.dev/github.com/gorilla/websocket#Conn)).

Then we will create an SSH connection using the websocket connection as the underlying transport.

Afterward we may be able to use this SSH connection for other purposes such us setting up a 
socks proxy or sending a reverse shell to the server.

## Using websocket.Conn as net.Conn

SSH client ([ssh.NewClientConn](https://pkg.go.dev/golang.org/x/crypto/ssh#NewClientConn)) and server ([ssh.NewServerConn](https://pkg.go.dev/golang.org/x/crypto/ssh#NewServerConn)) 
require a net connection ([net.Conn](https://pkg.go.dev/net#Conn)) as the underlying transport. 

In order to reuse our websocket connection, we need to convert the websocket connection ([websocket.Conn](https://pkg.go.dev/github.com/gorilla/websocket#Conn)) 
into a network connection ([net.Conn](https://pkg.go.dev/net#Conn)).
This requires implementing Read, Write and SetDeadLine methods.





