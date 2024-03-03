# A note on Client

Client could support a new parameter `--listener`.

- Client should spin up a WebServer implementing the same functionality as de Server (Websocket to `net.Conn`).
- Client should act as SSH server and Server as SSH client. 
- Client should reject connections based on SSH authentication