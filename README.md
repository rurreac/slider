# SLIDER

## What is Slider for

Slider wants to be a tool used during Pentesting. 

Consisting in a Server / Client binary, in this early stage, Slider can be utilized to send a 
fully interactive Reverse Shell back to the Pentester host (or achieve RCE) while pursuing a low detection level 
using a well known protocol through an encrypted connection.

## How does it work

In a nutshell, Slider works this way:

```mermaid
sequenceDiagram
    participant server
    participant client
    server ->> server: HTTP Server listens on port X 
    client ->> server: Client connects thought HTTP to Server and requests upgrade to Websocket
    client --> server: Websocket connection is created and session is established
    server ->> server: Websocket connection is transformed to net.Conn
    server ->> server: net.Conn is used to create an SSH Server
    client ->> client: Client uses Websocket connection to create an SSH client
    client ->> server: Client connects to Server through SSH
    client ->> server: Client runs Shell into a PTY and sends it to the Server
    server ->> server: Client opens a Channel Session to Server for later use
    server --> client: Server request Reverse Shell or RCE using Client Session
```
### Slider Server Output
![Slider Server](doc/slider_server.png)

### Slider Client Output
![Slider Client](doc/slider_client.png)



