# SLIDER

- [What is Slider](#what-is-slider)
- [How does it work?](#how-does-it-work)
- [Server](#server)
  - [Environment Variables](#environment-variables)
  - [Flags Overview](#server-flags-overview)
  - [Console](#console)
- [Client](#client) 
  - [Flags Overview](#client-flags-overview)
- [External Dependencies](#external-dependencies)

## What is Slider

Started to work on Slider to have a tool as small as possible that would help maintaining persistence during Pentesting,
sending an encrypted reverse shell from client to server, specially for those cases where the use of some frameworks 
would be limited for whatever reason.

Then I thought that the functionality could be extended while the size could be kept reduced, why not, also. that 
would allow using it in some other scenarios.

Currently, if compiled omitting the symbol table and debug information and omitting the DWARF symbol table (`-ldflags "-s -w"`),
the size is kept below 6mb. If also compressing it using [UPX](https://github.com/upx/upx) with the `--brute` flag, 
the size is kept somewhere around 2mb.

Slider is a Server and a Client within the same binary. It can be used to send a fully interactive reverse shell from 
client to server but also, run commands remotely, upload / download files, as well as running a reverse socks v5 server,
all through a cyphered connection, while allowing clients and servers authenticate to each other. 

## How does it work?
In a nutshell, Slider works this way:

```mermaid
sequenceDiagram
    participant server
    participant client
    server ->> server: HTTP Server listens on port X
    client ->> server: Client connects thought HTTP to Server and requests upgrade to Websocket
    client --> server: Websocket connection is created and session is established
    server ->> server: Websocket connection is transformed to net.Conn
    client ->> client: Websocket connection is transformed to net.Conn
    server ->> server: net.Conn is used to create an SSH Server
    client ->> client: net.Conn is used to create an SSH Client
    client ->> server: Client connects to Server through SSH
    server --> client: Server Interact with Client Session through its integrated console
```

## External Dependencies
I had quite a few debates with myself while working on this project cause there are so many great libraries out there 
for implementing flags, logging, commands, terminal UI, etc. that choosing not to use them could in some way limit the
functionality or overcomplicate things.

Since binary size was a key factor (a small binary easy to move around without making too much noise), decided
to stick to the Standard Library as much as possible, using external libraries for those things that would make the 
core implementation easier and discard those that would make UI nicer. 

Currently Slider uses the following external dependencies:
* [github.com/gorilla/websocket](https://github.com/gorilla/websocket)
* [github.com/creack/pty](https://github.com/creack/pty)
* [github.com/UserExistsError/conpty](https://github.com/UserExistsError/conpty)
* [github.com/armon/go-socks5](https://github.com/armon/go-socks5)


## Server

```
Slider Server

  Creates a new Slider Server instance and waits for 
incoming Slider Client connections on the defined port.

  Interaction with Slider Clients can be performed through
its integrated Console by pressing CTR^C at any time.

Usage: ./slider server [flags]

Flags:
  -address string
    	Server will bind to this address (default "0.0.0.0")
  -auth
    	Enables Key authentication of Clients
  -certs string
    	Path of a valid slider-certs json file
  -colorless
    	Disables logging colors
  -keepalive duration
    	Sets keepalive interval vs Clients (default 1m0s)
  -keypath string
    	Path for reading or storing a Server key
  -keystore
    	Store Server key for later use
  -port string
    	Port where Server will listen (default "8080")
  -verbose string
    	Adds verbosity [debug|info|warn|error|off] (default "info")
```
### Environment Variables

#### `SLIDER_HOME`: 
When defined, Slider will use this path to save all information.

When not defined / the environment variable does not exist or has an empty value: 
1. Slider will try to obtain the User Home directory. If this fails,
2. Slider will use the current working path.

#### `SLIDER_CERT_JAR`:
When not defined or its value is `1` or `true`. Changes to certificates (creation or deletion), 
will be stored.

If any other value is found then changes to certificates won't be stored. Note that if in this case,
the value is not `0` or `false`, you will be warned, just in case this wasn't on purpose. 

### Server Flags Overview

#### `-address`: 
Local address to bind to. By default, Slider binds to all local addresses

#### `-auth` and `-certs`:
By default, Slider Clients do not require any authentication to connect to Server.

* `-auth`: Enables and requires SSH Key-Based authentication to all Clients.
* `-certs`: Is an optional parameter, holding the path of a Certificate Jar file. This flag requires authentication is 
enabled.

When `-auth` is passed, a few things will and may happen:
  1. If `-cert` flag is not provided:
     1. Slider will check if the default certificate file (`client-certs.json`) exists in "[Slider Home directory](#slider_home-)". 
     2. If `client-certs.json` exists, Slider will load all existing KeyPairs into its Certificate Jar. 
     3. If `client-certs.json` does not exist, Slider will initialize its Certificate Jar with a new KeyPair  
  and store it a new `client-certs.json` file.
  2. if `-cert` flag is provided:
     1. If the file exists, Slider will load all KeyPairs in its Certificate Jar. 
     2. If the file does not exist, Slider will initialize the Certificate Jar with a new certificate and attempt to save it 
     in the provided path.

A note of the Certificates Files, whether changes to the Certificate Jar are stored depend on the "[SLIDER_CERT_JAR](#slider_cert_jar)"
environment variable.

The Certificate Jar will be saved in whatever is resolved from the  "[SLIDER_CERT_JAR](#slider_cert_jar)" + `/.certs` 
on *nix hosts, or `\certs` on Windows hosts.

#### `-colorless`:
By default, regardless of the OS, if Slider runs on a PTY, logs will show their log level using colors. If this flag is passed
then logs will have no colors.

#### `-keepalive`:
By default, Slider pings every Client Session (every 60s) to ensure its available, otherwise kills the Session.

This value can be changed to any other duration value or set to `0` to completely disable it.

#### `-keypath` and `-keystore`:
By default, everytime Slider Server is executed, a new in memory KeyPair is generated, and so it's lost on termination.

When the flag `-keystore` is provided, Slider will store a new KeyPair in disk, but:
1. If `-keypath` was not provided, and the default key file `server-cert.json` exists in the "[Slider Home directory](#slider_home-)", 
  then it will be loaded instead or overriding it.
2. If `-keypath` was provided:
   1. If the path exists, Slider will attempt to load its KeyPair.
   2. If the path does not exist, Slider will save a new KeyPair in this path.

#### `-port`:
By default, Slider listens in port `8080`. Specify any other port using this flag.

#### `verbose`:
Choose the log level verbosity between debug, info, warn and error. When verbosity is set to `off` only non labeled and
 fatal logs will be shown. 

### Console

```
Slider > help

  Commands  Description  

  bg        Puts Console into background and returns to logging output                                          
  certs     Interacts with the Server Certificate Jar                                                           
  connect   Receives the address of a Client to connect to                                                      
  download  Downloads file passed as an argument from Client                                                    
  execute   Runs a command remotely and returns the output                                                      
  exit      Exits Console and terminates the Server                                                             
  help      Shows this output                                                                                   
  sessions  Interacts with Client Sessions                                                                      
  socks     Runs / Stops a Socks server on the Client SSH Channel and a Listener to that channel on the Server  
  upload    Uploads file passed as an argument to Client
```

#### Commands walk through

##### Sessions
```
Slider > sessions -h
Interacts with Client Sessions

When run without parameters, all available Sessions will be listed.

Usage: sessions [flags]

Flags:
  -i int
    	Starts Interactive Shell on a Session ID
  -k int
    	Kills Session ID
```
Each connection from a Slider Client creates a new Session, and when that connection is broken or terminated, the
Session is dropped.
The `sessions` command allows you to interact with each opened Session. Through the `sessions` command it is possible 
to list Sessions, kill a Session or receive a Shell from a given Session. 

If the Client host is running *nix OS or a Windows version with ConPTY (introduced in 2018) the spawned Shell will be
fully interactive as well.

##### Connect
```
Slider > connect -h
Receives the address of a Client to connect to

Connects to a Client configured as Listener and creates a new Session

Usage: connect <client_address:port>
```
Regular Clients automatically connect back to the Server, but if we want to open a Session to a Client working as Listener
then we'll need to use the `connect` command.
This command will try to open a Session in the background, and you will be notified whether the connection was 
successful or not. `connect` will hold until that confirmation is given, or otherwise considered timed out (10s).

##### Execute
```
Slider > execute -h
Runs a command remotely and returns the output

Usage: execute [flags] [command]

Flags:
  -a	Runs given command on every Session
  -s int
    	Runs given command on a Session ID
```
If you want to run a single OS command on a client rather than interacting with the session itself you can use Console
`execute` command.
Note that `execute` will allow you to pass redirections or pipes to the Client as part of the command as well.

##### Socks
```
Slider > socks -h
Runs / Stops a Socks server on the Client SSH Channel and a Listener to that channel on the Server

Usage: socks [flags]

Flags:
  -k int
    	Kills Socks5 Listener and Server on a Session ID
  -p int
    	Uses this port number as local Listener, otherwise randomly selected
  -s int
    	Runs a Socks5 server over an SSH Channel on a Session ID
```
If we would like to create a reverse Socks v5 server (or kill an existing one), we could do it using the `socks` 
command.
Under the hood a specific SSH Channel is created for this purpose. The Client creates a Socks server and sends it
to the Channel while the Server opens a local port and send the incoming connections to the other end of that same 
Channel.  
By default `socks` only requires specifying a Client Session and the Server local port will be automatically assigned
by the OS, but we can also specify a port using the `-p`.

##### Upload
```
Slider > upload -h
Uploads file passed as an argument to Client

Note that if no destination name is given, file will be uploaded with the same basename to the Client CWD.

Usage: upload [flags] [src] [dst]

Flags:
  -s int
    	Uploads file to selected Session ID
```
Mostly self-explanatory. Note that `[dst]` if provided must be a filepath. Also, be mindful to your destination, cause
if the file exists and the User that is running the Client has the right permissions, the contents of the file will
be overridden.

Checksum of the file is checked, if there is a mismatch you'll be warned.

##### Download
```
Slider > download -h
Downloads file passed as an argument from Client

* If no destination name is given, file will be downloaded with the same basename to the Server CWD.
* Downloading from a file list does not allow specifying destination.  

Usage: download [flags] [src] [dst]

Flags:
  -f string
    	Receives a file list with items to download
  -s int
    	Downloads file from a given a Session ID
```
Allows you to `download` a file from the client. 

It is possible to pass a file list as an argument with the `-f` flag. Using this flag does not allow specifying a
destination. All files in the file list will be downloaded to [Slider Home Directory](#slider_home-). 
Each file will be saved with a concatenated name of the filepath as its basename.

Checksum of the file is checked, if there is a mismatch you'll be warned.

##### Certs
```
Slider > certs -h
Interacts with the Server Certificate Jar

When run without parameters, all available KeyPairs in the Certificate Jar will be listed.

Usage: certs [flags]

Flags:
  -n	Generate a new Key Pair
  -r int
    	Remove matching index from the Certificate Jar
```
The `certs` command requires that authentication is enabled on the Server otherwise it won't be listed or available.

Usually if the Server was run with `-auth` enabled there will be at least 1 KeyPair in the Certificate Jar.
The Private Key contained within the Keypair can be passed to the client so that it will authenticate against the
Server.

## Client

```
Slider Client

  Creates a new Slider Client instance and connects 
to the defined Slider Server.

Usage: ./slider client [flags] <[server_address]:port>

Flags:
  -address string
    	Address the Listener will bind to (default "0.0.0.0")
  -colorless
    	Disables logging colors
  -fingerprint string
    	Server fingerprint for host verification
  -keepalive duration
    	Sets keepalive interval in seconds. (default 1m0s)
  -key string
    	Private key to use for authentication
  -listener
    	Client will listen for incoming Server connections
  -port int
    	Listener Port (default 8081)
  -verbose string
    	Adds verbosity [debug|info|warn|error|off] (default "info")
```

### Client Flags Overview

#### `-listener`, `-address` and `-port`:
A Slider Client by default connects back to a server on a given address:port, but it is also possible to run a Slider 
Client in Listener mode (`-listener`). 

When used as Listener it will listen for incoming connections on a bound address (`-address`) and port (`-port`). If not 
configured, their default values are `0.0.0.0` and `8081` respectively.

One or several Servers will be able to open N number of sessions to a Client working as Listener at the same time.

The main two reasons for using a Slider Client on Listener mode are:
* The Server is located on a private network and a regular Client would not be able to reach it.
* Several Servers may want to collaborate on the same Client or use a particular Client as a gateway.

#### `-colorless`:
Same as with the Server, by default, regardless of the OS, if Slider runs on a PTY, logs will show their log level using 
colors. If this flag is passed then logs will have no colors.

#### `-fingerprint`:
A Slider fingerprint represents a sha256sum string of a base64 encoded public key.

This flag could either be a sha256sum string or a file containing a list of sha256sum string, each one of them representing
a different Slider Server. This is useful in particular when the Client is running as Listener, and we want to be able to
authorize several Servers by their public key.
A connection from a Server with a fingerprint not successfully verified will be rejected. 

#### `-keepalive`:
By default, Slider pings every Server Session (every 60s) to ensure its available, otherwise kills the Session.

This value can be changed to any other duration value or set to `0` to completely disable it.

Keepalive ensures that non listener clients terminate their connection to the server and shutdown, completely disabling
the keepalive will leave not listener clients hanging forever. 

#### `-key`:
A Slider Key represents an Ed25519 private key base64 encoded. 

Keys will only be used against a Server with authentication enabled otherwise will be disregarded.

A Client would use a key generated on a server and stored in its Certificate Jar, since a Client using any
certificate in the Server Certificate Jar will be authorized to connect.

Typically, you would like to use `-fingerprints` to authenticate Servers on publicly exposed Clients (running as Listeners)
and `-key` to authenticate Clients on Servers with `-auth` enabled.



