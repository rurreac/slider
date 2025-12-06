# SLIDER

**Slider** is a server / client in a binary that can act as remote administration tool or basic C2. 

The main purpose of Slider was having a lightweight tool, easy to transfer, that would help with remote administration, 
and penetration testing, specially on those cases where the use of some frameworks would be limited due to for instance, 
licenses or other requirements.

Slider can be used to: 
* Send a fully interactive Reverse Shell from Client to Server, 
* Run commands remotely, 
* Upload / download files, 
* Run a reverse socks v5 server, 

All through a cyphered connection, while allowing clients and servers authenticate and verify each other through
[Ed25519](https://ed25519.cr.yp.to/) key pairs.

## How does it work?
In a normal scenario, a Slider Server runs a web server on a given port, waiting for Slider clients to establish websocket
connections. 

Those websocket connections are then transformed into network connections which are then reused to create an SSH Server on
the Server side and an SSH Client on the Client side, encrypting this way the connection and providing a way to authenticate
Servers and Clients to each other. 

Once the connectivity is established (a Session is created) all functionality is requested through SSH requests and
responses with data streamed through SSH Channels or, in some cases, through SSH requests / response payloads.

Clients can also be listeners, in these scenarios Servers will interactively connect to Clients, initiating websocket
client connections while remaining as SSH Servers. 

## External Dependencies
For the sake of keeping the size contained, external libraries are used when they remove a particular overhead or 
drastically simplify the core functionality, while for the rest, only the Standard Library is used.

Currently, if compiled omitting the symbol table and debug information and omitting the DWARF symbol table 
(`-ldflags "-s -w"`), the size is kept below 6mb. 
If also compressing it using [UPX](https://github.com/upx/upx) with the `--brute` flag, the size is kept somewhere 
around 2mb.

Slider Release Binaries are already compressed with [UPX](https://github.com/upx/upx) if supported.

A Makefile is included for local building. When running `make` with no arguments (if [UPX](https://github.com/upx/upx) is installed), a faster 
compression will be applied.
For building binaries with the same compression level as the ones available for download use the `UPX_BRUTE` parameter:

```
make <TARGET> UPX_BRUTE=yes
```
Makefiles for building [Server](server/cmd) or [Client](client/cmd) only, are also included just in case it fits best your
purpose. 
But be aware that size wise the difference between a full build and a server or client build is slightly noticeable, 
and the more compression the less noticeable. 
Generally speaking you would like to stick with the full binary.


## Server

```
Creates a new Slider Server instance and waits for
incoming Slider Client connections on the defined port.

Interaction with Slider Clients can be performed through
its integrated Console by pressing CTR^C at any time.

Usage:
  slider server [flags]

Flags:
      --address string               Server will bind to this address (default "0.0.0.0")
      --auth                         Requires authentication throughout the server
      --ca-store                     Store Server JSON with key and CA for later use
      --ca-store-path string         Path for reading and/or storing a Server JSON
      --caller-log                   Display caller information in logs
      --certs string                 Path of a valid slider-certs json file
      --colorless                    Disables logging colors
      --headless                     Disables the internal console (CTR^C) and enables the Websocket Console
  -h, --help                         help for server
      --http-console                 Enables /console HTTP endpoint
      --http-health                  Enables /health HTTP path
      --http-redirect string         Redirects incoming HTTP to given URL
      --http-server-header string    Sets a server header value
      --http-status-code int         Status code [200|301|302|400|401|403|500|502|503] (default 200)
      --http-template string         Path of a default file to serve
      --http-version                 Enables /version HTTP path
      --json-log                     Enables JSON formatted logging
      --keepalive duration           Sets keepalive interval vs Clients (default 1m0s)
      --listener-ca string           CA for verifying client certificates
      --listener-cert string         Certificate for SSL listener
      --listener-key string          Key for SSL listener
      --port int                     port where Server will listen (default 8080)
      --proto string                 Set your own proto string (default "slider-v1")
      --verbose string               Adds verbosity [debug|info|warn|error|off] (default "info")
```

### Environment Variables

##### `SLIDER_HOME`:
When defined, Slider will use this path to save all information.

When not defined / the environment variable does not exist or has an empty value:
1. Slider will try to obtain the User Home directory. If this fails,
2. Slider will use the current working path.

##### `SLIDER_CERT_JAR`:
When not defined or its value is `1` or `true`. Changes to certificates (creation or deletion),
will be stored.

If any other value is found then changes to certificates won't be stored. Note that if in this case,
the value is not `0` or `false`, you will be warned, just in case this wasn't on purpose.

Slider only creates and uses [Ed25519](https://ed25519.cr.yp.to/) keys.

### Server Flags Overview

##### `--address`:
Local address to bind to. By default, Slider binds to all local addresses

##### `--auth` and `--certs`:
By default, Slider Clients do not require any authentication to connect to Server.

* `--auth`: Requires key authentication to all Clients. If `--http-console` is enabled, the web console will require fingerprint authentication.
* `--certs`: Is an optional parameter, holding the path of a Certificate Jar file. This flag requires authentication to be enabled.

When `--auth` is passed, a few things will and may happen:
1. If `--certs` flag is not provided:
    1. Slider will check if the default certificate file (`client-certs.json`) exists in "[Slider Home directory](#slider_home)".
    2. If `client-certs.json` exists, Slider will load all existing KeyPairs into its Certificate Jar.
    3. If `client-certs.json` does not exist, Slider will initialize its Certificate Jar with a new KeyPair  
       and store it a new `client-certs.json` file.
2. if `--certs` flag is provided:
    1. If the file exists, Slider will load all KeyPairs in its Certificate Jar.
    2. If the file does not exist, Slider will initialize the Certificate Jar with a new certificate and attempt to save it
       in the provided path.

A note of the Certificates Files, whether changes to the Certificate Jar are stored depend on the "[SLIDER_CERT_JAR](#slider_cert_jar)"
environment variable.

The Certificate Jar will be saved in whatever is resolved from the  "[SLIDER_CERT_JAR](#slider_cert_jar)" + `/.certs`
on *nix hosts, or `\certs` on Windows hosts.

##### `--json-log`:
Enables JSON formatted logging output. When enabled, all log messages will be output in JSON format with structured fields including timestamp, scope, level, message, and caller information (if `--caller-log` is also enabled). Might be useful for log aggregation systems, automated log parsing.

##### `--caller-log` (development only):
Enables display of caller information (file name and line number) in log messages. This helps with debugging by showing exactly where each log message originated in the code. Works with both standard and JSON formatted logs.

##### `--colorless`:
By default, regardless of the OS, if Slider runs on a PTY, logs will show their log level using colors. If this flag is passed
then logs will have no colors.

##### `--keepalive`:
By default, Slider pings every Client Session (every 60s) to ensure its available, otherwise kills the Session.

This value can be changed to any other duration value. If the value introduced is inferior to 5s, Slider will override
it to this one.

##### `--ca-store-path` and `--ca-store`:
By default, everytime Slider Server is executed, new in memory KeyPair and CA are generated, and so it's lost on termination.

When the flag `--ca-store` is provided, Slider will store a new KeyPair in disk, but:
1. If `--ca-store-path` was not provided, and the default key file `server-cert.json` exists in the "[Slider Home directory](#slider_home)",
   then it will be loaded instead or overriding it.
2. If `--ca-store-path` was provided:
    1. If the path exists, Slider will attempt to load its KeyPair.
    2. If the path does not exist, Slider will save a new KeyPair in this path.

##### `--port`:
By default, Slider listens in port `8080`. Specify any other port using this flag.

##### `--http-template`, `--http-server-header`, `--http-status-code`:
Allows mimicking another web server while accepts setting a status code and using a file as a template.

This may help you blend Slider with your environment.

The size of the file is currently limited to 2MiB which should be enough for an HTML template with embedded images.

##### `--http-version`:
Disabled by default, it will serve a JSON with current Proto and Slider version at `/version`. 

##### `--http-redirect`:
A redirect parameter must be at least a URL with a valid scheme and host (`http[s]://<host>[:<port>]`).

HTTP connections to the root path `/` will be redirected to the given URL, while the rest of the connections will proceed as usual.

##### `--http-console`:
Disabled by default. If enabled, it will serve the Slider Server Console at `/console` using xterm.js which connects to the Websocket Console. 
If `--auth` is enabled then authentication will be required to access the Websocket Console. 
In order to avoid sending credentials in plain text, enabling authentication also requires the server using TLS, otherwise it will refuse to start.
If `--http-template` and `--http-redirect` are not provided, then the root path will redirect you to the authentication page (if `auth` is enabled) or directly to the console (if `auth` is disabled).

##### `--headless`:
Disabled by default. If enabled, it will disable the internal Console (accessed by CTR^C) and enable the Websocket Console.

##### `--verbose`:
Choose the log level verbosity between debug, info, warn and error. When verbosity is set to `off` only non labeled and
fatal logs will be shown.

##### `--proto`:
Slider uses its own proto value (e.g. `slider-v1`), to ensure that only matching protocols are allowed to proceed
with the websocket upgrade. Among other things to avoid future compatibility issues.

This parameter allows you to specify your own proto value which can be handy, IF:
1. you want to drop any connection attempt other than your own "proto" before attempting the upgrade to websocket.
2. you feel that some kind of IPS for some reason blocks the default proto (because proto is sent as an HTTP header).

##### `--listener-cert`, `--listener-key`, `--listener-ca`:
The flags `--listener-cert` and `--listener-key` allow us to provide your own certificate so we can have a TLS listener.

If the flag `--listener-ca` is provided, the listener will also verify the client certificate against this CA certificate.

### Console

```
Slider# help

  Command   Description                                                 
  -------   -----------                                                 
  bg        Puts Console into background and returns to logging output  
  certs     Interacts with the Server Certificate Jar                   
  connect   Receives the address of a Client to connect to              
  execute   Runs a command remotely and returns the output              
  exit      Exits Console and terminates the Server                     
  help      Shows this output                                           
  portfwd   Creates a port forwarding tunnel to / from a client         
  sessions  Interacts with Client Sessions                              
  shell     Binds to a client Shell         
  socks     Creates a TCP Endpoint bound to a client SOCKSv5 server     
  ssh       Creates an SSH Endpoint that binds to a client              
  !command  Execute "command" in local shell (non-interactive)
```

#### Commands walk through

##### Sessions
```
Slider# sessions -h
When run without parameters, all available Sessions are listed.

Usage: sessions [flags]

  -i, --interactive  Start Interactive Slider Shell on a Session ID (default 0)  
  -d, --disconnect   Disconnect Session ID (default 0)                           
  -k, --kill         Kill Session ID (default 0)                                 

Mutually exclusive flags:

  -i/--interactive, -d/--disconnect, -k/--kill
```
Each connection from a Slider Client creates a new Session, and when that connection is broken or terminated, the
Session is dropped.
The `sessions` command allows you to interact with each opened Session. Through the `sessions` command it is possible
to list, kill, disconnect or receive a Shell from a given Session.

Using the interactive option does not automatically bind to a client shell. Instead, it uses the current terminal to 
interact with the Slider client through SFTP.

This is a handy and quick way to interact with the client, but the key word here is QUICK, if this is not
the case, consider using the `ssh` command to spin up an SSH endpoint to avoid blocking the console but also, for a more 
robust way to handle transfers, shells, etc... 

Running an interactive session provides its own sets of commands:

```
  Command           Description                                          
  -------           -----------                                          
  cd, chdir         Change remote directory                              
  chmod             Change file permissions                              
  execute           Runs a command remotely and returns the output       
  exit              Exits Console and terminates the Server              
  get, download     Download file or directory                           
  help              Shows this output                                    
  lcd               Change local directory                               
  lls, ldir, llist  List local directory contents                        
  lmkdir            Create local directory                               
  lpwd, lgetwd      Show current local directory                         
  ls, dir, list     List remote directory contents                       
  mkdir             Create remote directory                              
  mv, rename, move  Rename or move a file or directory                   
  put, upload       Upload file or directory                             
  pwd, getwd        Show current remote directory                        
  rm, del, delete   Remove file or directory                             
  shell             Binds to a client Shell  
  stat, info        Show detailed file information                       
  !command          Execute "command" in local shell (non-interactive) 
```

A note on the interactive `shell` command:
* If the Client host is running *nix OS or a Windows version with ConPTY (introduced in late 2018) the spawned Shell will be
  fully interactive as well.

A note between killing a Session and disconnecting from a Session: 
* Disconnect closes the Session at the Server side, it would be equivalent to terminating the Server. 
  * If the Client is configured with the `--retry` option, the Client will reconnect to the Server if available on the next
  try, creating a new Session.
  * If the Client is not configured with the `--retry` option, and is NOT configured with the `--listener` option, once it
runs its next keepalive check will shut down.  
* Kill is equivalent to terminating the execution of the Client, independently if it's a regular Client or a Listener one.

##### Connect
```
Slider# connect -h
Usage: connect [flags] <[client_address]:port>

  -i, --cert-id   Specify certID for SSH key authentication (default 0)  
  -d, --dns       Use custom DNS resolver (default "")                   
  -p, --proto     Use custom proto (default slider-v1)                   
  -c, --tls-cert  Use custom client TLS certificate (default "")         
  -k, --tls-key   Use custom client TLS key (default "")                 

Requires exactly 1 argument(s)
```
Regular Clients automatically connect back to the Server, but if we want to open a Session to a Client working as Listener
then we'll need to use the `connect` command.

This command will try to open a Session in the background, and you will be notified whether the connection was
successful or not. `connect` will hold until that confirmation is given, or otherwise considered timed out (10s).

Due to their purpose, Servers will disable Client authentication on connections to a Listener even if the Server is 
started with `--auth`.

I needed, it is possible, to use a custom DNS to resolve the Client, instead of the default one.

Since the Server is the one that initiates the connection to the Listener and the Listener is facing the network,
authentication of Servers will happen on the Client side with `--fingerprint`. 
Servers will be rejected if their fingerprint is not successfully verified. To authenticate to a Listener, use
the `-i` flag to specify the certificate ID that corresponds to the fingerprint used by the listener.

Depending on configuration, a TLS Listener may require you to provide a valid certificate for client authentication. 
In this case, you can provide a certificate and key (flags `-c`, `-k`) signed with the same CA.

##### Execute
```
Slider# execute -h
Usage: execute [flags] [command]

  -s, --session  Run command passed as an argument on a session id (default 0)      
  -a, --all      Run command passed as an argument on all sessions (default false)  

Requires at least 1 argument(s)

One flag required from each group:

  -s/--session, -a/--all  

Mutually exclusive flags:

  -s/--session, -a/--all 
```
If you want to run a single OS command on a client rather than interacting with the session itself you can use Console
`execute` command.

Considerations on `execute`:
* Allows you to pass redirections or pipes to the Client as part of the command as well.
* Doesn't run in fully interactive mode.
* Standard input is not sent to the Client.
* It is possible to terminate the execution by pressing CTR^C.

If you need something more interactive or don't want to keep the console busy, consider using `ssh` or `shell` commands.

##### SOCKS
```
Slider# socks -h
Usage: socks [flags]

  -s, --session  Run a Socks5 server over an SSH Channel on a Session ID (default 0)              
  -p, --port     Use this port number as local Listener, otherwise randomly selected (default 0)  
  -k, --kill     Kill Socks5 Listener and Server on a Session ID (default 0)                      
  -e, --expose   Expose port to all interfaces (default false)                                    

One flag required from each group:

  -s/--session, -k/--kill  

Mutually exclusive flags:

  -k/--kill, -s/--session  
  -k/--kill, -p/--port     
  -k/--kill, -e/--expose 
```
Slider will create an SOCKSv5 server on the Client side and forward the connection to the Server side on the specified port,
or a port randomly selected if not specified.

If a port is not specified using the `-p` flag, it will be automatically assigned.

By default, the Socks server will be exposed only to localhost, but you can use the `-e` flag to expose it to all interfaces.

##### SSH
```
Slider# ssh -h
Usage: ssh [flags]

  -s, --session  Session ID to establish SSH connection with (default 0)  
  -p, --port     Local port to forward SSH connection to (default 0)      
  -k, --kill     Kill SSH port forwarding to a Session ID (default 0)     
  -e, --expose   Expose port to all interfaces (default false)            

One flag required from each group:

  -s/--session, -k/--kill  

Mutually exclusive flags:

  -k/--kill, -s/--session  
  -k/--kill, -p/--port     
  -k/--kill, -e/--expose 
```
Slider will create an SSH server on the Server side on the specified port, or a port randomly selected if not specified,
and forward the connection to the Client side through another SSH channel.

By default, the SSH server will be exposed only to the localhost interface, but you can use the `-e` flag to expose it
to all interfaces.

The only supported authentication methods are anonymous and Public/Private key.

While it is not a full implementation, this SSH connection opens the following possibilities:
* Connect to a Client Shell using any SSH client.
* Transfer files using any SFTP client or `scp`.
* Connect to the Client using any SSH client and run commands on it.
* Connect to the Client through SSH and run a reverse Socks v5 server.
* Local and Remote Port forwarding.

If server authentication is enabled you must authenticate using the SSH key that matches the certificated used to
authenticate Client and Server.
Note that the key passed used is not a valid SSH key itself, but you can get it by running `certs -d <certID>` command 
on the console.

A few considerations:
* When using SFTP, if authentication is off, some clients such as [FileZilla](https://filezilla-project.org/) will require you to set up an 
anonymous connection to the server.
* If the Client supports PTYs, the SSH connection will be fully interactive as well, also, window size changes events will
be sent to the Client.
* If the Client does not support PTYs, like, for instance, some Windows versions (< Windows 10 build 18362), the SSH 
connection will be non-interactive, ergo, pressing CTRL^C will kill the SSH connection.

##### Shell
```
Slider# shell -h
Usage: shell [flags]

  -s, --session      Target Session ID for the shell (default 0)               
  -p, --port         Use this port number as local Listener, otherwise randomly selected (default 0)  
  -k, --kill         Kill Shell Listener and Server on a Session ID (default 0)                       
  -i, --interactive  Interactive mode, enters shell directly. Always TLS (default false)              
  -t, --tls          Enable TLS for the Shell (default false)                                         
  -e, --expose       Expose port to all interfaces (default false)                                    

One flag required from each group:

  -s/--session, -k/--kill  

Mutually exclusive flags:

  -k/--kill, -s/--session        
  -k/--kill, -p/--port           
  -k/--kill, -i/--interactive    
  -k/--kill, -t/--tls            
  -k/--kill, -e/--expose         
  -i/--interactive, -e/--expose  
  -i/--interactive, -t/--tls 
```
Slider will open a port locally that will allow you to bind to a Client Shell using [netcat](https://nmap.org/ncat/), 
or `openssl` for cyphered connections with the tls flag `-t`, which may be useful is `ssh` is not at hand. 

By default, the Shell will be exposed only to the localhost interface, but you can use the `-e` flag to expose it to 
all interfaces.

A few considerations:
* If the client supports PTYs the Shell can be upgraded to fully interactive as well.
* If the client is Windows and supports PTYs you will want to connect through `stty raw -echo && nc <host> <port>` or 
`stty raw -echo && openssl s_client --quiet --connect <host>:<port>` if tls enabled, to bind to the shell. 
Otherwise, you may end up with a dummy shell.

##### Certs
```
Slider# certs -h
When run without parameters, all available Slider key pairs are listed.

Usage: certs [flags]

  -n, --new       Generate a new Key Pair (default false)                     
  -r, --remove    Remove matching index from the Certificate Jar (default 0)  
  -d, --dump-ssh  Dump corresponding CertID SSH keys (default 0)              
  -c, --dump-ca   Dump CA Certificate and key (default false)                 

Mutually exclusive flags:

  -n/--new, -r/--remove, -d/--dump-ssh, -c/--dump-ca  
```
The `certs` command requires that authentication is enabled on the Server otherwise it won't be available.

Usually if the Server was run with `--auth` enabled there will be at least 1 KeyPair in the Certificate Jar.
The Private Key contained within the Keypair can be passed to the client so that it will authenticate against the Server.

Spinning up an SSH endpoint when authentication is enabled will require providing a valid certificate. 
Using the `-d`flag we can dump the SSH certificate matching the CertID use by the session and use it for any interaction with the SSH endpoint (ssh, sftp, scp, ...).

Note that when dumping certificates, `SLIDER_CERT_JAR` defines if the Certificate with the given ID is saved or not, by default, it will be stored locally, and you'll get the path.
If `SLIDER_CERT_JAR` is set to `false`, the Certificate will be dumped to the console and not saved.

We can also dump the server Certificate Authority certificate and key which we can use to generate our own certificates for creating TLS listeners.
If the server was run with the `--ca-store` flag, the CA certificate and key will be saved to disk, otherwise since it is ephemeral it will be just dump to the console.

If we generated our own certificates for server or client listeners with this CA, we can also provide this CA to authenticate
listener client certificates.

Once you have the dump the CA certificate and key, you can use them to create your own certificates for client listeners as in the example below:

1. Generate ECDSA/prime256v1 key:
```
c_name="http-listener"
openssl ecparam -genkey -name prime256v1 -out $c_name.key
```
      While you can use the ed25519 algorithm (`openssl genpkey -algorithm ED25519 -out $c_name.key`), it is not supported by all browsers and will error. 
2. Generate certificate (replace host/IP as necessary):
```
openssl req -new -key $c_name.key -out $c_name.csr -subj "/CN=localhost" \
-addext "subjectAltName = DNS:localhost,IP:127.0.0.1"
```
3. Sign certificate using CA:
```
openssl x509 -req -in $c_name.csr -CA ca_cert.pem -CAkey ca_key.pem \
-CAcreateserial -out signed-$c_name.crt -days 9999 -sha256 -copy_extensions copyall
```

##### Portfwd
```
Slider# portfwd -h
Usage: portfwd [flags] <[addressA]:portA:[addressB]:portB>

  -s, --session  Session ID to add or remove Port Forwarding (default 0)                                          
  -L, --local    Local Port Forwarding <[local_addr]:local_port:[remote_addr]:remote_port> (default false)        
  -R, --reverse  Reverse format: <[allowed_remote_addr]:remote_port:[forward_addr]:forward_port> (default false)  
  -r, --remove   Remove Port Forwarding from port passed as argument (requires L or R) (default false)            

Mutually exclusive flags:

  -L/--local, -R/--reverse 
```
Allows creating / removing Local and Remote port forwards dynamically over a specific session.

Running the command without arguments will display all Port Forwards.
* Any Remote Port forward that has been created through an SSH endpoint will be displayed as well. Its destination 
information won't be displayed as that is known only within the context of the SSH client.
* Terminating a Remote Port forward created through an SSH endpoint won't be allowed.
* Any Local Port Forward created through an SSH endpoint won't be displayed since the endpoint creation is handled within 
the SSH client.

## Client

```
Creates a new Slider Client instance and connects
to the defined Slider Server.

Usage:
  slider client [server_address] [flags]

Flags:
      --address string              Address the Listener will bind to (default "0.0.0.0")
      --caller-log                  Display caller information in logs
      --colorless                   Disables logging colors
      --dns string                  Uses custom DNS server <host[:port]> for resolving server address
      --fingerprint string          Server fingerprint for host verification (listener)
  -h, --help                        help for client
      --http-health                 Enables /health HTTP path
      --http-redirect string        Redirects incoming HTTP to given URL (listener)
      --http-server-header string   Sets a server header value (listener)
      --http-status-code int        Template Status code [200|301|302|400|401|403|500|502|503] (listener) (default 200)
      --http-template string        Path of a default file to serve (listener)
      --http-version                Enables /version HTTP path
      --json-log                    Enables JSON formatted logging
      --keepalive duration          Sets keepalive interval in seconds (default 1m0s)
      --key string                  Private key for authenticating to a Server
      --listener                    Client will listen for incoming Server connections
      --listener-ca string          CA for verifying server certificates (mTLS)
      --listener-cert string        Certificate for SSL listener
      --listener-key string         Key for SSL listener
      --port int                    Listener port (default 8081)
      --proto string                Set your own proto string (default "slider-v1")
      --retry                       Retries reconnection indefinitely
      --tls-cert string             TLS client Certificate
      --tls-key string              TLS client Key
      --verbose string              Adds verbosity [debug|info|warn|error|off] (default "info")
```

### Client Flags Overview

#### Common Client Flags

##### `--json-log`:
Enables JSON formatted logging output. When enabled, all log messages will be output in JSON format with structured fields including timestamp, scope, level, message, and caller information (if `--caller-log` is also enabled). This is useful for log aggregation systems and automated log parsing.

##### `--caller-log` (development only):
Enables display of caller information (file name and line number) in log messages. This helps with debugging by showing exactly where each log message originated in the code. Works with both standard and JSON formatted logs.

##### `--colorless`:
The same as with the Server, by default, regardless of the OS, if Slider runs on a PTY, logs will show their log level using
colors. If this flag is passed then logs will have no colors.

##### `--keepalive`:
By default, Slider pings every Server Session (every 60s) to ensure it's available, otherwise it kills the Session.

This value can be changed to any other duration value. If the value introduced is inferior to 5s, Slider will override
it to this one.

Keepalive ensures that non listener clients terminate their connection to the server and shutdown, completely disabling
the keepalive will leave not listener clients hanging forever.

#### Listener Client Flags

##### `--listener`, `--address` and `--port`:
A Slider Client by default connects back to a server on a given address:port (Reverse Client), but it is also possible to run a Slider
Client in Listener mode (`--listener`).

When used as Listener it will listen for incoming connections on a bound address (`--address`) and port (`--port`). If not
configured, their default values are `0.0.0.0` and `8081` respectively.

One or several Servers will be able to open N number of sessions to a Client working as Listener at the same time.

The main two reasons for using a Slider Client on Listener mode are:
* The Server is located on a private network and a regular Client would not be able to reach it.
* Several Servers may want to collaborate on the same Client or use a particular Client as a gateway.

##### `--fingerprint`:
A Slider fingerprint represents a sha256sum string of a base64 encoded public key.

This flag could either be a fingerprint string or a file containing a list fingerprints, each one of them representing
a different Slider Server. This is useful when we want to be able to authorize several Servers by their public key.
A connection from a Server with a fingerprint not successfully verified will be rejected.

##### HTTP flags:
Same considerations as in Server HTTP flags documentation applies.

#### Reverse Client Flags

##### `--retry`:
A Reverse Client configured with the `--retry` flag will try to reconnect to the server according to its `--keepalive` 
value. You will very likely want to tune `--keepalive` to either short reconnection intervals or expand them fitting 
your needs.

Enabling `--retry` will only have an effect if the Client was able to connect to the Server at least once, in other words, 
if the Client fails to connect to the Server on the first run it will terminate its execution as usual.

Combining Client `--retry` with Server `--auth` and maintaining different Certificate Jar Files, is a great way to work 
between different "Workspaces" where using one Certificate Jar or another will determine what Clients will automatically
reconnect to your Server and create a Session.

##### `--key`:
A Slider Key represents an Ed25519 private key base64 encoded.

Keys will only be used against a Server with authentication enabled, otherwise they will be disregarded.

A Client would use a key generated by the Server and stored in its Certificate Jar, since a Client using any
certificate in the Server Certificate Jar will be authorized to connect.

`--key` offers a way to authenticate Clients on Servers with `--auth` enabled. If the Server was not configured with 
authentication, providing `--key` won't have any effect.

##### `--dns`:
Allows you to provide a custom DNS to resolve the Server address rather than using the default DNS servers.

##### `--proto`:
The same considerations as for the server apply.

##### `--tls-cert`, `--tls-key`:
Authenticate to a server using a specific certificate. This will be required if server uses `--listener-ca` for certificate
validation. 
The provided certificate must have been generated using the same CA. 

##### `--listener-cert`, `--listener-key`, `--listener-ca`:
The same considerations as for the server apply.


## Hook

```
Connects to a Slider Server's web console endpoint (/console/ws)
and provides access to a remote slider console through your local terminal.

Usage:
  slider hook [flags] <server_url>

Flags:
      --ca string            CA certificate for server verification
      --client-cert string   Client certificate for mTLS
      --client-key string    Client private key for mTLS
      --fingerprint string   Certificate fingerprint for authentication
  -h, --help                 help for hook
      --server-name string   Server name for TLS verification
```

The `hook` command provides a way to connect to a Slider Server's web console directly from your local terminal, without needing a web browser. This might be useful if:
* Accessing the server console from remote environments without a graphical interface
* Automating console interactions through scripts
* Connecting to servers in headless mode

### Hook Flags Overview

##### `--fingerprint`:
When the server has authentication enabled (`--auth`), you must provide a valid certificate fingerprint to authenticate. The hook command will:
1. Exchange the fingerprint for a JWT token via the `/auth/token` endpoint
2. Use the JWT token to authenticate the WebSocket connection to `/console/ws`

This flag is required when connecting to servers with `--auth` enabled.

##### `--client-cert` and `--client-key`:
When connecting to a server that uses TLS with client certificate verification (`--listener-ca`), you must provide a valid client certificate and private key. These must be signed by the same CA that the server trusts.

These flags are mutually required - if you provide one, you must provide the other.

##### `--ca`:
Specifies a CA certificate to verify the server's TLS certificate. Consider using this flag if:
* The server uses a self-signed certificate
* You want to verify the server's identity against a specific CA

When using this flag, you should also provide `--server-name` to specify the expected server name.

##### `--server-name`:
Specifies the server name for TLS verification. This is used in combination with `--ca` to verify that the server's certificate matches the expected server name.

