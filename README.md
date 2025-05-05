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

Currently Slider uses the following external dependencies:
* [gorilla/websocket](https://github.com/gorilla/websocket) - implementation of the WebSocket Protocol
* [creack/pty](https://github.com/creack/pty) - managing PTYs on *nix systems
* [UserExistsError/conpty](https://github.com/UserExistsError/conpty) - managing PTYs on Windows Systems
* [armon/go-socks5](https://github.com/armon/go-socks5) - using an existing network connection as socks transport
* [pkg/sftp](https://github.com/pkg/sftp) - SFTP server side implementation


## Server

```
Slider Server

  Creates a new Slider Server instance and waits for
incoming Slider Client connections on the defined port.

  Interaction with Slider Clients can be performed through
its integrated Console by pressing CTR^C at any time.

Usage: <slider_server> [flags]

  --verbose
        Adds verbosity [debug|info|warn|error|off] (default info)  
  --address
        Server will bind to this address (default 0.0.0.0)  
  --port
        port where Server will listen (default 8080)  
  --keepalive
        Sets keepalive interval vs Clients (default 1m0s)  
  --colorless
        Disables logging colors (default false)  
  --auth
        Enables Key authentication of Clients (default false)  
  --certs
        Path of a valid slider-certs json file (default "")  
  --keystore
        Store Server key for later use (default false)  
  --keypath
        Path for reading and/or storing a Server key (default "")  
  --http-template
        Path of a default file to serve (default "")  
  --http-server-header
        Sets a server header value (default "")  
  --http-redirect
        Redirects incoming HTTP to given URL (default "")  
  --http-status-code
        Status code [200|301|302|400|401|403|500|502|503] (default 200)  
  --http-version
        Enables /version HTTP path (default false)  
  --http-health
        Enables /health HTTP path (default false)  
  --proto
        Set your own proto string (default slider-v1)  
```

![Sever](./doc/server.gif)

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

##### `-address`:
Local address to bind to. By default, Slider binds to all local addresses

##### `-auth` and `-certs`:
By default, Slider Clients do not require any authentication to connect to Server.

* `-auth`: Enables and requires SSH Key-Based authentication to all Clients.
* `-certs`: Is an optional parameter, holding the path of a Certificate Jar file. This flag requires authentication is
  enabled.

When `-auth` is passed, a few things will and may happen:
1. If `-cert` flag is not provided:
    1. Slider will check if the default certificate file (`client-certs.json`) exists in "[Slider Home directory](#slider_home)".
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

![Sever Auth](./doc/server_auth.gif)

##### `-colorless`:
By default, regardless of the OS, if Slider runs on a PTY, logs will show their log level using colors. If this flag is passed
then logs will have no colors.

##### `-keepalive`:
By default, Slider pings every Client Session (every 60s) to ensure its available, otherwise kills the Session.

This value can be changed to any other duration value. If the value introduced is inferior to 5s, Slider will override
it to this one.

##### `-keypath` and `-keystore`:
By default, everytime Slider Server is executed, a new in memory KeyPair is generated, and so it's lost on termination.

When the flag `-keystore` is provided, Slider will store a new KeyPair in disk, but:
1. If `-keypath` was not provided, and the default key file `server-cert.json` exists in the "[Slider Home directory](#slider_home)",
   then it will be loaded instead or overriding it.
2. If `-keypath` was provided:
    1. If the path exists, Slider will attempt to load its KeyPair.
    2. If the path does not exist, Slider will save a new KeyPair in this path.

##### `-port`:
By default, Slider listens in port `8080`. Specify any other port using this flag.

##### `-http-template`, `-http-server-header`, `-http-status-code`:
Allows mimicking another web server while accepts setting a status code and a using a file as template.

This may help you blend Slider with your environment.

Size of the file is currently limited to 2MiB which should be enough for an HTML template with embedded images.

##### `-http-version`:
Disabled by default, it will serve a JSON with current Proto and Slider version at `/version`. 

##### `-http-redirect`:
A redirect parameter must be at least a URL with a valid scheme and host (`http[s]://<host>[:<port>]`).

HTTP connections will be redirected to the given URL while Slider connections will proceed as usual.
Can be used in combination with `-template` to include a server header in the response headers.

##### `-verbose`:
Choose the log level verbosity between debug, info, warn and error. When verbosity is set to `off` only non labeled and
fatal logs will be shown.

##### `-proto`:
Slider uses its own proto value (e.g. `slider-v1`), to ensure that only matching protocols are allowed to proceed
with the websocket upgrade. Among other things to avoid future compatibility issues.

This parameter allows you to specify your own proto value which can be handy, IF:
1. you want to drop any connection attempt other than your own proto, before attempting the upgrade to websocket.
2. you feel that the default proto (because it's sent as an HTTP header) is, for some reason, blocked by some kind of IPS.

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
* Disconnect, closes the Session at the Server side, it would be equivalent to terminating the Server. 
  * If the Client is configured with the `-retry` option, the Client will reconnect to the Server if available on the next
  try, creating a new Session.
  * If the Client is not configured with the `-retry` option, and is NOT configured with the `-listener` option, once it
runs its next keepalive check will shut down.  
* Kill, is equivalent to terminate the execution of the Client, independently if it's a regular Client or a Listener one.

##### Connect
```
Slider# connect -h
Usage: connect [flags] <[client_address]:port>

  -c, --cert   Specify certID for key authentication (default 0)  
  -d, --dns    Use custom DNS resolver (default "")               
  -p, --proto  Use custom proto (default slider-v1)               

Requires exactly 1 argument(s)
```
Regular Clients automatically connect back to the Server, but if we want to open a Session to a Client working as Listener
then we'll need to use the `connect` command.

This command will try to open a Session in the background, and you will be notified whether the connection was
successful or not. `connect` will hold until that confirmation is given, or otherwise considered timed out (10s).

Due to their purpose, Servers will disable Client authentication on connections to a Listener even if the Server is 
started with `-auth`.

I needed, it is possible, to use a custom DNS to resolve the Client, instead of the default one.

Since the Server is the one that initiates the connection to the Listener and the Listener is facing the network,
authentication of Servers will happen on the Client side with `-fingerprint`. 
Servers will be rejected if their fingerprint is not successfully verified. in order to authenticate to a Listener, use
the `-c` flag to specify the certificate ID that you want to use.

![Console Connect](./doc/console_connect.gif)

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

![Console Execute](./doc/console_execute.gif)

##### Socks
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

If a port is not specified using the `-p` flag, one  will be automatically assigned.

By default, the Socks server will be exposed only to localhost, but you can use the `-e` flag to expose it to all interfaces.

![Console Socks](./doc/console_socks.gif)

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

Only supported authentication methods are anonymous and Public/Private key.

While it is not a full implementation, this SSH connection opens the following possibilities:
* Connect to a Client Shell using any SSH client.
* Transfer files using any SFTP client or `scp`.
* Connect to the Client using any SSH client and run commands on it.
* Connect to the Client through SSH and run a reverse Socks v5 server.
* Local and Remote Port forwarding.

If server authentication is enabled you must authenticate using the SSH key that matches the certificated used to
authenticate Client and Server.
Note that the key passed used is not a valid SSH key itself, but you can obtain it by running `certs -d <certID>` command 
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

  -n, --new     Generate a new Key Pair (default false)                     
  -r, --remove  Remove matching index from the Certificate Jar (default 0)  
  -d, --dump    Dump CertID SSH keys (default 0)                            

Mutually exclusive flags:

  -n/--new, -r/--remove, -d/--dump 
```
The `certs` command requires that authentication is enabled on the Server otherwise it won't be available.

Usually if the Server was run with `-auth` enabled there will be at least 1 KeyPair in the Certificate Jar.
The Private Key contained within the Keypair can be passed to the client so that it will authenticate against the
Server.

Note that when dumping certificates `SLIDER_CERT_JAR`, defines if the Certificate with the given ID is saved or not, 
by default, it will be stored locally, and you'll get the path.
If `SLIDER_CERT_JAR` is set to `false`, the Certificate will be dumped to the console and not saved.

![Console Certs](./doc/console_certs.gif)

## Client

```
Slider Client

Creates a new Slider Client instance and connects
to the defined Slider Server.

Usage: <slider_client> [flags] [<[server_address]:port>]

  --verbose
        Adds verbosity [debug|info|warn|error|off] (default info)  
  --keepalive
        Sets keepalive interval in seconds. (default 1m0s)  
  --colorless
        Disables logging colors (default false)  
  --fingerprint
        Server fingerprint for host verification (listener) (default "")  
  --key
        Private key for authenticating to a Server (default "")  
  --listener
        Client will listen for incoming Server connections (default false)  
  --port
        Listener port (default 8081)  
  --address
        Address the Listener will bind to (default 0.0.0.0)  
  --retry
        Retries reconnection indefinitely (default false)  
  --http-template
        Path of a default file to serve (listener) (default "")  
  --http-server-header
        Sets a server header value (listener) (default "")  
  --http-redirect
        Redirects incoming HTTP to given URL (listener) (default "")  
  --http-status-code
        Template Status code [200|301|302|400|401|403|500|502|503] (listener) (default 200)  
  --http-version
        Enables /version HTTP path (default false)  
  --http-health
        Enables /health HTTP path (default false)  
  --dns
        Uses custom DNS server <host[:port]> for resolving server address (default "")  
  --proto
        Set your own proto string (default slider-v1)  

Mutually exclusive flags:

  --listener, --key    
  --listener, --dns    
  --listener, --retry  

Flag "--listener" with status "false" is incompatible with flags:

  --address             
  --port                
  --fingerprint         
  --http-template       
  --http-server-header  
  --http-redirect       
  --http-status-code    
  --http-version        
  --http-health 
```

![Client](./doc/client.gif)

### Client Flags Overview

#### Common Client Flags

##### `-colorless`:
Same as with the Server, by default, regardless of the OS, if Slider runs on a PTY, logs will show their log level using
colors. If this flag is passed then logs will have no colors.

##### `-keepalive`:
By default, Slider pings every Server Session (every 60s) to ensure its available, otherwise kills the Session.

This value can be changed to any other duration value. If the value introduced is inferior to 5s, Slider will override
it to this one.

Keepalive ensures that non listener clients terminate their connection to the server and shutdown, completely disabling
the keepalive will leave not listener clients hanging forever.

#### Listener Client Flags

##### `-listener`, `-address` and `-port`:
A Slider Client by default connects back to a server on a given address:port (Reverse Client), but it is also possible to run a Slider
Client in Listener mode (`-listener`).

When used as Listener it will listen for incoming connections on a bound address (`-address`) and port (`-port`). If not
configured, their default values are `0.0.0.0` and `8081` respectively.

One or several Servers will be able to open N number of sessions to a Client working as Listener at the same time.

The main two reasons for using a Slider Client on Listener mode are:
* The Server is located on a private network and a regular Client would not be able to reach it.
* Several Servers may want to collaborate on the same Client or use a particular Client as a gateway.

##### `-fingerprint`:
A Slider fingerprint represents a sha256sum string of a base64 encoded public key.

This flag could either be a fingerprint string or a file containing a list fingerprints, each one of them representing
a different Slider Server. This is useful when we want to be able to authorize several Servers by their public key.
A connection from a Server with a fingerprint not successfully verified will be rejected.

##### HTTP flags:
Same considerations as in Server HTTP flags documentation applies.

#### Reverse Client Flags

##### `-retry`:
A Reverse Client configured with the `-retry` flag will try to reconnect to the server according to its `-keepalive` 
value. You will very likely want to tune `-keepalive` to either short reconnection intervals or expand them fitting 
your needs.

Enabling `-retry` will only have an effect if the Client was able to connect to the Server at least once, in other words, 
if the Client fails to connect to the Server on the first run it will terminate its execution as usual.

Combining Client `-retry` with Server `-auth` and maintaining different Certificate Jar Files, is a great way to work 
between different "Workspaces" where using one Certificate Jar or another will determine what Clients will automatically
reconnect to your Server and create a Session.

##### `-key`:
A Slider Key represents an Ed25519 private key base64 encoded.

Keys will only be used against a Server with authentication enabled otherwise will be disregarded.

A Client would use a key generated by the Server and stored in its Certificate Jar, since a Client using any
certificate in the Server Certificate Jar will be authorized to connect.

`-key` offers a way to authenticate Clients on Servers with `-auth` enabled. If the Server was not configured with 
authentication, providing `-key` won't have any effect.

##### `-dns`:
Allows you to provide a custom DNS to resolve the Server address rather than using the default DNS servers.

##### `-proto`:
Same considerations as for the server apply.


## Credits

This project is built on top the idea of using SSH over a websocket connection. 

The concept is not new, there are quite a few online services for such matter and if you are interested only on 
traversing through networks, then should definitively check [Chisel](https://github.com/jpillora/chisel) out, which 
brought us here and is way more versed and versatile in this matter.

Lastly, all console captures were taken using [VHS](https://github.com/charmbracelet/vhs). Tape samples in 
the [doc](./doc) folder.