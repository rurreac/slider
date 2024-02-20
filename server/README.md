# A Note on Console:

- 'Console' interacts with the Slider Client using SSH Connection Request and
	Reply messages.
- Connection Requests are costly, sometimes fail (check function `sessionRequestAndRetry`).

## The Issue

Sometimes the Connection Request is receiving **"false"** and an empty Payload with the answer, 
meaning it hasn't been properly handled.

This is due to the Client handling `ssh.request` requests through the `ssh.Conn` and `ssh.Client` conflicting
one with the other.

As a workaround, adding a retry every 1s up to 5s-10s seems to fix the issue as eventually the `ssh.Conn` handles
the `ssh.Request` instead of the `ssh.Client`.


## The Alternatives:

### Option 1

Maybe, a better option to handle it, would be moving the whole Session/Execute interaction
part of the Console to the Client and send it over to the Server, so that, opening a
session would be just copying the stream to stdin, stdout, stderr. Same as it is currently
done for a Reverse Shell.

All necessary logic to interact with the Client Host should be moved to the Slider Client
and executed from the new Client Console.

This way all interaction with the Client would be local to the Client which:

- Reduce the need of sending SSH Connection Requests and Responses back and forth.
- Allow (potentially) all future Interactive interactions with the Client over the same SSH
Client and Client Session. 

Note that when interaction is handle through the server (as currently is), each interaction
with the Client opens and closes a new SSH Client Session.

### Option 2

A much better way, possibly required if at some point SOCKS5 is part of the functionality, would be manually
opening a specific "session" channel from the client following / implementing most of the `ssh.Client.NewSession()`.

### Option 3

Another option that would require a less complex implementation than "Option 2" as still would make use of `ssh.Client`
would be creating a new SSH channel for managing only Connection messages from the server.

Then this channel could talk to the SSH "session" channel through channels / pipelines.

It's likely that the combination of "Option 1" and "Option 3" would be the ideal one. Still a similar implementation
of `ssh.Client.NewSession()` would be required if wanting to add a SOCK5 server as a functionality.


# A Note on Conn/Channel Requests

- SSH Connection Requests can include a Payload and allow Replies
- Session Channel Requests can include a Payload and allow Replies
- SSH Replies can include a Payload and only return an error
