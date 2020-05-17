# Auth Daemon-Server

This is an implementation of a server in C that communicates with a proxy client in Go that
is supposed to handle requests from the Internet. (daemon not fully daemonized, just monitors
children)

# How it works

The daemon starts by forking twice and spawning the server on one child and the proxy on the other. On the remaining
process, it runs the process monitoring routine.

The server and the proxy can only talk to the daemon initially, which sets up a client UNIX socket to do so. Requests
from any other process to the server or proxy will be rejected by the acess control store that both of them implement.

Upon exec'ing, the server and proxy whitelist their parent process - the control daemon. The daemon then can send
`AuthorizeProcess` requests to them to whitelist their peers (server to proxy and proxy to server).

If one of the components is killed (proxy or server), the daemon restarts them and reauthorize the healed process with its
counterpart. It does so by sending `HeartbeatRequest` to the proxy and server and keeping track of a number of lags (number of heartbeats
that either process failed to respond to). Once the daemon deems the process unresponsive, by virtue of it falling behind too many
heartbeats, it kills it, reaps it, forks again, and execs, sending an `AuthorizeProcess` message to its peer to
replace the old pid with the new one.

# Organization

```
.
├── README.md
├── daemon
├── server 
└── proxy-service
```

* daemon: Manages health and status of the entire system.

* server: C IPC server to that listens for requests from the local proxy service to be sanitized, classified, and routed to the local-running daemon agent.

* proxy-service: Go service that handles the application's business logic and communication with the Internet. Receives requests from the web and implements the client for the IPC protocol that communicates with the daemon.


## Architecture

```

     Internet Security                            | 
        _________                                 |                           
---->   |       |   validation  Domain Security   |         #----------# -----------|>
---->   | proxy | ---------------> Server ------>  <------  || Daemon ||  ---|>         Various system reactions
---->   |       |                                 |         ||        ||  --------|>    
                                                  |
                                                  |
```

The Daemon is in effect isolated from the Internet, and can only talk to the IPC server. They communicate through a protocol that
the Go proxy service also implements, and the latter gets requests from the Internet to pass it on.
