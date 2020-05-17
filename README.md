# Auth Daemon-Server

This is an implementation of a server in C that communicates with a proxy client in Go that
is supposed to handle requests from the Internet. (daemon not fully daemonized, just monitors
children)

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
