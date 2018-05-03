<img align="right" src="static/image/logo-64.png"/>

# System Monitor

## Introduction

This is a simple web server for monitoring the status and metrics of multiple hosts in multiple clusters.

It has two operation modes, i.e. 'app' mode and 'node' mode. One public server will run this server with 'app' mode, 
which will serve the web pages and user interactions. It will request and assemble the information from the other 'node' servers 
according to the user requests. On the other hand, each target host that we would like to monitor will run this server with 'node' mode, 
which will collect various status and metrics.

```
/--- External Network ---\            /--- Internal Network ---\

                          +----------+             +----------+
 UserA  --(WebSocket)-->  |          | --(HTTP)--> | Smonitor |
 UserB  --(WebSocket)-->  | Smonitor |             |  (node)  |
 UserC  --(WebSocket)-->  |  (app)   |             +----------+
                          |          |             +----------+
                          |          | --(HTTP)--> | Smonitor |
                          +----------+             |  (node)  |
                                                   +----------+                  
```

Because this is still an on-going (hobby) project, both the architecture and the implementation are subject to change.

## Screenshots

Home page
![home page](screenshots/home.png)

Host detail page (no Nvidia GPU installed)
![host page](screenshots/host.png)

GPU status cards will be added to the host detail page if it has Nvidia GPUs installed
![gpu cards](screenshots/gpu.png)

## License

[The MIT License (MIT)](LICENSE.md)
