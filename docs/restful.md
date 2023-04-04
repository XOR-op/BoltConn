# RESTful API

API for external controlling.

| Method  | Path                                       | Description                                          |
|---------|--------------------------------------------|------------------------------------------------------|
| POST    | /reload                                    | Reload configurations.                               |
| GET     | /tun                                       | Get current transparent proxy setting.               |
| PUT     | /tun                                       | Set current transparent proxy setting.               |
| GET     | /connections                               | Get all active connections.                          |
| DELETE  | /connections                               | Stop all active connections.                         |
| DELETE  | /connections/:id                           | Stop the specific connection.                        |
| GET     | /eavesdrop/all                             | Get all captured http packets.                       |
| GET     | /eavesdrop/range?start=*start*(&end=*end*) | Get captured http packets from *start* to *end*.     |
| GET     | /eavesdrop/payload/:id                     | Get headers and bodies of the packet.                |
| GET     | /proxies                                   | Get all proxy groups.                                |
| GET     | /proxies/:group                            | Get info for specific group.                         |
| PUT     | /proxies/:group                            | Set proxy for specific group.                        |
| GET     | /traffic                                   | Get global traffic statistics.                       |
| GET(WS) | /ws/traffic                                | Create a websocket of traffic statistics per second. |
| GET(WS) | /ws/logs                                   | Create a websocket of logs.                          |

API for debugging.

| Method | Path      | Description                  |
|--------|-----------|------------------------------|
| GET    | /sessions | Get all active raw sessions. |