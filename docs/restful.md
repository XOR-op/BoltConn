# RESTful API

API for external controlling.

| Method | Path                                      | Description                                      |
|--------|-------------------------------------------|--------------------------------------------------|
| GET    | /active                                   | Get all active connections.                      |
| GET    | /logs                                     | Get all logs.                                    |
| GET    | /captured/all                             | Get all captured http packets.                   |
| GET    | /captured/range?start=*start*(&end=*end*) | Get captured http packets from *start* to *end*. |
| GET    | /captured/detail/*id*                     | Get headers and bodies of the packet.            |
| GET    | /groups                                   | Get all proxy groups.                            |
| PUT    | /groups                                   | Update selected proxy for the group.             |

API for debugging.

| Method | Path      | Description                  |
|--------|-----------|------------------------------|
| GET    | /sessions | Get all active raw sessions. |