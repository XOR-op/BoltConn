# RESTful API

API for external controlling.

| Method | Path                                  | Description                                      |
|--------|---------------------------------------|--------------------------------------------------|
| GET    | /connections                          | Get all active connections.                      |
| DELETE | /connections                          | Stop all active connections.                     |
| DELETE | /connections/:id                      | Stop the specific connection.                    |
| GET    | /logs                                 | Get all logs.                                    |
| GET    | /mitm/all                             | Get all captured http packets.                   |
| GET    | /mitm/range?start=*start*(&end=*end*) | Get captured http packets from *start* to *end*. |
| GET    | /mitm/payload/:id                     | Get headers and bodies of the packet.            |
| GET    | /groups                               | Get all proxy groups.                            |
| PUT    | /groups                               | Update selected proxy for the group.             |

API for debugging.

| Method | Path      | Description                  |
|--------|-----------|------------------------------|
| GET    | /sessions | Get all active raw sessions. |