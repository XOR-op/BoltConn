# RESTful API

API for external controlling.

| Method | Path      | Description                          |
|--------|-----------|--------------------------------------|
| GET    | /active   | Get all active connections.          |
| GET    | /logs     | Get all logs.                        |
| GET    | /captured | Get all captured http packets.       |
| GET    | /groups   | Get all proxy groups.                |
| PUT    | /groups   | Update selected proxy for the group. |

API for debugging.

| Method | Path      | Description                  |
|--------|-----------|------------------------------|
| GET    | /sessions | Get all active raw sessions. |