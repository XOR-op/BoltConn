# BoltConn

BoltConn is a transparent proxy for domain name/application level routing.

Support platforms: Macos, Linux.

*Warning: Since this project is under heavy development, breaking changes of features or API will happen.*

## Features

- [x] TLS mitm
- [x] modification of http/s requests and responses
- [x] graceful shutdown
- [x] socks5 & ss support
- [x] clash-compatible ruleset configuration
- [x] RESTful API controller
- [x] command-line tool for controlling and monitoring

## Documentations

For architecture, see [design.md](./docs/design.md).

For RESTful API, see [restful.md](./docs/restful.md).

## Getting Started

To run BoltConn:

```bash
cargo build --release && cargo rr --bin boltconn
```

To generate CA certificate:

```bash
cargo build --release && cargo rr --bin bolthelper
```

## Future Plan

- multiple outbound protocols support
    - [ ] http
    - [ ] wireguard
    - [ ] openvpn
    - [ ] trojan
    - [ ] other local interfaces
- [ ] more configurations
- [ ] web portal
- [ ] on-demand privilege elevation
- [ ] better IPv6 support
- [ ] Windows support with Wintun driver