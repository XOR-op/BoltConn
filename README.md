# BoltConn

BoltConn is a transparent proxy for domain name/application level routing.

Supported platforms: Macos, Linux.

*Warning: Since this project is under heavy development, breaking changes of features or API will happen.*

## Features

- [x] TLS mitm
- [x] modification of http/s requests and responses
- [x] graceful shutdown
- [x] socks5 & ss support
- [x] clash-compatible ruleset configuration
- [x] RESTful API controller
- [x] command-line tool for controlling and monitoring
- [x] symmetric UDP NAT

## Documentations

For architecture, see [design.md](./docs/design.md).

For RESTful API, see [restful.md](./docs/restful.md).

For comparison with other related projects, see [comparison.md](./docs/comparison.md).

## Getting Started


Execute `cargo build --release` at the root directory of the project, and cp all
executables in `target/release` into directory you like.

To run BoltConn:

```bash
boltconn
```

To generate CA certificate:

```bash
boltctl cert -p <your_desired_path>
```

To control a running BoltConn service, use `boltctl`. And you can use `boltctl --help` to see more details.

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