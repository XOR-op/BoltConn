# BoltConn
BoltConn is a transparent proxy for domain name/application level routing.

Support platforms: Macos, Linux.

*Warning: Since this project is under development, no guarantee for compatibility and availability.*
## Features
- [x] TLS mitm
- [x] modification of http/s requests and responses
- [x] graceful shutdown

## Design
See [design.md](./docs/design.md).

## How to use
To run BoltConn:
```bash
cargo build --release && cargo rr --bin boltconn
```
To generate CA certificate:
```bash
cargo build --release && cargo rr --bin boltconn-helper
```
## TO-DO
- multiple outbound protocols support
  - [x] direct
  - [x] socks5
  - [ ] http connect
  - [ ] wireguard
  - [ ] openvpn
  - [ ] shadowsocks
  - [ ] trojan
  - [ ] other local interfaces
- [ ] configurations
- [ ] web portal
- [ ] on-demand privilege elevation
- [ ] better IPv6 support