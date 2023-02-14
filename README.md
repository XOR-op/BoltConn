# BoltConn

[![check.yml](https://img.shields.io/github/actions/workflow/status/XOR-op/BoltConn/check.yml)](https://github.com/XOR-op/BoltConn/actions)
[![License: GPLv3](https://img.shields.io/badge/license-GPLv3-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/XOR-op/BoltConn?color=00b4f0)](https://github.com/XOR-op/BoltConn/releases)

A transparent proxy supporting L4/L7 tunneling with MitM, designed for privacy and security.

## Features
- Transparent proxy supported by Tun device, with route table managed automatically.
- HTTP, SOCKS5, Shadowsocks, Trojan, Wireguard outbound support.
- Fake-ip DNS server to prevent DNS query leak. Support DoH/DoT upstream.
- Rule based flexible routing, including domain name, process name, and other rules.
- Support for subscription to proxy lists (a.k.a. proxy provider).
- Most-compatible ruleset configuration with mainstream software (e.g. Clash).
- MitM based URL rewrite/redirect, for fine-grained traffic control and privacy preservation.
- Hot-reload without disconnecting existent connections
- RESTful API together with command-line tool to configure program.

## Getting Started

Download pre-built binaries from [release](https://github.com/XOR-op/BoltConn/releases) or build yourself, then add the path to `$PATH`.

To run BoltConn:

```bash
boltconn
```

To generate CA certificate:

```bash
boltadm cert -p <your_desired_path>
```

To control a running BoltConn service, use `boltadm`. And you can use `boltadm --help` to see more details.

## Documentations
For architecture, see [design.md](./docs/design.md).

For RESTful API, see [restful.md](./docs/restful.md).

For comparison with other related projects, see [comparison.md](./docs/comparison.md).

## Future Plan
- optional HTTP/SOCKS5 inbound support
- outbound protocols support
  - local interfaces
  - proxy relay
- more rules
  - Wi-Fi SSID
  - ASN
  - logical rules
  - GEO-IP
- more MitM configurations
  - modify HTTP header
  - modify HTTP body
  - custom scripts
- web portal
- IPv6 support
- Windows support with Wintun driver

## License
This software is released under the GPL-3.0 license.