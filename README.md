<h1 align="center">
  <img src="./assets/icon.svg" alt="BoltConn" width="192">
    <br/>
    BoltConn
    <br/>
</h1>



<p align="center">
<a href="https://github.com/XOR-op/BoltConn/actions">
<img src="https://img.shields.io/github/actions/workflow/status/XOR-op/BoltConn/check.yml" alt="GitHub Actions">
</a>
<a href="./LICENSE">
<img src="https://img.shields.io/badge/license-GPLv3-blue.svg" alt="License: GPLv3">
</a>
<a href="https://github.com/XOR-op/BoltConn/releases">
<img src="https://img.shields.io/github/v/release/XOR-op/BoltConn?color=00b4f0" alt="Release">
</a>
</p>

A go-to solution for transparent application proxy & firewall with tunneling and MitM, designed with privacy and security in mind.

## Features
- **Transparent Proxy with Automatic Route Table Management:** The Tun device supports BoltConn's transparent proxy, and its route table is managed automatically.
- **Multiple Outbound Protocols Support:** BoltConn supports HTTP, SOCKS5, Shadowsocks, Trojan, and Wireguard outbounds. It is also possible to chain all these outbounds.
- **Fake-IP DNS Server for Leak Prevention:** BoltConn's Fake-IP DNS server prevents DNS query leaks and supports DoH/DoT upstream.
- **Flexible Rule-Based Routing:** With domain name, process name, and other rules, BoltConn allows for flexible routing.
- **Proxy/Rule List Subscription:** BoltConn supports proxy/rule list subscription; compatible with Clash.
- **MitM Functionality for Fine-Grained Traffic Control and Privacy Preservation:** BoltConn supports MitM-based URL/header rewrite/redirect.
- **Hot-Reload Capability for Seamless Upgrades:** BoltConn supports hot-reload without disconnecting existing connections.
- **RESTful API and Command-Line Tool for Easy Configuration:** BoltConn provides a RESTful API and command-line tool to configure the program.

For the full features, see [features.md](./docs/features.md).

## Getting Started


To get started with BoltConn, follow these simple steps:

1. Download pre-built binaries from [release](https://github.com/XOR-op/BoltConn/releases) or build yourself.
2. Add the path of the binary to `$PATH`.
3. Run BoltConn by typing `boltconn` in your terminal.

To generate CA certificate:

```bash
boltadm cert -p <your_desired_path>
```

To control a running BoltConn service, use `boltadm`.  For more information, use `boltadm --help`.

## Documentations
Learn more about BoltConn's architecture, RESTful API, and how it compares to other related projects:

- [design.md](./docs/design.md) explains BoltConn's architecture.
- [restful.md](./docs/restful.md) covers BoltConn's RESTful API.
- [comparison.md](./docs/comparison.md) compares BoltConn with other related projects.
- [features.md](./docs/features.md) lists full features of BoltConn.

## Future Plan
- more rules
  - Wi-Fi SSID
  - ASN
  - GEO-IP
- more MitM configurations
  - modify HTTP body
  - custom scripts
- web portal
- IPv6 support
- Windows support with Wintun driver
- refactor:
  - better DNS handling

## License
This software is released under the GPL-3.0 license.