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
All efforts made to make you fully control your network. Experimental webui & desktop client is available in [XOR-op/BoltBoard](https://github.com/XOR-op/BoltBoard).


## Features
- **Fine-grained Traffic Control**: Allow VPN-style global control, or dedicated http/socks5 per-inbound control.
- **Rule-based Blocking**: Block ad/tracking traffic on a per-process/per-website/flexible way.
- **Rule-based Tunneling**: Flexible way to tunnel traffic through http/socks5/wireguard/etc outbounds. Able to use compatible rules from similar community.
- **Audit Traffic**: Audit traffic history by accessing API or dumping into SQLite.
- **Modify HTTPS Data**: Manipulate requests and responses inside HTTPS traffic to redirect, block or modify them. Support injecting Javascript now.

For the full features, see [features.md](./docs/features.md).

## Getting Started

### Installation
#### Pre-built binaries
- Download pre-built binaries from [release](https://github.com/XOR-op/BoltConn/releases) and add the path of the binary to `$PATH`.
#### Install latest git version with cargo
```bash
cargo install --locked --git https://github.com/XOR-op/BoltConn
```

### Configuration
Before running BoltConn, you should run these two commands first:
1. Create necessary configuration and runtime files. The default configuration path is `$HOME/.config/boltconn`, and the
default runtime path is `$HOME/.local/share/boltconn`:
```bash
boltconn init
```
2. Generate root certificates with proper permissions for MitM:
```bash
sudo -E boltconn cert
```

### Run BoltConn
```bash
sudo -E boltconn start
```

### CLI Tools for Management
```bash
boltconn [conn/proxy/rule/tun/reload/...]
```
See `boltconn --help` for more help.

## Documentations
Learn more about BoltConn's architecture, RESTful API, and how it compares to other related projects:

- [design.md](./docs/design.md) explains BoltConn's architecture.
- [restful.md](./docs/restful.md) covers BoltConn's RESTful API.
- [features.md](./docs/features.md) lists full features of BoltConn.

## Future Plan
- Full IPv6 support
- Windows support with Wintun driver
- Better integration with external programs (e.g. OpenVPN or ssh)

## License
This software is released under the GPL-3.0 license.