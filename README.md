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
- **Audit Traffic**: Audit recent traffic history through the control APIs.
- **Modify HTTPS Data**: Manipulate requests and responses inside HTTPS traffic to redirect, block or modify them. Support injecting Javascript now.

For configuration, API, rule, and proxy details, see the documentation below.

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
# generate configuration files
boltconn generate init
```
2. Generate root certificates with proper permissions for MitM:
```bash
# generate root certificates and make them readable only by root user (recommended)
sudo -E boltconn generate cert
# or generate them without configuring permissions
boltconn generate cert --rootless
```

### Run BoltConn
```bash
# run BoltConn globally
sudo -E boltconn start
# or run BoltConn with rootless mode (certain features will be unavailable)
boltconn start --rootless
```

### CLI Tools for Management
```bash
boltconn [conn/proxy/rule/tun/reload/...]
```
See `boltconn --help` for more help.

## Documentations
Learn more about BoltConn's configuration, proxy behavior, RESTful API, and rule system:

- [config.md](./docs/config.md) covers configuration and state behavior.
- [instrument.md](./docs/instrument.md) documents the instrument WebSocket protocol and rule integration.
- [proxy.md](./docs/proxy.md) documents proxy and outbound behavior.
- [rule.md](./docs/rule.md) explains rule syntax and matching behavior.
- [restful.md](./docs/restful.md) covers BoltConn's RESTful API.

## Future Plan
- Stablize Windows support with Wintun driver (it's experimental now).

## License
This software is released under the GPL-3.0 license.
