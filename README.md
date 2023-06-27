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
All efforts made to make you fully control your network.

## Features
- **Block Anything You Dislike**: Block annoying ads, ubiquitous telemetry or any traffic you don't want this app send.
- **Secure Your Traffic with Tunneling**: Prevent your traffic sniffed by ISP or third-party with Wireguard, Shadowsocks and more.
You can also chain them at client side, without support from proxy server.
- **Audit Your Traffic**: Audit traffic history to make sure apps behave trustworthy.
- **Modify in the Way You Want**: Manipulate requests and responses inside HTTPS traffic. Examine if the app secretly sends your data to their server, and block them once you find it.
- **Flexible Configuration**: Combine all above features with highly-customizable rule system. Directly include components from community, and compose your unique configuration.

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
- Improve and release web dashboard and desktop GUI client
- More rules
  - Wi-Fi SSID
- More MitM configurations
  - modify HTTP body
  - custom scripts
- IPv6 support
- Windows support with Wintun driver

## License
This software is released under the GPL-3.0 license.