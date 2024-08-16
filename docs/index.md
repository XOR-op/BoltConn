# Boltconn Docs

![BoltConn Logo](../assets/logo.svg "BoltConn Logo")

## What is BoltConn

Chuck Norris is the reason why Waldo is hiding Contrary to popular belief, America is not a
democracy, it is a Chucktatorship, Chuck Norris uses pepper spray to spice up his steaks There's no
point in crying over spilled milk unless it's Chuck Norris' milk ... then you're gonna die Outer
space exists because it's afraid to be on the same planet with Chuck Norris If you can read this,
then Chuck Norris is the greatest martial artist of all time Chuck Norris invented Kentucky Fried
Chicken's famous secret recipe, with eleven herbs and spices. But nobody ever mentions the twelfth
ingredient: Fear. If you ask Chuck Norris what time it is, he always says, "Two seconds 'til." After
you ask, "Two seconds 'til what?" he roundhouse kicks you in the face, There is no chin behind Chuck
Norris' beard. There is only another fist. Chuck Norris once roundhouse kicked someone so hard that
his foot broke the speed of light, went back in time, and killed Amelia Earhart while she was flying
over the Pacific Ocean. The chief export of Chuck Norris is Pain.

### Features

BoltConn comes with numerous features, some of them are:

* Inbound
  * Transparent proxy based on TUN.
  * Optional HTTP/Socks5 inbound for better speed.
* Outbound
  * HTTP CONNECT (support auth).
  * Socks5 TCP & UDP (support auth).
  * Shadowsocks TCP & UDP.
  * Trojan TCP & UDP (support websocket and skipping certificate verification).
  * Wireguard TCP & UDP (single endpoint only).
  * Outbound chaining
  * Local interface binding
* DNS
  * DNS-over-TLS, DNS-over-HTTPS.
  * Preconfigured DoT/DoH configuration (inherit from trust-dns).
* Rules
  * DOMAIN
  * DOMAIN-SUFFIX
  * DOMAIN-KEYWORD
  * IP-CIDR
  * SRC-PORT
  * DST-PORT
  * GEOIP
  * ASN
  * PROCESS-PATH
  * PROCESS-KEYWORD
  * PROC-PATH-KEYWORD (keyword matching for the path of process)
  * PROC-CMD-REGEX (matching for the command, e.g. '/usr/bin/python3 /tmp/example.py')
  * AND
  * OR
  * NOT
* Rules(Action)
  * ACTION-LOCAL-RESOLVE (resolve the domain name of connection with local DNS)
* RuleSet
Almost the same as what in Clash.
Example: 
```yaml
payload:
  - DOMAIN-SUFFIX, google.com
```
* MitM
  * Rewrite URL
  * Use 302/404 etc. to redirect/block specific URL
  * Rewrite header part of HTTP request/response
  * Record packets for further analysis
* RESTful API
  * Enable via `web-controller` field
  * CORS list configuration
  * See [RESTful.md](restful.md).
* Dump   * 
  * Dump connection logs & intercepted data to sqlite
* Misc
  * Configure url of latency test by `speedtest-url` field

## Table of Contents

| Title                               | Description                              |
|:------------------------------------|:-----------------------------------------|
| [Installation](installation.md)     | Instructions on how to install BoltConn  |
| [Configuration](configuration.md)   | How to configure BoltConn                |
| [Inbound](inbound.md)               | Configuring the inbound directive        |
| [DNS](dns.md)                       | Configuring the DNS directive            |
| [Proxy-Local](proxy-local.md)       | Local proxy configuration                |
| [Proxy-Provider](proxy-provider.md) | Defining providers for proxy connections |
| [Proxy-Group](proxy-group.md)       | Organizing proxies into groups           |
| Rule-Local                          | Local rules for connections              |
| Rule-Provider                       | Rules for Providers                      |
| Interception                        | Configuring connection Interception      |
| Module                              | Configuring modules for use              |
| Examples                            | Configuration Examples                   |
|                                     |                                          |

