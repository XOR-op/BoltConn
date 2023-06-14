# Full Features
### Inbound
- Transparent proxy based on TUN.
- Optional HTTP/Socks5 inbound for better speed.
### Outbound
- HTTP CONNECT (support auth).
- Socks5 TCP & UDP (support auth).
- Shadowsocks TCP & UDP.
- Trojan TCP & UDP (support websocket and skipping certificate verification).
- Wireguard TCP & UDP (single endpoint only).
- Outbound chaining
- Local interface binding
### DNS
- DNS-over-TLS, DNS-over-HTTPS.
- Preconfigured DoT/DoH configuration (inherit from trust-dns).
### Rules
- DOMAIN
- DOMAIN-SUFFIX
- DOMAIN-KEYWORD
- IP-CIDR
- DST-PORT
- PROCESS-PATH
- PROCESS-KEYWORD
- PROC-PATH-KEYWORD (keyword matching for the path of process)
- PROC-CMD-REGEX (matching for the command, e.g. '/usr/bin/python3 /tmp/example.py')
- AND
- OR
- NOT
### RuleSet
Almost the same as what in Clash.
Example: 
```yaml
payload:
  - DOMAIN-SUFFIX, google.com
```
### MitM
- Rewrite URL
- Use 302/404 etc. to redirect/block specific URL
- Rewrite header part of HTTP request/response
- Record packets for further analysis
### RESTful API
See [RESTful.md](restful.md).
### Dump 