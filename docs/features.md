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
### DNS
- DoT, DoH with domain name (DoT/DoH with raw ip addresses are not supported now).
- Preconfigured DoT/DoH configuration (inherit from trust-dns).
### Rules
- DOMAIN
- DOMAIN-SUFFIX
- DOMAIN-KEYWORD
- IP-CIDR
- DST-PORT
- PROCESS-PATH
- PROCESS-KEYWORD
- PROCPATH-KEYWORD (keyword matching for the path of process)
- AND
- OR
- NOT
### RuleSet
Almost the same as what in Clash.
### MitM
- Rewrite URL
- Use 302/404 etc. to redirect/block specific URL
- Rewrite header part of HTTP request/response
- Record packets for further analysis
### RESTful API
See [RESTful.md](restful.md).
