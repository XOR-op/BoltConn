```text
 _                 _   ___
| |   ___  __ __ _| | | _ \_ _ _____ ___  _
| |__/ _ \/ _/ _` | | |  _/ '_/ _ \ \ / || |
|____\___/\__\__,_|_| |_| |_| \___/_\_\\_, |
                                       |__/
```

## Local Proxy Configuration

Here is the introduction to local proxy configurations

### Proxy Declaration

All proxy settings are defined by first assigning an identifier or name to the proxy, followed by a designation of
proxy type. The supported proxy types that may be used in the "type" designation are:

* http
* socks5
* shadowsocks
* trojan
* wireguard

After designating a proxy type, only then can further descriptors be used to define the settings for
the proxy.

#### http

```yaml
local-proxy:
	{$Name}:
		type: http
		server:
		port:
		auth:
```

#### socks5

```yaml
local-proxy:
	{$Name}:
		type: socks5
		server: Server address
		port: Port to run on
		auth: authentication to use
		udp: yes or no
```

#### shadowsocks

```yaml
local-proxy:
	{$Name}:
		type: shadowsocks
		server:
		port:
		password:
		cipher:
		upd:
```

#### Trojan

```yaml
local-proxy:
	{$Name}:
		type: trojan
		server:
		port:
		password:
		sni:
		skip_cert_verify:
		websocket_path:
		udp:
```

#### Wireguard

```yaml
local-proxy:
	{$Name}:
		type: wireguard
		local_addr:
		local_addr_v6:
		private_key:
		public_key:
		endpoint:
		dns:
		dns_preference:
		mtu:
		preshared_key:
		keepalive:
		reserved:
		over_tcp:
```
