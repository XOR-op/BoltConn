## Inbound Connection configuration

The `inbound:` mapping is optional, and if warranted informs BoltConn about configuration parameters
for inbound connections. It is also unfortunately, where configuration of BoltConn becomes a bit
confusing. This confusion is because yaml is flexible and can describe the same data in numerous ways. 

In the configuration of inbound connection settings this is chiefly evident when defining connection
types of http and socks5. As both use different syntax to define the same type of data, which is the
port number that will be used.

```yaml
# An http connection will simply designate it is a http type with a mapping followed by the value
# of the port. It will not use a scalar.
inbound:
	http: 8080
# Where a connection that is of type socks5, will use a scalar to define a port.
inbound:
	socks5:
		- 8901
```

Regardless of connection type, the inbound connection setting can include an optional boolean
setting of whether to enable a tunnel on the inbound connection or disable it. By default, this
tunnel is enabled, and the setting can be completely left out if not needed.

The inbound configuration can be completely be excluded from the BoltConn configuration, it can be
configured to use either of the two connection types, or it can be configured to use both connection
types within the same inbound configuration. 

We will next take a look at the two different connections types that can be defined in the inbound
connection configuration.

#### Http

Defining a http type inbound connection is the simplest of the two. All that is needed is to
define `http:` as a mapping, followed by the value of the port to use.

```yaml
inbound:
	http: 8080 
```

#### Socks5

Socks5 connection types provide more settings for configuration, so defining them is more
involved. Numerous ports can be included in the connection definition, along with numerous methods
of authentication for the connection. It is probably the best just to demonstrate a few examples.

```yaml
# Simple socks5
inbound:
	socks5:
		- 8901

# Complex socks5
inbound:
	socks5:
		- 2000
		- host: 0.0.0.0
		  port: 8080
		- port: 3000
		  auth:
			  <?USERNAME1>: <?PASSWORD1>
			  <?USERNAME2>: <?PASSWORD2>
```

#### Both

Just to show that an inbound configuration can use both types of connections, we will add such an
example below.

```yaml
inbound:
	enable-tun: false
	http: 1080
	socks5:
		- port: 8080
		auth:
			<?USERNAME>: <?PASSWORD>
```

### DNS Configuration

Required DNS settings are both bootstrap and nameserver, all other settings are optional and not
required. For bootstrap and nameserver, the mapping is declared followed by a scalar definition on
the next line, indented, and beginning with a `-`. If a protocol needs to be declared, it should
preceed the address on the same line as the address, and separated with a comma. For example, 
`- udp, 8.8.8.8` would be a scalar defining the udp protocol should be used to contact the
nameserver at "8.8.8.8".

The preference setting is optional, and has a limited amount of values that are valid. They are:
* ipv4-only
* ipv6-only
* prefer-ipv4
* prefer-ipv6

Host designation follows the same convention as bootstrap and nameserver, that is entries are entered in
a scalar on the next line.

Nameserver policy follows a different convention. As each policy is ascribed a label that is
used for a mapping, and the policy definition is defined as a scalar that is tied to the above mapping.

```yaml
dns:
	preference: <$PREFERENCE>
	bootstrap: 
		- <$PROTOCOL>, <$ADDRESS>
	nameserver:
		- <$PROTOCOL>, <$ADDRESS>
	hosts:
		- <$HOST>, <$ADDRESS>
	nameserver_policy:
		<$POLICY LABEL>:
			- <$POLICY DEFINITION>
```

### Local Proxy Configuration

Here is the introduction to local proxy configurations

#### Proxy Declaration

All proxy settings are defined by first assigning an identifier or name to the proxy, followed by a designation of
proxy type. The supported proxy types that may be used in the "type" designation are:

* http
* socks5
* shadowsocks
* trojan
* wireguard

After designating a proxy type, only then can further descriptors be used to define the settings for
the proxy.

```yaml
# HTTP
local-proxy:
	{$Name}:
		type: http
		server:
		port:
		auth:

# Socks5
local-proxy:
	{$Name}:
		type: socks5
		server: Server address
		port: Port to run on
		auth: authentication to use
		udp: yes or no

# ShadowSocks
local-proxy:
	{$Name}:
		type: shadowsocks
		server:
		port:
		password:
		cipher:
		upd:

# Trojan
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

# Wireguard
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

### Proxy Provider

In the BoltConn configuration file a proxy provider identifies a resource for BoltConn to read into
to further define connection parameters regarding the configuration of proxies. This provider can
either be of type file or of type http. Both are first indicated by ascribing an identifier / name
to the resource followed by a value mapping to the type of resource the provider is. Afterwards,
further configuration is dependent on type. A provider of type file is followed by a value mapping
of the file’s path, and a provider of type http is followed by a value mapping of the resources url
and interval for continual reading of that url.

Both can be defined as follows:

```yaml
proxy-provider:
	# File provider
	<?NAME>:
		type: file
		path: <?PATH/TO/FILE>
	# http provider
	<?NAME>
		type: http
		path: <?URL PATH>
		interval: 30
```

#### Provider File

File providers must follow a format and use a syntax that enables BoltConn to read them. Because
providers are concerned with accessing remote resources they are stored in the `Remote` folder, and
are written in yaml. The mapping of `proxies:` is first given to indicate the following articles of
data are used to define proxy definitions, then each definition is defined in a scalar on the next
following line. 

```yaml
proxies:
	- {name: <?LABEL>, server: <?SERVER>, port: <?PORT>, type: <?TYPE>, cipher: <?CIPHER>, password: <?password>, udp: <? T or F>}
```

Like so.

### Proxy Groups

The directive `proxy-group` is as the name would indicate, used to define groups of proxies, and
provide BoltConn with a means of grouping different proxy configurations together that share a
common trait or characteristic. Proxy grouping also provides ease for creating definitions for
connection rulesets. 

Proxy groups can contain proxies, proxy providers, proxy provider splices, proxy definitions, proxy
chains, and interface definitions. Pretty much allowing any number of items to be grouped together
under a single unifying identifier. 

Below is a robust example of several proxy group definitions.

```yaml
proxy-group:
  Relay:
    proxies:
      - lan_http
      - lan_socks
      - Chain
      - DIRECT
      - VPN
    providers:
      - US
  Home:
    proxies:
      - local-chain
      - DIRECT
  US:
    providers:
      - US
  SanJose:
    providers:
      - name: US
        filter: '.*View.*'
  VPN:
    proxies:
      - DIRECT
    interface: tun1
  local-chain:
    chains:
      - lan_http
      - lan_socks
  Chain:
    chains:
      - lan_socks
      - US
```


### Local Rules

Local rules determine how BoltConn is to structure network traffic and controls what is done with
that traffic within it’s capable framework. To do so it utilizes a predefined set of directives that
begin each rule statement, followed by the value required to fulfill the directive, and if required an
action statement to inform BoltConn of what needs to be performed for each match of rule.

<!-- Right here needs an explanation why some rule statements require a third value, while other -->
<!-- statements do not. -->

| Keyword           | Type   | Definition | Example |
|:------------------|:-------|:-----------|:--------|
| INBOUND           | string |            |         |
| DOMAIN-SUFFIX     |        |            |         |
| DOMAIN-KEYWORD    |        |            |         |
| DOMAIN            |        |            |         |
| PROCESS-NAME      |        |            |         |
| PROCESS-KEYWORD   |        |            |         |
| PROC-PATH-KEYWORD |        |            |         |
| PROC-CMD-REGEX    |        |            |         |
| LOCAL-IP-CIDR     |        |            |         |
| SRC-IP-CIDR       |        |            |         |
| IP-CIDR           |        |            |         |
| GEOIP             |        |            |         |
| ASN               |        |            |         |
| SRC-PORT          |        |            |         |
| DST-PORT          |        |            |         |
| RULE-SET          |        |            |         |
| ALWAYS            |        |            |         |
| NEVER             |        |            |         |


#### Examples

<!-- Right here should be a swanky example of how to use these keywords, so newbs don’t ask too many -->
<!-- questions. -->


### Interception

```yaml
interception:
    name: <%NAME>
        - 
```

### Modules

In BoltConn, a module allows users to cohesively group a set of rules, intercepts, providers, and
rewrite statements into an associative unit for handlings packets that originate from or are destined to
a specific domain or network subnet.

Modules are stored in a subdirectory of the BoltConn configuration directory titled `Module`, and
each module is contained within its own yaml file, and that yaml file follows the same convention as
the BoltConn configuration. Yaml mappings define sections of the module file, and identify what
information will be provided in the following sequence. 

#### Rewrites

The rewrite mapping is specifically unique to the module file, and is not used anywhere else in the
BoltConn configuration. Rewrites function in BoltConn just like rewrites function in webservers,
that is, they internally redirect the datastream to a different destination. This redirection can be
perform on urls, header-req, and header-resp.

```yaml
rule-local:
	- DOMAIN-SUFFIX, foobar.com, Relay
	
intercept-rule:
	- DOMAIN-SUFFIX, foobar.com
	- DOMAIN-SUFFIX, foobar.food
	
rewrite:
	- url, ^https://foobar.food(.*)$, 302, https://foobar.com
	- url, ^https://bar.foobar.com, 404
```
