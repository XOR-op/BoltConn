```text
 ___      _                      _
|_ _|_ _ | |__  ___ _  _ _ _  __| |
 | || ' \| '_ \/ _ \ || | ' \/ _` |
|___|_||_|_.__/\___/\_,_|_||_\__,_|
```

## Inbound Connection configuration

The `inbound:` mapping is optional, and if warranted informs BoltConn about configuration parameters
for inbound connections. It is also unfortunately, where configuration of BoltConn becomes a bit
confusing. This confusion is because yaml is flexible and can describe the same data in numerous ways. 

In the configuration of inbound connection settings this is chiefly evident when defining connection
types of http and socks5. As both use different syntax to define the same type of data, which is the
port number that will be used.

```yaml
# An http connection will simply designate it is an http type with a mapping followed by the value
# of the port. It will not use a scalar.
inbound:
	http: 8080
# Where a connection that is of type socks5, will use a scalar to define a port.
inbound:
	socks5:
		- 8901
```

Regardless of connection type, the inbound connection setting can include an optional boolean
setting of whether to enable a tunnel on the inbound connection or disable it. By default this
tunnel is enabled, and the setting can be completely left out if not needed.

The inbound configuration can be completely be excluded from the BoltConn configuration, it can be
configured to use either of the two connection types, or it can be configured to use both connection
types within the same inbound configuration. 

We will next take a look at the two different connections types that can be defined in the inbound
connection configuration.

### Http

Defining a http type inbound connection is the most simple of the two. All that is needed is to
define `http:` as a mapping, followed by the value of the port to use.

```yaml
inbound:
	http: 8080 
```

### Socks5

Socks5 connection types provide more settings for configuration, so defining them is more
involved. Numerous ports can be included in the connection definition, along with numerous methods
of authentication for the connection. It is probably best just to demonstrate a few examples.

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

### Both

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
