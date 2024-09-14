```text
 ___                    ___             _    _
| _ \_ _ _____ ___  _  | _ \_ _ _____ _(_)__| |___ _ _
|  _/ '_/ _ \ \ / || | |  _/ '_/ _ \ V / / _` / -_) '_|
|_| |_| \___/_\_\\_, | |_| |_| \___/\_/|_\__,_\___|_|
                 |__/
```

## Proxy Provider

In the BoltConn configuration file a proxy provider identifies a resource for BoltConn to read into
to further define connection parameters regarding the configuration of proxies. This provider can
either be of type file or of type http. Both are first indicated by ascribing an identifier / name
to the resource followed by a value mapping to the type of resource the provider is. Afterwards,
further configuration is dependent on type. A provider of type file is followed by a value mapping
of the file’s path, and a provider of type http is followed by a value mapping of the resources url
and interval for continual reading of that url.

Both can are defined as follows:

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

### Provider File

File providers must follow a format and use a syntax that enables BoltConn to read them. Because
providers are concerned with accessing remote resources they are stored in the `Remote` folder, and
are written in yaml. The mapping of `proxies:` is first given to indicate the following articles of
data are used to define proxy definitions, then each definition is defined in a scalar on the next
following line. 

```yaml
proxies:
	- {name: <?LABEL>, server: <?SERVER>, port: <?PORT>, type: <?TYPE>, cipher: <?CIPHER>, password: <?password>, udp: <?T or F> }
```

Like so.
