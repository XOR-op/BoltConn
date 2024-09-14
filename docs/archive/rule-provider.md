```text
 ___      _       ___             _    _
| _ \_  _| |___  | _ \_ _ _____ _(_)__| |___ _ _ ___
|   / || | / -_) |  _/ '_/ _ \ V / / _` / -_) '_(_-<
|_|_\\_,_|_\___| |_| |_| \___/\_/|_\__,_\___|_| /__/

```

Rule Providers
--------------

Defining rule providers in your configuration file is optional, and only required if one so desires. 

Similar to [Proxy Providers](proxy-provider.md), rule providers define a resource for BoltConn to
access in order to acquire information regarding rule sets, and again in similarity to [Proxy
Providers](proxy-provider.md), the resource can be either a file in the local filesystem or an HTTP
url that BoltConn accesses. In most respects, both proxy providers and rule providers are similar,
except for when defining http providers. As with HTTP providers the two differ from one another.

Both are first indicated by ascribing an identifier / name to the resource followed by a value
mapping defining the type of provider. The next value mapping for both defines the path to the
resource. HTTP providers will need the additional mappings for "root_path" and a boolean value
mapping of whether to force update of the provider or not. 

A syntax make up of the structure is as follows.

```yaml
rule-provider:
	# File provider
	<?NAME>:
		type: file
		path: <?PATH/TO/FILE>
	# http provider
	<?NAME>
		type: http
		path: <?URL PATH>
		root_path: <?ROOT URL PATH>
		force_update: <?YES or NO>
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
