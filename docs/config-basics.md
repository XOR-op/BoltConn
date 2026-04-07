```text
  ___           __ _                    _   _
 / __|___ _ _  / _(_)__ _ _  _ _ _ __ _| |_(_)___ _ _
| (__/ _ \ ' \|  _| / _` | || | '_/ _` |  _| / _ \ ' \
 \___\___/_||_|_| |_\__, |\_,_|_| \__,_|\__|_\___/_||_|
                    |___/

```

## Configuration

Since BoltConn itself will need to be ran with suid permissions, it is assummed that all commands in
this documentation wherein are ran either with `sudo` or as the root user. So it may behove the user
to use `sudo su` to become root user while performing the configuration process. Furthermore,
becuase of the requirement to run BoltConn with suid permissions, the configuration files will need
to be placed in the `.config` directory of the root user. If you desire to place them elsewhere, you
will need to designate their location with the `--config` flag for every command that is to be
executed. 

### Creating the default configuration file.

To create all the default configuration file required to run BoltConn, the user will need to
run the `BoltConn generate init` command. When done as root or with sudo, this will create the
default configuration file in `/root/.config/boltconn/config.yml`. Which should look like so:

```yaml
interface: auto
inbound:
  http: 9961
dns:
  bootstrap:
    - 1.1.1.1
  nameserver:
    - doh, 1.1.1.1

proxy-group:
  Default:
    proxies:
      - DIRECT

rule-local:
  - FALLBACK, Default  
```

#### Breaking down the parts of the default configuration

Let’s take a moment now to work through each section of the default configuration file to gain a
better understanding on how to configure BoltConn for our specific purposes. 

* interface: By default this can be set to auto, to acquire which network interface to use based on
  network subnet.
* inbound: Is used to designate inbound ports that BoltConn will listen for.
  * http: Designates that BoltConn should listen for connections using the http protocol on port
    9961.
* dns: Designates settings that specifically define how BoltConn manages and manipulates dns
  queries.
  * bootstrap: defines the dns servers that will be used at startup to resolve hostnames for the
    primary domain name servers that will be used by BoltConn during it’s runtime.
	* 1.1.1.1: Is the domain name server for Cloudflare, and here it is being used as the server to
      bootstrap further dns queries to.
  * nameserver: defines the dns name server for use by BoltConn after initial startup.
	* doh, 1.1.1.1: Tells boltconn to use the Dns Over HTTPS protocol for the domain name server
      1.1.1.1 to resolve dns queries to. 
* proxy-group: Designates a group of proxies who BoltConn will forward traffic through to the world
  wide web.
  * Default: In this example servers as the label for the first proxy-group and it’s definitions.
	* proxies: Is a directive that tells BoltConn the next nested entries under it are proxy
      definitions.
	  * DIRECT: Is a proxy type keyword that informs BoltConn that the connection is direct and will
        not use a proxy to forward connections through.
* rule-local: Designates the beginning of a rules section for local connections.
  * FALLBACK, Default: Are both special keywords that tell BoltConn to use the FALLBACK rule set,
    and that the rule set is the default one to use.

### Crash Course in Yaml

A lot of applications these days use yaml for their configurations, so having a firm understanding
of how yaml structures data will provide any user with foundational understanding they can use else
where.

Yaml provides a hierarchical structure to data in order for it to provide meaning and allow computational
parsing. At the top of this hierarchical structure is the "mapping", which maps a label to it’s
value.

```yaml
mouth: beak
arm: wing
```

Often labels have more than one value associated to them, so in yaml mappings are often followed by
"sequences". Sequences allow more than one value to be ascribed to a mapping.

```yaml
bird:
	- duck
	- swan
	- goose
```

In the instance where what follows a mapping needs to follows a label/value context, yaml provides sequences of
mappings. 

```yaml
bird:
	- name: duck
	  type: water fowl
	- name: hawk
	  type: bird of prey
	- name: parrot
	  type: tropical perching bird
```

Finally, for those occasions rare occasions when a mapping needs additional values ascribed to it, but this
additional information does not represent a sequence of the same type, and needs to be defined in
the label/value context. Yaml provides mapping of mappings.

```yaml
duck: {
	foot: webbed
	bill: flat
}
hawk: {foot: clawed, bill: sharp}
```

There are just a few examples to provide a very basic understanding on how yaml is structured. For
more information you can visit [Tina Muller’s site](https://www.yaml.info/index.html) on yaml, [the
official yaml site](https://www.yaml.org), or if you just need a refresher there is always the [yaml
reference card](https://yaml.org/refcard.html) and the [yaml cheatsheet](https://quickref.me/yaml).
