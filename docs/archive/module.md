```text
 __   __         __      __         
|  \ /  |       / _)     \ \        
|   v   | ___   \ \  _   _\ \   ___ 
| |\_/| |/ _ \ / _ \| | | |> \ / __)
| |   | ( (_) | (_) ) |_| / ^ \> _) 
|_|   |_|\___/ \___/ \___/_/ \_\___)
                                    
```

Modules
-------

In BoltConn, a module allows users to cohesively group a set of rules, intercepts, providers, and
rewrites into an associative unit for handlings packets that originate from or are destined to 
a specific domain or network subnet. The benefits of modularization are numerous, because not only
do they allow entire rulesets to be enabled or disabled with a solitary modification, but they
prevent rules from being ignored when in conflect with another existing rule or due to the priority
of their placement in BoltConn’s rule loading sequence. To put it simply, this allows rules to "get
out of the way" of each other load time, and conserves the reasources that would have been spent
attempting to resolve conflicts.

Modules are stored in a subdirectory of the BoltConn configuration directory titled `Module`, and
each module is contained within its own yaml file, and that yaml file follows the same convention as
the BoltConn configuration. Yaml mappings define sections of the module file, and identify what
information will be provided in the following sequence. 

### Rewrites

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
