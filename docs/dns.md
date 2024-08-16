```text
 ___  _  _ ___
|   \| \| / __|
| |) | .` \__ \
|___/|_|\_|___/

```

## DNS Configuration

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
