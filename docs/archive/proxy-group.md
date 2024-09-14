```text
 ___                     ___
| _ \_ _ _____ ___  _   / __|_ _ ___ _  _ _ __
|  _/ '_/ _ \ \ / || | | (_ | '_/ _ \ || | '_ \
|_| |_| \___/_\_\\_, |  \___|_| \___/\_,_| .__/
                 |__/                    |_|
```

## Proxy Groups

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
