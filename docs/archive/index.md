```text
        ________      ___________________
        ___  __ )________  /_  /__  ____/___________________ 
        __  __  |  __ \_  /_  __/  /    _  __ \_  __ \_  __ \
        _  /_/ // /_/ /  / / /_ / /___  / /_/ /  / / /  / / /
        /_____/ \____//_/  \__/ \____/  \____//_/ /_//_/ /_/ 

                             .:-=++***##***+=-:.                                
                        .-+#%@@@@@@@@@@@@@@@@@@@@%*=:.                          
                    .-*%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#+:                       
                  -*@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%+:                    
               .+%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#-                  
             .+@@@@@@@@@@@@@@@%#*+=========++*#%@@@@@@@@@@@@@@%-                
            =@@@@@@@@@@@@@#+=-=+****#*##*****++=-=*%@@@@@@@@@@@@#:              
          :#@@@@@@@@@@@%+--+##*++===+++++===++*###+--+%@@@@@@@@@@@+             
         -@@@@@@@@@@@%-:+%#+==+*#####**#######*=-=*%%+:-#@@@@@@@@@@#            
        =@@@@@@@@@@@@#*@*--*%%*+======++======+#%#+:=#@+*@@@@@@@@@@@%.          
       =@@@@@@@@@@@@@@#:-#@*--=*#############*+=-=#@*:-@@@@@@@@@@@@@@%          
      :@@@@@@@@@@@@@@-.#@*:-#%#***************###*--%@+.*@@@@@@@@@@@@@#         
      %@@@@@@@@@=-@@::@@-:#%*********************#%*.+@#.=@%:*@@@@@@@@@=        
     =@@@@@@@@@* #@::@@:-@#+******+*##%%##********+%%.-@# +@=.%@@@@@@@@%        
     #@@@@@@@@@:-@+.%@::@#+*****+#%%*+==+*%@#******+%%.+@+.%@.=@@@@@@@@@-       
    .@@@@@@@@@#.*@.-@* %%+*****+%#:        :%%******+@+.@% +@=.@@@@@@@@@*       
    :@@@@@@@@@@%@@-*@*=@#*####*%@=:--------:=@@#####*%%-%@=+@@%@@@@@@@@@#       
    -@@@@@@=:---------=----------============----------=---------:+@@@@@%       
    :@@@@@@%%%%%%####*+##******##=+++++++++++##******##*#####%%##%%@@@@@#       
    .@@@@@@@@@@=%@==@# #@******%@=          *@#******@+:@@-*@%#@@@@@@@@@*       
     #@@@@@@@@@.-@*.%@-.@%+****+#@#+:...:-+%@******+%# *@+ #@::@@@@@@@@@-       
     -@@@@@@@@@# *@%*%@-:%%*******#%%%%%%%%#*******%#.+@# *@+.%@@@@@@@@%        
      #@@@@@@@@@* *@=.#@+.*%#********************#%=.#@*.+@+ *@@@@@@@@@-        
      :@@@@@@@@@@*-%@*.=@%-:+###**************##*=:+@%-:#@@-*@@@@@@@@@*         
       -@@@@@@@@@@@@@@@=:+@%+-=+**#########**+=-=*@%=:+@@@@@@@@@@@@@@#          
        -@@@@@@@@@@@@#=%%+-=*%#*+===========++#%%*--*@%=*@@@@@@@@@@@#           
         -@@@@@@@@@@@%+:=#%#+==+**##########*+===*%%#-:+%@@@@@@@@@@*            
          .#@@@@@@@@@@@@*--=*###*+=========++*###*=-=#@@@@@@@@@@@@=             
            =%@@@@@@@@@@@@@#+=-==*@@@@@@@@@%+====+#@@@@@@@@@@@@@*.              
              +%@@@@@@@@@@@@@@@%##@@@@@@@@@%*#%@@@@@@@@@@@@@@@#-                
               .=%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@*:                  
                  :*%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#=.                    
                     :+#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%*=.                       
                        .-=*%@@@@@@@@@@@@@@@@@@@%#+=:                           
                              .:-=++*****++==-:.
```

# Boltconn Docs

A go-to solution for transparent application proxy & firewall with tunneling and MitM, designed with
privacy and security in mind. All efforts made to make you fully control your network. Experimental
webui & desktop client is available in [XOR-op/BoltBoard](https://github.com/XOR-op/BoltBoard).

## What is BoltConn

BoltConn is all about dominance and owning your own turf. It’s like a drop kick to the throat of
network limitations. It's a ninja warrior of connection forwarding, that throws five fists for fury full of protocols
and tunnels. What’s even better is that it is loaded with features.

### Features

BoltConn comes with the following totally awesome features:

* Inbound
  * Transparent proxy based on TUN.
  * Optional HTTP/Socks5 inbound for better speed.
* Outbound
  * HTTP CONNECT (support auth).
  * Socks5 TCP & UDP (support auth).
  * Shadowsocks TCP & UDP.
  * Trojan TCP & UDP (support websocket and skipping certificate verification).
  * Wireguard TCP & UDP (single endpoint only).
  * Outbound chaining
  * Local interface binding
* DNS
  * DNS-over-TLS, DNS-over-HTTPS.
  * Preconfigured DoT/DoH configuration (inherit from trust-dns).
* Rules
  * DOMAIN, DOMAIN-SUFFIX, DOMAIN-KEYWORD
  * SRC-PORT, DST-PORT
  * GEOIP, ASN, IP-CIDR
  * PROCESS-PATH, PROCESS-KEYWORD
  * PROC-PATH-KEYWORD (keyword matching for the path of process)
  * PROC-CMD-REGEX (matching for the command, e.g. '/usr/bin/python3 /tmp/example.py')
  * Operations as in "AND", "OR", or "NOT"
* Rules(Action)
  * ACTION-LOCAL-RESOLVE (resolve the domain name of connection with local DNS)
* RuleSet
Almost the same as what is in Clash. (What is clash?)
Example: 
```yaml
payload:
  - DOMAIN-SUFFIX, google.com
```
* MitM
  * Rewrite URL
  * Use 302/404 etc. to redirect/block specific URL
  * Rewrite header part of HTTP request/response
  * Record packets for further analysis
* RESTful API
  * Enable via `web-controller` field
  * CORS list configuration
  * See [RESTful.md](restful.md).
* Dump   * 
  * Dump connection logs & intercepted data to sqlite
* Misc
  * Configure url of latency test by `speedtest-url` field

## Table of Contents

| Title                               | Description                              |
|:------------------------------------|:-----------------------------------------|
| [Installation](installation.md)     | Instructions on how to install BoltConn  |
| [Config Basics](config-basics.md)   | BoltConn Config Basics overview          |
| [Inbound](inbound.md)               | Configuring the inbound directive        |
| [DNS](dns.md)                       | Configuring the DNS directive            |
| [Proxy-Local](proxy-local.md)       | Local proxy configuration                |
| [Proxy-Provider](proxy-provider.md) | Defining providers for proxy connections |
| [Proxy-Group](proxy-group.md)       | Organizing proxies into groups           |
| [Rule-Local](rule-local.md)         | Local rules for connections              |
| [Rule-Provider](rule-provider.md)   | Defining providers for rules             |
| [Interception](interception.md)     | Configuring connection Interception      |
| [Module](module.md)                 | Configuring modules for use              |
|                                     |                                          |

