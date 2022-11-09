# Design
## Tun Device
We use tun(linux)/utun(macos) device to implement transparent proxy. 

To be more specific, assume we allocate `172.17.100.1` for the device.
We configure routing tables so that `0.0.0.0/0 -> 172.17.100.1`. Then our
device is able to capture IP packets from any source address. 

To forward packets out, we send those packets to our NAT service at, say, 
`172.17.100.1:12345`. The ip addresses must be same to ensure no infinite loop
exists. We do this because we use system's TCP/IP stack to reconstruct TCP streams.
Otherwise, a userspace TCP/IP stack is needed.

## NAT
We use NAT service to present TCP streams instead of standalone TCP packets.
In our NAT, the source port of streams will be used as identifiers for connections.
Therefore, incoming traffics can be correctly forwarded to applications. To avoid
loopback for outgoing traffics, we must bind socket to the outgoing interface, so they
can obtain correct local address instead of `172.17.100.1`.

## Dns Policy
We use fake ip (or called fake DNS) to associate ip addresses to domain names.
That is the base of domain name routing. We also override the default DNS setting of
system.

## Connection Management
todo