# slppy
Provide SLP implementation in python.

SLP is a discovery protocol for local area
networks.  It is an alternative to DNS-SD
or SSDP.  Commonly employed in enterprise
equipment.

This module provides functionality to query
as well as snoop for SLP activity on a subnet.

It is intended to provide an interoperable
implementation with existing SLP devices.
If starting from scratch, I strongly advise
using DNS-SD over SLP (aka zeroconf, used with
avahi or Bonjour).  It has much more rich
software ecosystem and architecturally is
better suited to scaling across networks.
Another alternative is SSDP, which is a bit
simpler, but similarly does not scale to
crossing routers.
