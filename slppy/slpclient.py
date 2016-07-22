# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2016 Lenovo
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import netifaces
import os
import random
import select
import socket
import struct


# SLP has a lot of ambition that was unfulfilled in practice.
# So we have a static footer here to always use 'DEFAULT' scope, no LDAP
# predicates, and no authentication for service requests
srvreqfooter = b'\x00\x07DEFAULT\x00\x00\x00\x00'
# An empty instance of the attribute list extension
# which is defined in RFC 3059, used to indicate support for that capability
attrlistext = b'\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00'


def _list_ips():
    # Used for getting addresses to indicate the multicast address
    # as well as getting all the broadcast addresses
    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs:
            yield addrs[netifaces.AF_INET]


def list_interface_indexes():
    # Getting the interface indexes in a portable manner
    # would be better, but there's difficulty from a python perspective.
    # For now be linux specific
    try:
        for iface in os.listdir('/sys/class/net/'):
            ifile = open('/sys/class/net/{0}/ifindex'.format(iface), 'r')
            intidx = int(ifile.read())
            ifile.close()
            yield intidx
    except (IOError, WindowsError):
        # Probably situation is non-Linux, just do limited support for
        # such platforms until other people come alonge
        return


def _v6mcasthash(srvtype):
    # The hash algorithm described by RFC 3111
    nums = bytearray(srvtype.encode('utf-8'))
    hashval = 0
    for i in nums:
        hashval *= 33
        hashval += i
        hashval &= 0xffff  # only need to track the lowest 16 bits
    hashval &= 0x3ff
    hashval |= 0x1000
    return '{0:x}'.format(hashval)


def _generate_slp_header(payload, multicast, functionid, xid, extoffset=0):
    if multicast:
        flags = 0x2000
    else:
        flags = 0
    packetlen = len(payload) + 16  # we have a fixed 16 byte header supported
    if extoffset:  # if we have an offset, add 16 to account for this function
        # generating a 16 byte header
        extoffset += 16
    if packetlen > 1400:
        # For now, we aren't intending to support large SLP transmits
        # raise an exception to help identify if such a requirement emerges
        raise Exception("TODO: Transmit overflow packets")
    # We always do SLP v2, and only v2
    header = bytearray([2, functionid])
    # SLP uses 24 bit packed integers, so in such places we pack 32 then
    # discard the high byte
    header.extend(struct.pack('!IH', packetlen, flags)[1:])
    # '2' below refers to the length of the language tag
    header.extend(struct.pack('!IHH', extoffset, xid, 2)[1:])
    # we only do english (in SLP world, it's not like non-english appears...)
    header.extend(b'en')
    return header


def _generate_request_payload(srvtype, multicast, xid, prlist=''):
    prlist = prlist.encode('utf-8')
    payload = bytearray(struct.pack('!H', len(prlist)) + prlist)
    srvtype = srvtype.encode('utf-8')
    payload.extend(struct.pack('!H', len(srvtype)) + srvtype)
    payload.extend(srvreqfooter)
    extoffset = len(payload)
    payload.extend(attrlistext)
    header = _generate_slp_header(payload, multicast, functionid=1, xid=xid,
                                  extoffset=extoffset)
    return header + payload


def _find_srvtype(net, srvtype, addresses, xid):
    """Internal function to find a single service type

    Helper to do singleton requests to srvtype

    :param net: Socket active
    :param srvtype: Service type to do now
    :param addresses:  Pass through of addresses argument from find_targets
    :return:
    """
    if addresses is None:
        data = _generate_request_payload(srvtype, True, xid)
        net.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        v6addrs = []
        v6hash = _v6mcasthash(srvtype)
        # do 'interface local' and 'link local'
        # it shouldn't make sense, but some configurations work with interface
        # local that do not work with link local
        v6addrs.append(('ff01::1:' + v6hash, 427, 0, 0))
        v6addrs.append(('ff02::1:' + v6hash, 427, 0, 0))
        for idx in list_interface_indexes():
            # IPv6 multicast is by index, so lead with that
            net.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, idx)
            for sa in v6addrs:
                try:
                    net.sendto(data, sa)
                except socket.error:
                    # if we hit an interface without ipv6 multicast,
                    # this can cause an error, skip such an interface
                    # case in point, 'lo'
                    pass
        for i4 in _list_ips():
            if 'broadcast' not in i4:
                continue
            addr = i4['addr']
            bcast = i4['bcast']
            net.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                           socket.inet_aton(addr))
            net.sendto(data, ('239.255.255.253', 427))
            net.sendto(data, (bcast, 427))


def find_targets(srvtypes, addresses=None):
    """Find targets providing matching requested srvtypes

    This is a generator that will iterate over respondants to the SrvType
    requested.

    :param srvtypes: An iterable list of the service types to find
    :param addresses: An iterable of addresses/ranges.  Default is to scan
                      local network segment using multicast and broadcast.
                      Each address can be a single address, hyphen-delimited
                      range, or an IP/CIDR indication of a network.
    :return: Iterable set of results
    """
    net = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    # TODO: increase RCVBUF to max, mitigate chance of
    # failure due to full buffer.
    # SLP is very poor at scanning large counts and managing it, so we
    # must make the best of it
    # Some platforms/config default to IPV6ONLY, we are doing IPv4
    # too, so force it
    net.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    # we are going to do broadcast, so allow that...
    initxid = random.randint(0, 32768)
    xididx = 0
    for srvtype in srvtypes:
        xididx += 1
        _find_srvtype(net, srvtype, addresses, initxid + xididx)
    r, _, _ = select.select((net,), (), (), 2)
    while r:
        (rsp, peer) = net.recvfrom(9000)
        print(repr(rsp))
        r, _, _ = select.select((net,), (), (), 2)



if __name__ == '__main__':
    find_targets(
        ["service:management-hardware.IBM:integrated-management-module2"])
