grewrite - Rewrite GRE tunnels as UDP
=====================================

This program turns GRE tunnels into UDP tunnels.

It works by rewriting outbound GRE packets to UDP and inbound UDP packets on
the configured port back to GRE. Importantly, this happens without making the
packets any larger.

It can be used with iptables (via NFQUEUE) where the tunnel is routed through
(or originates from) your Linux machine, or via TUN/TAP if you need to modify
packets that do not traverse the netfilter framework.


Building
--------

	./autogen.sh
	./configure
	make
	make install


Quick Start/Usage
-----------------

To start grewrite using iptables/NFQUEUE.

On host A (ex. 10.0.0.1):

	ip tunnel add gre1 mode gre remote 10.0.0.2 local 10.0.0.1
	ip link set gre1 up
	ip addr add 192.168.1.1/30 dev gre1

Oh host B (ex. 10.0.0.2):

	ip tunnel add gre1 mode gre remote 10.0.0.1 local 10.0.0.2
	ip link set gre1 up
	ip addr add 192.168.1.2/30 dev gre1

On both hosts:

	iptables -t mangle -A POSTROUTING -o eth0 -p gre -j NFQUEUE --queue-num 65109 --queue-bypass
	iptables -t mangle -A PREROUTING -i eth0 -p udp -m udp --dport 22205 -j NFQUEUE --queue-num 65109 --queue-bypass

	grewrite -q 65109 -d 22205

More detailed usage information can be displayed by running:

	grewrite -h


NFQUEUE Mode
------------

Packets traversing the netfilter framework can be queued to userspace for
decision making and optional rewriting using the iptables NFQUEUE target
('queue' in nftables).

grewrite will "bind" to a given queue number and modify packets as appropriate
before marking them as accepted. Unknown or unsuitable packets are marked as
accepted and remain unmodified.

See the file examples/nfqueue-iptables.sh for more information.


TUN/TAP Mode
------------

When using TUN/TAP mode, grewrite will create a new TAP interface (which is
named 'grewrite0' by default). Packets received by this interface will be
modified if appropriate and then retransmitted using the source MAC address of
the TAP interface).

See the file examples/tuntap-openvswitch.sh for how to use this
mechanism with openvswitch.


Caveats
-------

This program is designed to work with the minimal (4-byte) GRE header only. Do
not enable checksums/keys/sequencing/other features. If headers are deemed to
be incompatible then packets will not be modified.

Because a UDP header is 8 bytes long (i.e 4 bytes larger than GRE), this works
by making use of redundant and/or reserved fields in the tunneled payload such
that the receiving end is able to reconstruct the original packet.

This means that:

a) UDP payload data is not true to the original packet
b) only certain protocols inside the GRE tunnel may be rewritten (as above,
   incompatible packets will be transmitted unmodified)
c) rewriting may not work for future versions of supported protocols.

Supported protocols are: IPv4, IPv6, IS-IS and ES-IS (or, at least the parts
that are required for IS-IS to work properly).

IPv6 support is only guaranteed where flow labels are not in use. If flow
labels are in use then grewrite can either zero them or generate new ones at
the receiving end. The flow label originally transmitted will not be
preserved.


Useful RFCs
-----------

IPv4 - https://tools.ietf.org/html/rfc791
IPv6 - https://tools.ietf.org/html/rfc2460
IPv6 flow labels - https://tools.ietf.org/html/rfc6437
GRE - https://tools.ietf.org/html/rfc2890
UDP - https://tools.ietf.org/html/rfc768
Fletcher checksum - https://tools.ietf.org/html/rfc1008


