#!/bin/sh

IFACE=eth0
QUEUE=65109
UDP_PORT=22205

# Send GRE packets leaving eth0 to NFQUEUE
iptables -t mangle -A POSTROUTING -o "$IFACE" -p gre -j NFQUEUE --queue-num "$QUEUE" --queue-bypass

# Send UDP packets entering eth0 to NFQUEU
iptables -t mangle -A PREROUTING -i "$IFACE" -p udp -m udp --dport "$UDP_PORT" -j NFQUEUE --queue-num "$QUEUE" --queue-bypass
