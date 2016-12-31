#!/bin/sh

iptables -t mangle -A PREROUTING -i eth0 -p udp -m udp --dport 22205 -j NFQUEUE --queue-num 65109 --queue-bypass
iptables -t mangle -A POSTROUTING -o eth0 -p gre -j NFQUEUE --queue-num 65109 --queue-bypass
