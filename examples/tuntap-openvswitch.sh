#!/bin/sh

BRIDGE=br0
MAC=52:54:00:11:22:33
TAPDEV=grewrite0
UDP_PORT=22205
#VLAN=1234

# Clean up - careful! This removes all action=output flows that mention the MAC above.
for flow in $(ovs-ofctl dump-flows "$BRIDGE" | egrep "$MAC.+actions=output" | grep actions=output | awk '{ print $7 }'); do
  ovs-ofctl del-flows "$BRIDGE" "$flow" >&/dev/null
done
ovs-vsctl del-port "$BRIDGE" "$TAPDEV" >&/dev/null

# Setup
if ! grep -q "$TAPDEV" /proc/net/dev; then
  echo "You must create $TAPDEV first, either by running grewrite (interface is " >&2
  echo "removed when grewrite terminate), or by using 'ip tuntap add $TAPDEV mode tap'" >&2
  exit 1
fi

output="output"
if [ ! -z "$VLAN" ]; then
  ovs-vsctl add-port "$BRIDGE" "$TAPDEV" "tag=$VLAN"
  output="strip_vlan,output"
else
  ovs-vsctl add-port "$BRIDGE" "$TAPDEV"
fi

ofp=$(ovs-ofctl show "$BRIDGE" | grep "$TAPDEV" | cut -d\( -f1 | cut -d\  -f2)
if [ -z "$ofp" ]; then
  echo "$0: Can't find openflow port for $TAPDEV on $BRIDGE" >& 2
  exit 1
fi

# Send GRE packets to our TAP device. The assumption is they are being transmitted
# on to the switch untagged.
ovs-ofctl add-flow "$BRIDGE" "ip,dl_src=$MAC,nw_proto=47,action=output:$ofp"

# Send UDP port $UDP_PORT traffic to TAP device. If $VLAN is set above, the
# assumption is that we acquire the packet as it enters the switch, therefore the
# tag must be removed. When the packet is transmitted back to the switch from the
# TAP deviceit will be retagged by virtue of being on the port.
ovs-ofctl add-flow "$BRIDGE" "udp,dl_dst=$MAC,tp_dst=$UDP_PORT,action=$output:$ofp"
