#!/bin/sh

bridge=br0
mac=f2:43:fc:75:99:2a
tapdev=grewrite0
vlan=2099

# Clean up
for flow in `ovs-ofctl dump-flows "$bridge" | grep actions | grep -v NORMAL | grep "$mac" | cut -d, -f7-| awk '{ print $1 }' | cut -d, -f2-`; do
  ovs-ofctl del-flows "$bridge" "$flow" >&/dev/null
done
ovs-vsctl del-port "$bridge" "$tapdev" >&/dev/null

# Setup
output="output:"
if [ ! -z "$vlan" ]; then
  ovs-vsctl add-port "$bridge" "$tapdev" "tag=$vlan"
  output="strip_vlan,output:"
else
  ovs-vsctl add-port "$bridge" "$tapdev"
fi

ofp=$(ovs-ofctl show "$bridge" | grep "$tapdev" | cut -d\( -f1 | cut -d\  -f2)
if [ -z "$ofp" ]; then
  echo "$0: Can't find openflow port for $tapdev on $bridge" >& 2
  exit 1
fi

ovs-ofctl add-flow "$bridge" "dl_src=$mac,dl_type=0x0800,ip_proto=47,action=output:$ofp"
ovs-ofctl add-flow "$bridge" "dl_dst=$mac,dl_type=0x0800,ip_proto=17,udp_dst=22205,action=$output:$ofp"
