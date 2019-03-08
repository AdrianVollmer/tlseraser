#!/bin/bash
# https://askubuntu.com/questions/11709/how-can-i-capture-network-traffic-of-a-single-process

set -e
set -u

if [ "$(id -u)" != "0" ]; then
    echo "This script must be run as root" 1>&2
    exit 1
fi

inport=$1
outport=$((inport+1))
netns=lg
subnet=192.168.253

function finish {
    ip link del veth-b
    ip netns del $netns
}
trap finish EXIT

# create a test network namespace:
ip netns add $netns

# create a pair of virtual network interfaces (veth-a and veth-b):
ip link add veth-a type veth peer name veth-b

# change the active namespace of the veth-a interface:
ip link set veth-a netns $netns

# configure the IP addresses of the virtual interfaces:
ip netns exec $netns ifconfig veth-a up $subnet.1 netmask 255.255.255.0
ifconfig veth-b up $subnet.254 netmask 255.255.255.0

# configure the routing in the test namespace:
ip netns exec $netns route add default gw $subnet.254 dev veth-a

# run the network mirror
ip netns exec $netns socat TCP-LISTEN:$inport,bind=$subnet.1,fork,reuseaddr TCP:$subnet.254:$outport

