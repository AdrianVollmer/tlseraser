#!/bin/bash
# this creates a "network mirror", for the sole reason of having a separate
# network interface where we can see the clear text traffic
# https://askubuntu.com/questions/11709/how-can-i-capture-network-traffic-of-a-single-process

set -u

if [ "$(id -u)" != "0" ]; then
    echo "This script must be run as root" 1>&2
    exit 1
fi

inport=$1
outport=$inport
netns=mirror
subnet=192.168.253
devname=noTLS

function finish {
    ip netns del $netns 2> /dev/null
}
trap finish EXIT SIGINT SIGTERM SIGUSR1

# delete network namespace if it still exists:
if [[ `ip netns show` =~ $netns ]] ; then ip netns del $netns 2> /dev/null ; fi

# create a test network namespace:
ip netns add $netns

# create a pair of virtual network interfaces ($devname-a and $devname):
ip link add $devname-a type veth peer name $devname

# change the active namespace of the $devname-a interface:
ip link set $devname-a netns $netns

# configure the IP addresses of the virtual interfaces:
ip netns exec $netns ifconfig $devname-a up $subnet.1 netmask 255.255.255.0
ifconfig $devname up $subnet.254 netmask 255.255.255.0

# configure the routing in the test namespace:
ip netns exec $netns route add default gw $subnet.254 dev $devname-a

# run the network mirror
ip netns exec $netns socat TCP-LISTEN:$inport,bind=$subnet.1,fork,reuseaddr TCP:$subnet.254:$outport

