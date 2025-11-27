#!/bin/bash

sudo ip link del veth_host 2>/dev/null
sudo ip netns del ns_test  2>/dev/null

sudo ip link add veth_host type veth peer name veth_ns
sudo ip addr add 192.168.100.3/24 dev veth_host
sudo ip link set veth_host up
sudo ethtool -K veth_host tx off

sudo ip netns add ns_test
sudo ip link set veth_ns netns ns_test
sudo ip netns exec ns_test bash -c "
    ip link set veth_ns up
    ip addr add 192.168.100.1/24 dev veth_ns
    ethtool -K veth_ns tx off
"

echo "Run:"
echo "sudo ip netns exec ns_test socat -x - TCP4:192.168.100.2:60000"