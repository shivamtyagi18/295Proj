#!/bin/bash 

if [[ -z $4 ]]; then 
    echo "Usage: $0 <eth1> <eth2> <controller_ip> <bridge_ip>"
    exit 1
fi

apt-get update 
apt-get install openvswitch-switch -y 
ovs-vsctl add-br ovs-lan
ovs-vsctl add-port ovs-lan $1
ovs-vsctl add-port ovs-lan $2
ifconfig $1 0
ifconfig $2 0 
ovs-vsctl set-controller ovs-lan tcp:$3:6653 
ifconfig ovs-lan $4 netmask 255.255.255.0 up
