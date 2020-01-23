#!/bin/bash
sudo ovs-vsctl del-br lan
sudo ovs-vsctl add-br lan
#node1
sudo ovs-vsctl add-port lan ethx -- set interface ethx ofport_request=1
sudo ifconfig ethx 0
#node2
sudo ovs-vsctl add-port lan ethx -- set interface ethx ofport_request=2
sudo ifconfig ethx 0
#node_snort
sudo ovs-vsctl add-port lan ethx -- set interface ethx ofport_request=3
sudo ifconfig ethx 0
#controller
sudo ovs-vsctl set-controller br0 tcp:10.0.10.10:6633 \-- set-fail-mode lan standalone
sudo ifconfig lan 10.0.0.10 netmask 255.255.255.0 up
