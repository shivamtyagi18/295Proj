#!/bin/bash
apt-get update
apt-get install default-jdk -y 
apt-get install default-jre -y 
apt-get install build-essential ant maven python-dev -y

git clone git://github.com/floodlight/floodlight.git -b v1.2
cd floodlight 
git submodule update 
ant 
mkdir /var/lib/floodlight 
chmod 777 /var/lib/floodlight 

