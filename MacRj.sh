#!/bin/sh

NAME=$(cat ./MacRj.conf | grep Name | cut -d ':' -f 2)
PASS=$(cat ./MacRj.conf | grep Pass | cut -d ':' -f 2)
NIC=$(cat ./MacRj.conf | grep Nic | cut -d ':' -f 2)
sudo ./MacRj $NAME $PASS $NIC
