#!/bin/bash

ISP_PROXY_IP="10.0.2.15"
LEO_ISP_IP="192.168.30.1"


LEO_NIC="enp0s8"
CPE_NIC="enp0s3"

#clear 
iptables -t mangle -F 

iptables -t mangle -N DIVERT 
iptables -t mangle -A DIVERT -j MARK --set-mark 111
iptables -t mangle -A DIVERT -j ACCEPT 

iptables -t mangle -A PREROUTING -i ${CPE_NIC} -p tcp -m socket -j DIVERT 

iptables -t mangle -A PREROUTING -i ${CPE_NIC} -p tcp --match multiport --dport 5201,5202 -j TPROXY --tproxy-mark 111/111 --on-port 8443

ip rule add fwmark 111 lookup 100 
ip route add local 0.0.0.0/0 dev ${LEO_NIC} tab 100
