#!/bin/bash

ISP_PROXY_IP="10.0.2.15"
LEO_ISP_IP="192.168.30.1"


LEO_NIC="enp0s8"
CPE_NIC="enp0s3"

ip route add default scope global nexthop via ${LEO_ISP_IP} dev ${LEO_NIC}
ip route add ${ISP_PROXY_IP} via ${LEO_ISP_IP} dev ${LEO_NIC} 

iptables -t nat -A POSTROUTING -o ${LEO_NIC} -j MASQUERADE


