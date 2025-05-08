#!/bin/bash 

ISP_NIC="enp0s3"
LEO_NIC="enp0s8"

LEO_ISP_IP="192.168.30.1"

LEO_SUB_NET="192.168.30.0/24"

iptables -t nat -F 
iptables -t nat -X 
iptables -t nat -L 
iptables -t nat -A POSTROUTING -o ${ISP_NIC} -j MASQUERADE


