#!/bin/bash

ISP_PROXY_IP="192.168.1.74"
LEO_ISP_IP="192.168.10.1"

LEO_NIC="enp0s8"
CPE_NIC="enp1s0"

TUN_NIC="tun0" 

sudo ip link del tun0
sudo ip tuntap add dev tun0 mode tun 
sudo ip addr add 192.168.10.102/24 dev tun0 
sudo ip link set dev tun0 up

sudo tc filter del dev enp0s8 
sudo tc qdisc del dev enp0s8 ingress 

sudo tc qdisc add dev enp0s8 ingress
sudo tc filter add dev enp0s8 parent ffff: protocol all u32 \
          match ip protocol 17 0xff \
          action mirred egress mirror dev tun0     


#match udp dst 1024 0xffff \
#action mirred egress redirect dev tun0

