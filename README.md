# Quic based PEP implemented with quicly/h2o  
A Performance Enhanced Proxy (PEP) using QUIC 
Uses https://github.com/h2o/quicly (TBD)

# basic usage and example output

server
```
./cpep-srv 

```
*Note*: The server looks for a TLS certificate and key in the current working dir named "server.crt" and "server.key" respectively([See TLS](#TLS)). You can use a self signed certificate; the client doesn't validate it.


client
```
```

# how to build
## 1. Install required dependencies 
```
sudo apt update
sudo apt install git cmake libssl-dev libev-dev g++ -y
```
## 2.  
```
git clone --recurse-submodules https://github.com/funglee2k22/vwa-ng.git 
mkdir build
cd build
cmake ../vwa-ng
make
```

# TLS
QUIC requires TLS, so cpep (cpep-srv) requires TLS certificates when running in server mode. It will look for a "server.crt" and "server.key" file in the current working directory.

You can create these files by creating a self-signed certificate via openssl with the following one-liner:
```
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -sha256 -days 365 -nodes -subj "/C=US/ST=Oregon/L=Portland/O=Company Name/OU=Org/CN=www.example.com"
```
