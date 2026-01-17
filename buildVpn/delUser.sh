#!/bin/bash
cd /etc/openvpn/easy-rsa
./easyrsa revoke $1
./easyrsa gen-crl
cp pki/crl.pem /etc/openvpn/server/