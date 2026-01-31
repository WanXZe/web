#!/bin/bash
cd /etc/openvpn/easy-rsa
./easyrsa revoke $1
./easyrsa gen-crl
cp pki/crl.pem /etc/openvpn/server/
chmod 644 /etc/openvpn/server/crl.pem
systemctl restart openvpn@server
echo "已撤销证书 $1，并更新 CRL /etc/openvpn/server/crl.pem，已重启 openvpn 服务。"