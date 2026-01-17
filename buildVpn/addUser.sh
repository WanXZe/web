#!/bin/bash
# 脚本功能：自动生成OpenVPN客户端证书+ovpn配置文件+打包
# 传参格式：bash 本脚本名.sh 客户端用户名 服务端公网IP 服务端端口
# 示例：bash build_client.sh myuser 1.2.3.4 1194

# 1. 检查传入的参数是否完整（必须3个参数）
if [ $# -ne 3 ];then
    echo "★ 传参错误！正确用法：bash $0 客户端用户名 服务端IP 服务端端口"
    echo "★ 示例：bash $0 testuser 123.123.123.123 1194"
    exit 1
fi
path=$(dirname $(readlink -f $0))
cd /etc/openvpn/easy-rsa/

./easyrsa build-client-full $1 nopass

cd $path
mkdir -p ./$1Info
echo "
client
dev tun
proto udp
remote $2 $3
resolv-retry infinite
nobind
persist-key
persist-tun

ca ca.crt
cert $1.crt
key $1.key
tls-auth tls-auth.key 1
cipher AES-256-GCM
auth SHA512
tls-version-min 1.2
verb 3
" > ./$1Info/$1.ovpn

cp /etc/openvpn/easy-rsa/pki/ca.crt ./$1Info/
mv /etc/openvpn/easy-rsa/pki/issued/$1.crt ./$1Info/
mv /etc/openvpn/easy-rsa/pki/private/$1.key ./$1Info/
cp /etc/openvpn/server/tls-auth.key ./$1Info/

tar -czvf $1.tar.gz ./$1Info

rm -rf ./$1Info