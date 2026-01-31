#!/bin/bash
set -e
path=$(dirname $(readlink -f $0))
# 检查系统是否为ub
# 1. 检查root权限
ls /root >/dev/null 2>&1
if [[ $? != 0 ]];then
	echo "权限不足！请用 sudo bash $0 运行脚本"
	exit 0
fi

if [[ $(sysctl -n net.ipv4.ip_forward) == 1 ]];then
    echo "内核转发已开启！"
else
    echo 'net.ipv4.ip_forward = 1' >> /etc/sysctl.conf
    sysctl -p
    if [[ $(sysctl -n net.ipv4.ip_forward) == 1 ]];then
        echo "内核转发开启成功！"
    else
        echo "内核转发开启失败！请自行DEBUG！脚本已退出" 
        exit 0
    fi
fi

# 4. 安装依赖：openvpn+easy-rsa+python3+pip
apt install -y openvpn easy-rsa python3 python3-pip iptables
# 如果是国外服务器可以去掉镜像
if [[ $? != 0 ]];then
	apt update -y && apt install -y openvpn==2.4.12 easy-rsa python3 python3-pip iptables
	if [[ $? != 0 ]];then
		echo "安装依赖包失败，请检查网络"
		exit 1
	fi
fi
echo "安装OpenVPN、EasyRSA、Python3、Flask成功"

# ========== 第一步：创建证书工作目录，复制easy-rsa模板 ==========
mkdir -p /etc/openvpn/{server,client,keys}
cp -r /usr/share/easy-rsa /etc/openvpn/easy-rsa
cd /etc/openvpn/easy-rsa

# ========== 第二步：初始化证书环境（PKI公钥基础设施） ==========
if [ -d './pki' ];then
    echo "目录 PKI 已存在，跳过初始化"
    :
else
    ./easyrsa init-pki
    ./easyrsa build-ca nopass
    ./easyrsa build-server-full server nopass
    ./easyrsa gen-dh
    openvpn --genkey --secret ../keys/tls-auth.key
    cp ./pki/ca.crt ./pki/issued/server.crt ./pki/private/server.key ./pki/dh.pem ../keys/tls-auth.key ../server/
fi
echo "OpenVPN全套证书生成成功"

# 6. OpenVPN服务端核心配置
echo '
# ===================== 基础网络配置 =====================
port 1194                  # OpenVPN默认端口，UDP协议，防火墙已放行
proto udp                  # 推荐UDP：速度快、延迟低、适合办公，穿透性强；可选tcp 443（伪装HTTPS）
dev tun                    # tun模式：路由模式，支持跨网段访问（企业必选）
ca /etc/openvpn/server/ca.crt       # CA根证书路径
cert /etc/openvpn/server/server.crt # 服务端证书路径
key /etc/openvpn/server/server.key  # 服务端密钥路径（保密）
dh /etc/openvpn/server/dh.pem       # DH密钥路径

# ===================== 合规强加密配置（监管要求，禁止修改弱加密） =====================
tls-auth /etc/openvpn/server/tls-auth.key 0  # 防攻击密钥，0代表服务端
cipher AES-256-GCM        # 核心加密算法：AES-256位，目前最安全的对称加密，国密合规
auth SHA512               # 校验算法：SHA512，防止数据篡改
tls-version-min 1.2       # 禁用低版本TLS，仅用TLS1.2+，杜绝安全漏洞
tls-cipher TLS-DHE-RSA-WITH-AES-256-GCM-SHA384 # 强加密套件组合

# ===================== VPN网段与路由配置（核心，按需修改） =====================
server 10.8.0.0 255.255.255.0  # OpenVPN的虚拟网段，不要和你的企业内网网段重复即可
ifconfig-pool-persist ipp.txt   # 记录客户端IP分配，重启后不变，方便审计


# ===================== 安全加固配置 =====================
keepalive 10 120          # 心跳检测：10秒发一次包，120秒无响应则断开
comp-lzo no
# allow-compression no               # 禁用压缩，防止CRIME攻击，合规要求
# user nobody               # 以最小权限用户运行，防止提权
# group nogroup
persist-key
persist-tun               # 断线重连时保留配置，避免反复认证

# ===================== 合规审计日志配置（必须项，监管必查，红线！） =====================
status /var/log/vpn/openvpn-status.log  # 在线用户状态日志：谁在线、IP、连接时间
log-append /var/log/vpn/openvpn.log     # 完整系统日志：所有连接/断开/错误记录
verb 3                    # 日志详细级别：3级刚好，既详细又不冗余
mute 20                   # 抑制重复日志，避免日志刷屏
' > /etc/openvpn/server.conf

# 7. 防火墙配置 + NAT（使用 iptables）
# 检测公网接口（用于 NAT）
PUB_IF=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i=="dev") print $(i+1)}' | head -n1)

if [ -z "$PUB_IF" ]; then
    PUB_IF=$(ip route | awk '/default/ {print $5; exit}')
fi
echo "Detected public interface: $PUB_IF"
# 允许必要端口并启用转发/NAT
iptables -A INPUT -i "$PUB_IF" -p udp --dport 1194 -j ACCEPT
iptables -A INPUT -i "$PUB_IF" -p tcp --dport 2026 -j ACCEPT
iptables -A INPUT -i "$PUB_IF" -p tcp --dport 22 -j ACCEPT
# 允许从 VPN 子网转发，并接受已建立连接返回
iptables -A FORWARD -s 10.8.0.0/24 -j ACCEPT
iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
# NAT: 把 VPN 子网流量伪装成服务器公网IP
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o "$PUB_IF" -j MASQUERADE
# 持久化 iptables 规则
DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent netfilter-persistent
netfilter-persistent save

echo 1 > /proc/sys/net/ipv4/ip_forward
echo "防火墙配置完成（iptables + NAT），放行1194/UDP、2026/TCP、SSH端口"
mkdir -p /var/log/vpn
# 8. OpenVPN服务管理：启动+开机自启
systemctl enable --now openvpn@server
systemctl restart openvpn@server
if [[ $(systemctl is-active openvpn@server) == "active" ]];then
    echo "OpenVPN服务启动成功！"
else
    echo "OpenVPN服务启动失败，请查看日志 /var/log/openvpn.log"
fi


cd $path

# 10. 启动网页管理系统+后台运行+日志持久化
# pip3 install -r ./web/requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
# nohup python3 ./web/app.py >> /var/log/vpn/python.log 2>&1 &
sleep 2
echo "📌 日志文件路径：/var/log/openvpn.log"