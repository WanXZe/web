#!/bin/bash
set -e

# 停止并禁用 OpenVPN 服务
sudo systemctl stop openvpn@server || true
sudo systemctl disable openvpn@server || true
sudo systemctl daemon-reload || true

# 停止后台 Web 管理进程（如果有）
sudo pkill -f 'app.py' || true

# 卸载相关软件（包含用于持久化 iptables 的包）
sudo apt purge -y openvpn easy-rsa iptables-persistent netfilter-persistent || true
sudo apt autoremove -y || true

# 删除配置与日志
sudo rm -rf /etc/openvpn || true
sudo rm -rf /var/log/vpn || true

# 清理 iptables（包括 NAT）
sudo iptables -t nat -F || true
sudo iptables -F || true
sudo iptables -X || true

# 删除持久化规则文件（iptables-persistent 产生）
sudo rm -f /etc/iptables/rules.v4 /etc/iptables/rules.v6 /etc/iptables/* || true

# 恢复内核转发为禁用（可根据需要手动启用）
sudo sed -i 's/^net.ipv4.ip_forward =.*/net.ipv4.ip_forward = 0/' /etc/sysctl.conf || true
sudo sysctl -p || true

echo "已移除 OpenVPN、证书、持久化防火墙规则，清空 iptables 规则并禁用 IP 转发。"