sudo systemctl stop openvpn@server
sudo systemctl disable openvpn@server
sudo systemctl daemon-reload
sudo apt purge -y openvpn easy-rsa
sudo apt autoremove -y
sudo rm -rf /etc/openvpn
sudo rm -rf /var/log/vpn
sudo ufw delete allow 1194/udp
sudo ufw delete allow 2026/tcp
sudo ufw reload

sudo sed -i 's/^net.ipv4.ip_forward =.*/net.ipv4.ip_forward = 0/' /etc/sysctl.conf
sudo sysctl -p
