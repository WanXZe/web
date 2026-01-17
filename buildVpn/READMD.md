## 声明：本脚本用于一键自动搭建Ubuntu系统端口流量转发，含简单的前端管理（更新ing）
## 搭建流程
1.进入文件夹
```bash
cd ./vpn
```
2.以root身份运行脚本build.sh，一键搭建
```bash
sudo bash ./build.sh
```
3.以root身份运行脚本addUser.sh，添加用户证书和密钥
注意此脚本需要三个参数 分别是 用户名 服务器IP 端口
```bash
sudo bash ./addUser.sh username ip 1194
```
此时在当前文件夹会生成一个 username.tar.gz的压缩包
4.在客户端安装openvpn,启动openvpn
5.解压username.tar.gz,进入username,usernameInfo
6.双击username.ovpn，在openvpn中点击连接
7.del.sh是删除服务器端口转发功能（删除本项目）
8.delUser是删除用户
```bash
sudo bash ./delUser.sh username
```
9.前端
127.0.0.1:2026