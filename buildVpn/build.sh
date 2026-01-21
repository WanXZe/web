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
    if [[ $(sysctl -n net.ipv4.ip_forward) == 1 ]];then
        echo "内核转发开启成功！"
    else
        echo "内核转发开启失败！请自行DEBUG！脚本已退出" 
        exit 0
    fi
    exit 0
fi

# 4. 安装依赖：openvpn+easy-rsa+python3+pip+flask
apt install -y openvpn easy-rsa python3 python3-pip ufw
# 如果是国外服务器可以去掉镜像
if [[ $? != 0 ]];then
	apt update -y && apt install -y openvpn easy-rsa python3 python3-pip ufw
	pip3 install flask --upgrade -i https://pypi.tuna.tsinghua.edu.cn/simple
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
    echo "OpenVPN全套证书生成成功"
fi

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
push "route 192.168.1.0 255.255.255.0"  # 推送你的【企业内网网段】，员工连上VPN后可访问这个网段
# 【跨境业务必加】推送你获批的境外业务网段/IP，比如：push "route 203.xx.xx.0 255.255.255.0"

# ===================== 安全加固配置 =====================
keepalive 10 120          # 心跳检测：10秒发一次包，120秒无响应则断开
comp-lzo no               # 禁用压缩，防止CRIME攻击，合规要求
user nobody               # 以最小权限用户运行，防止提权
group nogroup
persist-key
persist-tun               # 断线重连时保留配置，避免反复认证

# ===================== 合规审计日志配置（必须项，监管必查，红线！） =====================
status /var/log/vpn/openvpn-status.log  # 在线用户状态日志：谁在线、IP、连接时间
log-append /var/log/vpn/openvpn.log     # 完整系统日志：所有连接/断开/错误记录
verb 3                    # 日志详细级别：3级刚好，既详细又不冗余
mute 20                   # 抑制重复日志，避免日志刷屏
' > /etc/openvpn/server.conf

# 7. 防火墙配置+内核转发放行
# vpn 端口
ufw allow 1194/udp
# 网站端口
ufw allow 2026/tcp
ufw allow ssh
ufw --force enable
echo 1 > /proc/sys/net/ipv4/ip_forward
echo "防火墙配置完成，放行1194/UDP、2026/TCP、SSH端口"
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

# 生成相关脚本
mkdir -p ./web/{templates,static}

cat > ./web/app.py << 'EOF'
#!/usr/bin/env python3
from flask import Flask, render_template, request, redirect, url_for, flash, session, g
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'vpn.db')

app = Flask(__name__)
app.secret_key = os.environ.get('VPN_SECRET') or os.urandom(24)

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
    return db

def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

def init_db():
    with app.app_context():
        db = get_db()
        db.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            price INTEGER NOT NULL,
            stock INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            amount INTEGER NOT NULL,
            status TEXT DEFAULT 'paid',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(product_id) REFERENCES products(id)
        );
        ''')
        db.commit()
        admin = query_db('SELECT * FROM users WHERE username = ?', ('admin',), one=True)
        if not admin:
            db.execute('INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)',
                       ('admin', generate_password_hash('admin'), 1))
        prod = query_db('SELECT * FROM products LIMIT 1')
        if not prod:
            db.execute('INSERT INTO products (name, price, stock) VALUES (?, ?, ?)',
                       ('VPN-1 Month', 100, 100))
        db.commit()

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def current_user():
    uid = session.get('user_id')
    if not uid:
        return None
    return query_db('SELECT * FROM users WHERE id = ?', (uid,), one=True)

@app.route('/')
def index():
    products = query_db('SELECT * FROM products')
    user = current_user()
    return render_template('index.html', products=products, user=user)

@app.route('/regist', methods=['GET', 'POST'])
def regist():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            flash('用户名和密码不能为空')
            return redirect(url_for('regist'))
        try:
            db = get_db()
            db.execute('INSERT INTO users (username, password) VALUES (?, ?)',
                       (username, generate_password_hash(password)))
            db.commit()
            flash('注册成功，请登录')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('用户名已存在')
            return redirect(url_for('regist'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = query_db('SELECT * FROM users WHERE username = ?', (username,), one=True)
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            flash('登录成功')
            return redirect(url_for('index'))
        flash('用户名或密码错误')
        return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('已登出')
    return redirect(url_for('index'))

@app.route('/buy/<int:product_id>', methods=['GET', 'POST'])
def buy(product_id):
    user = current_user()
    product = query_db('SELECT * FROM products WHERE id = ?', (product_id,), one=True)
    if not product:
        flash('商品不存在')
        return redirect(url_for('index'))
    if request.method == 'POST':
        if not user:
            flash('请先登录')
            return redirect(url_for('login'))
        amount = int(request.form.get('amount', 1))
        db = get_db()
        if product['stock'] < amount:
            flash('库存不足')
            return redirect(url_for('buy', product_id=product_id))
        db.execute('INSERT INTO orders (user_id, product_id, amount, status) VALUES (?, ?, ?, ?)',
                   (user['id'], product_id, amount, 'paid'))
        db.execute('UPDATE products SET stock = stock - ? WHERE id = ?', (amount, product_id))
        db.commit()
        flash('购买成功')
        return redirect(url_for('orders'))
    return render_template('buy.html', product=product, user=user)

@app.route('/orders')
def orders():
    user = current_user()
    if not user:
        flash('请先登录')
        return redirect(url_for('login'))
    rows = query_db('SELECT o.*, p.name as product_name FROM orders o JOIN products p ON o.product_id = p.id WHERE o.user_id = ? ORDER BY o.created_at DESC', (user['id'],))
    return render_template('orders.html', orders=rows, user=user)

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    user = current_user()
    if not user or not user['is_admin']:
        flash('需要管理员权限')
        return redirect(url_for('login'))
    db = get_db()
    if request.method == 'POST':
        if request.form.get('action') == 'add':
            name = request.form.get('name')
            price = int(request.form.get('price', 0))
            stock = int(request.form.get('stock', 0))
            db.execute('INSERT INTO products (name, price, stock) VALUES (?, ?, ?)', (name, price, stock))
            db.commit()
            flash('已添加商品')
        elif request.form.get('action') == 'restock':
            pid = int(request.form.get('product_id'))
            add = int(request.form.get('add', 0))
            db.execute('UPDATE products SET stock = stock + ? WHERE id = ?', (add, pid))
            db.commit()
            flash('已补货')
    products = query_db('SELECT * FROM products')
    orders = query_db('SELECT o.*, u.username as user_name, p.name as product_name FROM orders o JOIN users u ON o.user_id = u.id JOIN products p ON o.product_id = p.id ORDER BY o.created_at DESC')
    return render_template('admin.html', products=products, orders=orders, user=user)

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=2026, debug=False)
EOF

cat > ./web/templates/index.html << 'EOF'
<!doctype html>
<html lang="zh-cn">
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width,initial-scale=1">
	<title>VPN 商店</title>
	<link rel="stylesheet" href="/static/main.css">
	<style>body{font-family:Arial,Helvetica,sans-serif;padding:20px}</style>
</head>
<body>
	<h1>VPN 商店</h1>
	<p>
		{% if user %}
			欢迎，{{ user.username }} | <a href="{{ url_for('orders') }}">我的订单</a> | <a href="{{ url_for('logout') }}">登出</a>
			{% if user.is_admin %} | <a href="{{ url_for('admin') }}">管理员后台</a>{% endif %}
		{% else %}
			<a href="{{ url_for('login') }}">登录</a> | <a href="{{ url_for('regist') }}">注册</a>
		{% endif %}
	</p>
	<h2>商品列表</h2>
	<table border="1" cellpadding="8" cellspacing="0">
		<tr><th>ID</th><th>商品</th><th>价格</th><th>库存</th><th>操作</th></tr>
		{% for p in products %}
			<tr>
				<td>{{ p.id }}</td>
				<td>{{ p.name }}</td>
				<td>{{ p.price }}</td>
				<td>{{ p.stock }}</td>
				<td><a href="{{ url_for('buy', product_id=p.id) }}">购买</a></td>
			</tr>
		{% endfor %}
	</table>
</body>
</html>
EOF

cat > ./web/templates/login.html << 'EOF'
<!doctype html>
<html lang="zh-cn">
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width,initial-scale=1">
	<title>登录</title>
	<link rel="stylesheet" href="/static/main.css">
</head>
<body>
	<h1>登录</h1>
	{% with messages = get_flashed_messages() %}
		{% if messages %}
			<ul>
			{% for m in messages %}<li>{{ m }}</li>{% endfor %}
			</ul>
		{% endif %}
	{% endwith %}
	<form method="post">
		<label>用户名: <input name="username"></label><br>
		<label>密码: <input name="password" type="password"></label><br>
		<button type="submit">登录</button>
	</form>
	<p><a href="{{ url_for('regist') }}">还没有帐号？注册</a></p>
</body>
</html>
EOF

cat > ./web/templates/register.html << 'EOF'
<!doctype html>
<html lang="zh-cn">
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width,initial-scale=1">
	<title>注册</title>
	<link rel="stylesheet" href="/static/main.css">
</head>
<body>
	<h1>注册</h1>
	{% with messages = get_flashed_messages() %}
		{% if messages %}
			<ul>
			{% for m in messages %}<li>{{ m }}</li>{% endfor %}
			</ul>
		{% endif %}
	{% endwith %}
	<form method="post">
		<label>用户名: <input name="username"></label><br>
		<label>密码: <input name="password" type="password"></label><br>
		<button type="submit">注册</button>
	</form>
	<p><a href="{{ url_for('login') }}">已有帐号？登录</a></p>
</body>
</html>
EOF

cat > ./web/templates/admin.html << 'EOF'
<!doctype html>
<html lang="zh-cn">
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width,initial-scale=1">
	<title>管理员后台</title>
	<link rel="stylesheet" href="/static/main.css">
</head>
<body>
	<h1>管理员后台</h1>
	<p><a href="{{ url_for('index') }}">返回商店</a></p>
	{% with messages = get_flashed_messages() %}
		{% if messages %}
			<ul>
			{% for m in messages %}<li>{{ m }}</li>{% endfor %}
			</ul>
		{% endif %}
	{% endwith %}
	<h2>添加商品</h2>
	<form method="post">
		<input type="hidden" name="action" value="add">
		<label>名称: <input name="name"></label>
		<label>价格: <input name="price" type="number" value="0"></label>
		<label>库存: <input name="stock" type="number" value="0"></label>
		<button type="submit">添加</button>
	</form>
	<h2>商品列表</h2>
	<table border="1" cellpadding="6">
		<tr><th>ID</th><th>名称</th><th>价格</th><th>库存</th><th>操作</th></tr>
		{% for p in products %}
			<tr>
				<td>{{ p.id }}</td>
				<td>{{ p.name }}</td>
				<td>{{ p.price }}</td>
				<td>{{ p.stock }}</td>
				<td>
					<form style="display:inline" method="post">
						<input type="hidden" name="action" value="restock">
						<input type="hidden" name="product_id" value="{{ p.id }}">
						<input name="add" type="number" value="10" style="width:60px">
						<button type="submit">补货</button>
					</form>
				</td>
			</tr>
		{% endfor %}
	</table>
	<h2>订单列表</h2>
	<table border="1" cellpadding="6">
		<tr><th>ID</th><th>用户</th><th>商品</th><th>数量</th><th>状态</th><th>时间</th></tr>
		{% for o in orders %}
			<tr>
				<td>{{ o.id }}</td>
				<td>{{ o.user_name }}</td>
				<td>{{ o.product_name }}</td>
				<td>{{ o.amount }}</td>
				<td>{{ o.status }}</td>
				<td>{{ o.created_at }}</td>
			</tr>
		{% endfor %}
	</table>
</body>
</html>
EOF

cat > ./web/templates/buy.html << 'EOF'
<!doctype html>
<html lang="zh-cn">
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width,initial-scale=1">
	<title>购买</title>
	<link rel="stylesheet" href="/static/main.css">
</head>
<body>
	<h1>购买 - {{ product.name }}</h1>
	{% with messages = get_flashed_messages() %}
		{% if messages %}
			<ul>
			{% for m in messages %}<li>{{ m }}</li>{% endfor %}
			</ul>
		{% endif %}
	{% endwith %}
	<p>价格: {{ product.price }} | 库存: {{ product.stock }}</p>
	<form method="post">
		<label>数量: <input name="amount" value="1" type="number" min="1" max="{{ product.stock }}"></label><br>
		<button type="submit">确认购买（模拟支付）</button>
	</form>
	<p><a href="{{ url_for('index') }}">返回商品页</a></p>
</body>
</html>
EOF

cat > ./web/templates/orders.html << 'EOF'
<!doctype html>
<html lang="zh-cn">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>我的订单</title>
  <link rel="stylesheet" href="/static/main.css">
</head>
<body>
  <h1>我的订单</h1>
  <p><a href="{{ url_for('index') }}">返回</a></p>
  <table border="1" cellpadding="8" cellspacing="0">
    <tr><th>ID</th><th>商品</th><th>数量</th><th>状态</th><th>下单时间</th></tr>
    {% for o in orders %}
      <tr>
        <td>{{ o.id }}</td>
        <td>{{ o.product_name }}</td>
        <td>{{ o.amount }}</td>
        <td>{{ o.status }}</td>
        <td>{{ o.created_at }}</td>
      </tr>
    {% endfor %}
  </table>
</body>
</html>
EOF

cat > ./web/requirements.txt << 'EOF'
Flask>=2.3.3
Werkzeug>=2.3.7
EOF

touch ./web/static/main.css
# 10. 启动网页管理系统+后台运行+日志持久化
pip3 install -r ./web/requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
nohup python3 ./web/app.py >> /var/log/vpn/python.log 2>&1 &
sleep 2
echo "📌 日志文件路径：/var/log/openvpn.log"