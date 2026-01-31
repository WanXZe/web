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

        # seed admin and a sample product
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
    return render_template('regiest.html')


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
        # simulate payment success
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
    app.run(host='0.0.0.0', port=2026, debug=True)