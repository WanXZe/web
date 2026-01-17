#引入
from flask import *
from functools import wraps
from uuid import uuid4
import sqlite3
import hashlib
import re
from PIL import Image,ImageDraw, ImageFont
import string
import random

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import Header
import ssl
import random
from datetime import datetime
import os
import markdown2
import sys

#配置部分
app = Flask(__name__)

Config = {}  
Config["PATH"] = os.path.dirname(os.path.abspath(__file__))
# 验证码长度
Config["captcha"] = 4
if sys.platform == "win32":
    Config["DATABASE"] = r'E:\my_code\web\blog\database.db'
    Config["font"] = ImageFont.truetype('C:/Windows/Fonts/simhei.ttf', 30)
    app.secret_key = 'supersafe'
else:
    Config["DATABASE"] = '/var/www/html/database.db'
    Config["font"] = ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf', 30)
    app.secret_key = f'{uuid4()}supersafe'


def log_create(level, userid, event):
    log_path = os.path.join(Config["PATH"], 'logs')
    file_name = f'{datetime.now().strftime("%Y-%m-%d")}.log'
    if not os.path.exists(log_path):
        os.makedirs(log_path)
    if not os.path.isfile(os.path.join(log_path, file_name)):
        with open(os.path.join(log_path, file_name), 'w', encoding='utf-8') as fb:
            fb.write('level,userid,event,time\n')
            fb.close()
    with open(os.path.join(log_path, file_name), 'a', encoding='utf-8') as fb:
        fb.write(f'{level},{userid},{event},{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}\n')
        fb.close()
    
#密码加密函数
def hash_password(raw_password):
    combined = 'super' + raw_password + 'safe'
    return hashlib.sha256(combined.encode('utf-8')).hexdigest()

#数据库函数
def get_db():
    db = getattr(g,'_datbase',None)
    if db == None:
        db = g._database = sqlite3.connect(Config["DATABASE"])
        db.row_factory = sqlite3.Row
    return db

# 初始化数据库
def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r', encoding='utf-8') as f:
            db.cursor().executescript(f.read())
        db.commit()

# 数据库交互函数
def search_db(command,value=None):
    db = get_db()
    cursor = db.cursor()
    if value:
        cursor.execute(command,value)
    else:
        cursor.execute(command)
    infomation = cursor.fetchone()
    return infomation

def search_dbs(command, value=None):
    db = get_db()
    cursor = db.cursor()
    if value:
        cursor.execute(command,value)
    else:
        cursor.execute(command)
    infomation = cursor.fetchall()
    return infomation

def add_db(command, value=None):
    db = get_db()
    cursor = db.cursor()
    if value:
        try:
            cursor.execute(command,value)
            db.commit()
        except sqlite3.Error as e:
            db.rollback()
            if e:
                log_create('ERROR', '/system', f'Database error: {e}')
                return e
            else:
                return 0
        finally:
            db.close()
    else:
        try:
            cursor.execute(command)
            db.commit()
        except sqlite3.Error as e:
            db.rollback()
            if e:
                log_create('ERROR', '/system', f'Database error: {e}')
                return e
            else:
                return 0
        finally:
            db.close()

# 登入/注册函数
def search(input_name):
    user = search_db("select user_password, id, user_identity from users where user_name = ?",(input_name,))
    if user:
        return user['user_password'], user['id'], user['user_identity']
    else:
        return 0, 0, 0

def name_vaild(name):
    pattern = r'^[0-9a-zA-Z@_]{4,20}$'
    if not re.fullmatch(pattern,name):
        return 1
    else:
        try:
            output = search_db("select user_name from users where user_name = ?",(name,))
            if output is not None:
                return 2
        except:
            return 3
    return 0

# 删除/修改/创建+用户/文章
def create_account(name, pswd, mail):
    log_create('INFO', f"/{name}", f'创建用户{name},邮箱{mail}')
    add_db("INSERT INTO users (id, user_name, user_password, user_mail) VALUES (?, ?, ?, ?)",(str(uuid4()),name, hash_password(pswd),mail))
    
def update_name(id,name,old_name):
    log_create('INFO', f"{session['id']}/{session['user-name']}", f'修改用户名为{name}')
    try:
        e1 = add_db(f"UPDATE users SET user_name = ? WHERE id = ?",(name,id))
    except:
        log_create('WARNING', f"{session['id']}/{session['user-name']}", f'修改用户名为{name}失败！{e1}')
        return e1
    finally:
        try:
            e2 = add_db(f"UPDATE articles SET author = ? WHERE author = ?",(name,old_name))
            return 0
        except:
            log_create('WARNING', f"{session['id']}/{session['user-name']}", f'修改文章作者名失败！{e2}')
            return e2

def del_account(id):
    log_create('WARNING', f"{session['id']}/{session['user-name']}", f'删除用户ID为{id},name为{session["user-name"]}的用户')
    add_db(f"DELETE FROM users WHERE id = ?",(id,))
    
def create_article(title,content,author):
    try:
        log_create("INFO", f"{session['id']}/{session['user-name']}", f'创建文章title={title}')
        e = add_db("INSERT OR IGNORE INTO articles (title, content, author, author_id) VALUES (?,?,?,?)",(title, content, author, session['id']))
        return 0
    except:
        log_create("WARNING", f"{session['id']}/{session['user-name']}", f'创建文章失败！{e}')
        return e
    
def update_article_funtion(id, title, content, author):
    try:
        log_create("INFO", f"{session['id']}/{session['user-name']}", f'更新文章title={title},id={id}')
        e = add_db("UPDATE articles SET title=?, content=?, author=? WHERE id = ?",(title, content, author, id))
        return 0
    except :
        log_create("WARNING", f"{session['id']}/{session['user-name']}", f'创建文章失败！{e}')
        return e

def del_article(id):
    try:
        log_create("INFO", f"{session['id']}/{session['user-name']}", f'删除文章id={id}')
        e = add_db("DELETE FROM articles WHERE id = ?",(id,))
        return 0
    except :
        log_create("WARNING", f"{session['id']}/{session['user-name']}", f'创建文章失败！{e}')
        return e
           
#验证码生成
# 1. 生成随机验证码
def generate_captcha_text(length=Config["captcha"]):
    chars = string.digits + string.ascii_letters  # 数字+大小字母
    return "".join(random.choice(chars) for _ in range(length))

# 2. 绘制验证码图片（加干扰线、噪点，防止识别
def generate_captcha_image(text):
    width, height = 120, 60
    img = Image.new("RGB", (width, height), (255, 255, 255))  # 白色背景
    draw = ImageDraw.Draw(img)

    # 绘制验证码字符（随机位置、颜色）
    for i, char in enumerate(text):
        x = random.randint(i * width // len(text), (i + 1) * width // len(text) - 20)
        y = random.randint(10, height - 30)
        draw.text(
            (x, y),
            char,
            fill=(random.randint(0, 150), random.randint(0, 150), random.randint(0, 150)),
            font=Config["font"],
        )

    # 绘制干扰
    for _ in range(18):
        start = (random.randint(0, width), random.randint(0, height))
        end = (random.randint(0, width), random.randint(0, height))
        draw.line(
            [start, end],
            fill=(random.randint(180, 255), random.randint(180, 255), random.randint(180, 255)),
            width=2,
        )

    # 绘制噪点
    for _ in range(85):
        draw.point(
            (random.randint(0, width), random.randint(0, height)),
            fill=(random.randint(0, 255), random.randint(0, 255), random.randint(0, 255)),
        )

    # 转为字节流（用于HTTP响应
    from io import BytesIO
    buf = BytesIO()
    img.save(buf, "PNG")
    buf.seek(0)
    return buf

def is_acc_captcha(captcha: str) -> dict:
    secrect_captcha = session.get("captcha", "")
    # 验证后立即重置验证码，防止重放攻击
    session["captcha"] = str(uuid4())
    if not secrect_captcha:
        return {"status": False, "message": "验证码未授权！"}
    if not captcha or len(captcha) != Config["captcha"] or captcha.lower() != secrect_captcha.lower():
        return {"status": False, "message": "验证码错误!"}
    return {"status": True, "message": "验证码验证成功！"}
    
def send_vc(Class, to_email):
    smtp_server = "smtp.exmail.qq.com"
    smtp_port = 465
    from_email = "wanxze@wanxze.space"
    password = "ojmo7hdHsunbt2KZ"
    try:
        msg = MIMEMultipart()
        msg['From'] = from_email
        msg['To'] = to_email
        msg['Subject'] = Header("邮箱验证", 'utf-8').encode()
        verification_code = generate_captcha_text(6)
        session['verification_code'] = verification_code
        if Class == 1:
            log_create('INFO', f"注册/{session.get('temp_acc')['username']}", f'发送邮箱验证码到{to_email}')
            body = """
            <html>
                <body>
                    <h2>验证码邮件</h2>
                    <p>您好！{}</p>
                    <p>您请求的验证码是<p><strong style="font-size: 24px; color: #1890ff;">{}</strong></p>
                    <p>请在10分钟内使用此验证码完成验证。</p>
                    <p>发送时间为: {}</p>
                    <p>如果您没有请求此验证码，请忽略此邮件.</p>
                    <hr>
                    <p style="color: #999; font-size: 12px;">此邮件由系统自动发送，请勿回复.</p>
                </body>
            </html>
            """.format(session.get("temp_acc")['username'],verification_code,datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        elif Class == 2:
            log_create('INFO', f"更改密码/{session.get('temp_id')}", f'发送邮箱验证码到{to_email}更改密码')
            body = """
            <html>
                <body>
                    <h2>验证码邮件</h2>
                    <p>您好！您正在修改密码！</p>
                    <p>您请求的验证码是<p><strong style="font-size: 24px; color: #1890ff;">{}</strong></p>
                    <p>请在10分钟内使用此验证码完成验证。</p>
                    <p>发送时间为: {}</p>
                    <p>如果您没有请求此验证码，请忽略此邮件.</p>
                    <hr>
                    <p style="color: #999; font-size: 12px;">此邮件由系统自动发送，请勿回复.</p>
                </body>
            </html>
            """.format(verification_code,datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        else:
            body="ERROR"
        msg.attach(MIMEText(body, 'html', 'utf-8'))
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(smtp_server, smtp_port, context=context) as server:
            server.login(from_email, password)
            server.send_message(msg)
            return 0
    except Exception as e:
        return e

def send_Q(body):
    smtp_server = "smtp.exmail.qq.com"
    smtp_port = 465
    from_email = "wanxze@wanxze.space"
    password = "ojmo7hdHsunbt2KZ"
    log_create('INFO', f"{session['id']}/{session['user-name']}", f'发送邮箱问题')

    try:
        msg = MIMEMultipart()
        msg['From'] = from_email
        msg['To'] = from_email
        msg['Subject'] = Header("想学", 'utf-8').encode()
        verification_code = generate_captcha_text(6)
        session['verification_code'] = verification_code
        msg.attach(MIMEText(body, 'html', 'utf-8'))
        context = ssl.create_default_context()
        
        with smtplib.SMTP_SSL(smtp_server, smtp_port, context=context) as server:
            server.login(from_email, password)
            server.send_message(msg)
            return 0

    except Exception as e:
        return e

def is_acc_vc(vc: str) -> dict:
    secrect_vc = session.get("verification_code", "")
    # 验证后立即重置验证码，防止重放攻击
    session["verification_code"] = str(uuid4())
    if not secrect_vc:
        return {"status": False, "message": "验证码未授权！"}
    if not vc or len(vc) != Config["captcha"] or vc.lower() != secrect_vc.lower():
        return {"status": False, "message": "验证码错误!"}
    return {"status": True, "message": "验证码验证成功！"}

#装饰器部分
def login_require(f):
    @wraps(f)
    def function(*args, **kwargs):
        if 'id' not in session:
            return redirect(url_for('login'))
        else:
            return f(*args, **kwargs)
    return function

def sudo_require(f):
    @wraps(f)
    def function(*args,**kwargs):
        if session['user-identity'] == 'administrator':
            return f(*args,**kwargs)
        else:
            return render_template('/error/403.html')
    return function

def is_author_or_admin_require(f):
    @wraps(f)
    def function(*args,**kwargs):
        db = get_db()
        cursor = db.cursor()
        cursor.execute("select author_id from articles where id=?",(kwargs.get('id'),))
        article = cursor.fetchone()
        if article and article['author_id'] == session['id'] or session['user-identity'] == 'administrator':
            return f(*args,**kwargs)
        else:
            return render_template('/error/403.html')
    return function

#路由部分
@app.route("/robots.txt")
def robots():
    return "User-agent: *<br/>Disallow: *"

@app.errorhandler(404)
def not_found(error):
    return render_template('/error/404.html'), 404

@app.route('/', methods=['GET','POST'])
def index():
    if request.method=="POST":
        # 验证图像验证码
        response = is_acc_captcha(request.form.get("captcha"))
        if response["status"]:
            body=f"ID:{request.form.get("id")}<br/>用户:{request.form.get("author")}<br/>说：{request.form.get("Q")}"
            send_Q(body)
            return render_template('index.html',msg="发送成功！")
        else:
            return render_template('index.html',msg=response["message"])
    return render_template('index.html') 
    
@app.route("/captcha")
def captcha():
    text = generate_captcha_text()
    session["captcha"] = text
    img_buf = generate_captcha_image(text)
    response = make_response(img_buf.read())
    response.headers["Content-Type"] = "image/png"
    return response

@app.route('/login',methods=['POST','GET'])
def login():
    if 'id' in session:
        return render_template('index.html')
    if request.method == "POST":
        # 验证图像验证码
        response = is_acc_captcha(request.form.get("captcha", ""))
        if response["status"]:
            if request.form.get('username'):
                user_name =  request.form.get('username')
                input_pswd,id, identity = search(user_name)
            
                if input_pswd == 0 and id == 0 and identity == 0:
                    return render_template('login.html',error="用户不存在")
                
                if input_pswd == hash_password(request.form.get('password')): 
                    session['id'] = id
                    session['user-name'] = user_name
                    session['user-identity'] = identity
                    log_create('INFO', f"{id}/{user_name}", '用户登录')
                    return redirect(url_for('index'))
                else:
                    log_create('WARNING', f"{id}/{user_name}", '用户登录失败，密码错误')
                    return render_template('login.html',error="密码错误!")
        else:
            log_create('WARNING', f"/{request.form.get('username')}", '用户登录失败，验证码错误')
            return render_template('login.html',error=response["message"])
    return render_template('login.html', message=request.args.get('message'))
 
@app.route('/register',methods=['POST','GET'])
def register():
    if id in session:
        return redirect(url_for('index'))
    else:
        if session.get('temp_acc'):
            if session.get('verification_code'):
                # 验证邮箱
                response = is_acc_vc(request.form.get("verification_code", ""))
                if response["status"]:
                    create_account(session.get('temp_acc')['username'],session.get('temp_acc')['password'],session.get('temp_acc')['to_mail'])
                    INFO = search_db("select id, user_name, user_identity from users where user_name=?",(session.get('temp_acc')['username'],))
                    session.clear()
                    session['id'], session['user-name'], session['user-identity']= INFO[0], INFO[1], INFO[2]
                    return redirect(url_for('login',message = "用户注册成功！请登入！"))
                else:
                    return render_template('register.html',error=response["message"])
            elif request.form.get('to_mail'):
                pattern = r'^[a-zA-Z0-9_.+-]+@wanxze\.space$'
                if re.fullmatch(pattern, request.form.get('to_mail')):
                    send_vc(1,request.form.get('to_mail'))
                    session['temp_acc']['to_mail'] = request.form.get('to_mail')
                    return render_template('register.html')
                else:
                    return render_template('register.html',error="必须以@wanxze.space结尾的邮箱才可以注册！！！")
            return render_template('register.html')
        else:
            if request.method == 'POST':
                # 验证图像验证码
                response = is_acc_captcha(request.form.get("captcha", ""))
                if response["status"]:
                    if request.form.get('username') and request.form.get('password') and request.form.get('confirm_password'):
                        name = request.form.get('username')
                        error = name_vaild(name)
                        if request.form.get('password') != request.form.get('confirm_password'):
                            return render_template('register.html',error="密码不一致")
                        elif error == 1:
                            return render_template('register.html',error="非法字符!")
                        elif error == 2:
                            return render_template('register.html',error="用户名重复")
                        elif error == 3:
                            return render_template('register.html',error="数据库出错")
                        else:
                            session['temp_acc']={'username':request.form.get('username'),'password':request.form.get('password')}
                            return render_template('register.html',msg="请验证邮箱验证码，完成注册")
                    else:
                        return render_template('register.html',error="请输入账号密码")
                else:
                    return render_template('register.html',error=response["message"])
            else:
                return render_template('register.html')
    
@app.route('/logout',methods=['POST','GET'])
def logout():
    log_create('INFO', f"{session.get('id')}/{session.get('user-name')}", '用户登出')
    session.clear()
    return render_template('logout.html',message=request.args.get('message'))

@app.route('/blogs')
@login_require
def blog():
    articles = search_dbs("select id, title, author, created_at from articles")
    return render_template('blogs.html',list=articles)

@app.route('/admin', methods=['POST','GET'])
@login_require
@sudo_require
def admin():
    log_create("INFO", f"{session['id']}/{session['user-name']}", f'访问管理员页面')
    if request.method == 'POST':
        if request.form.get('table_name') == "arcticles":
            del_article(request.form.get('del_id'))
        elif request.form.get('table_name') == "users":
            del_account(request.form.get('del_id'))
    users = search_dbs("select id, user_name, user_password from users")
    articles = search_dbs("select id, title, author from articles")
    return render_template('admin.html',users=users,articles=articles)

@app.route('/article/<int:id>',methods=['POST','GET'])
@login_require
def article(id):
    log_create('INFO', f"{session.get('id')}/{session.get('user-name')}", f'查看文章id={id}')
    try:
        raw_article = search_db("select title,author,content from articles where id=?",(id,))
        article = {
            "title": raw_article[0], 
            "author": raw_article[1], 
            "content": markdown2.markdown(raw_article[2])
        }
        return render_template('article.html',article=article)
    except:
        return render_template('article.html',error = "文章不存在！")
    
@app.route('/update_article/<int:id>',methods=['POST','GET'])
@login_require
@is_author_or_admin_require
def update_article(id):
    if request.method == 'POST' and request.form.get('title'):
        update_article_funtion(id, request.form.get('title'), request.form.get('content').strip().replace('<', '&lt;').replace('>', '&gt;'), session['user-name'])
        return redirect(url_for('article', id=id))
    else:
        try:
            article = search_db("select id, title, author, content from articles where id=?",(id,))
            return render_template('profile.html', option=1, article=article)
        except:
            return render_template('article.html',error = "文章不存在！")

@app.route('/profile/<int:option>',methods=['POST','GET'])
@login_require
def profile(option):
    if request.form.get("captcha"):
        # 验证图像验证码
        response = is_acc_captcha(request.form.get("captcha", ""))
        if response["status"]:
            if option == 1:
                if request.form.get('author'):
                    create_article(
                        request.form.get('title'),
                        request.form.get('content').strip().replace('<', '&lt;').replace('>', '&gt;'),
                        session['user-name']
                    )
                    return redirect(url_for('blog'))
                else:
                    return render_template('profile.html', option=option, user=[])
                
            elif option == 2:
                if request.form.get('new_name'):
                    name = request.form.get('new_name')
                    error = name_vaild(name)
                    if error == 1:
                        return render_template('/profile/2',error="非法字符!")
                    elif error == 2:
                        return render_template('/profile/2',error="用户名重复")
                    elif error == 3:
                        return render_template('/profile/2',error="数据库错误！")
                    else:
                        update_name(request.form.get('id'),name,session['user-name'])
                        return redirect(url_for('logout',message='用户名修改成功！请重新登入！'))
                else:
                    return render_template('profile.html', option=option)
        else:
            return render_template('profile.html', option=option, error=response["message"])
    else:
        return render_template('profile.html', option=option)
    
@app.route('/personal_articles',methods=['POST','GET'])
@login_require
def personal_articles():
    try:
        list = search_dbs("select id, title, author, created_at from articles where author_id=?",(session['id'],))
        return render_template('personal_articles.html',articles=list)
    except:
        return render_template('personal_articles.html',error = "您还没有文章哦~")
    
@app.route('/forget_password',methods=['POST','GET'])
def forget_password():
    if session.get('id'):
        return redirect(url_for('index'))
    
    if request.method == 'POST' and request.form.get('verification_code'):
        if request.form.get("captcha"):
            if request.form.get("captcha").lower() == session.get("captcha").lower():   
                if session.get('verification_code').lower() == request.form.get("verification_code").lower():
                    add_db("UPDATE users SET user_password = ? WHERE id = ?",(hash_password(request.form.get('new_password')),session.get('temp_id')))
                    session.clear()
                    return render_template('login.html',message="密码修改成功~~")
                else:
                    return render_template('forget_password.html',step=2, error="邮箱验证码错误！")
            else:
                return render_template('forget_password.html',step=2, error="图形验证码错误！")
        else:
            return render_template('forget_password.html',step=2)
    else:
        if request.method == 'POST':
            if request.form.get("captcha"): 
                if request.form.get("captcha").lower() == session.get("captcha").lower():
                    if request.form.get('username') and request.form.get('email'):
                        info = search_db("select id from users where user_name = ? and user_mail = ?",(request.form.get('username'),request.form.get('email'))) 
                        if info:
                            send_vc(2, request.form.get('email'))
                            session['temp_id'] = info['id']
                            return render_template('forget_password.html',step=2, message="验证码已发送到您的邮箱，请查收！")
                        else:
                            return render_template('forget_password.html',step=1, error = "用户不存在或邮箱错误！")
                    else:
                        return render_template('forget_password.html',step=1, error="请输入用户名和邮箱！")
                else:
                    return render_template('forget_password.html',step=1, error = "验证码错误！")
        else:
            return render_template('forget_password.html', step=1)

#运行
if __name__ == '__main__':
    init_db()
    log_create('INFO', '/system', '系统启动')
    app.run(port=2026,debug=True)