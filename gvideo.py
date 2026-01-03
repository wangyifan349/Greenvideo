
import sqlite3
from flask import Flask, render_template, request, redirect, session, url_for, g, flash
import os

app = Flask(__name__)
app.secret_key = 'my_very_simple_video_site_example'  # Flask会话密钥
DATABASE = 'database.db'  # SQLite数据库文件名

# 获取或创建数据库连接
def get_db():
    # g对象为Flask请求周期内的全局存储容器
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row  # 查询结果为字典形式
    return db

# 执行SQL查询的通用函数
def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

# 初始化数据库，创建用户和视频表
def init_db():
    with app.app_context():
        db = get_db()
        # 用户表：id唯一主键，用户名唯一，密码明文（仅示例，生产不建议明文！）
        db.execute('CREATE TABLE IF NOT EXISTS user (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)')
        # 视频表：包含上传者id、标题、外链、是否隐藏等字段
        db.execute('''
            CREATE TABLE IF NOT EXISTS video (
                id INTEGER PRIMARY KEY,
                title TEXT,
                url TEXT,
                user_id INTEGER,
                is_hidden INTEGER DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES user(id)
            )
        ''')
        db.commit()

# 每次网络请求结束自动关闭数据库连接
@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# 首页：展示所有未隐藏的视频
@app.route('/')
def index():
    username = session.get('username')  # 当前登录用户名
    # 查所有未隐藏视频，连表显示上传者名
    videos = query_db(
        'SELECT video.*, user.username FROM video JOIN user ON video.user_id = user.id WHERE video.is_hidden=0 ORDER BY video.id DESC'
    )
    return render_template('index.html', username=username, videos=videos)

# 注册页面/处理
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username, password = request.form['username'], request.form['password']
        db = get_db()
        try:
            # 新增用户（用户名唯一）
            db.execute('INSERT INTO user (username, password) VALUES (?,?)', (username, password))
            db.commit()
            flash('注册成功，请登录！', "success")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            # 如果用户名被占用
            flash('用户名已存在！', "danger")
    return render_template('register.html')

# 登录页面/处理
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username, password = request.form['username'], request.form['password']
        # 校验用户名和密码
        user = query_db('SELECT * FROM user WHERE username=? AND password=?', [username, password], one=True)
        if user:
            # 通过校验则写入Session
            session['username'] = username
            session['user_id'] = user['id']
            flash('登录成功！', "success")
            return redirect(url_for('index'))
        else:
            flash('用户名或密码错误', "danger")
    return render_template('login.html')

# 退出登录（清理Session）
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# 上传视频
@app.route('/upload', methods=['GET', 'POST'])
def upload():
    # 必须登录
    if 'username' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        title, url = request.form['title'], request.form['url']
        user_id = session['user_id']
        db = get_db()
        # 插入新视频（外链）
        db.execute('INSERT INTO video (title, url, user_id) VALUES (?,?,?)', (title, url, user_id))
        db.commit()
        flash('视频上传成功！', "success")
        return redirect(url_for('my_videos'))
    return render_template('upload.html', username=session['username'])

# 我的（当前登录用户的）视频页面
@app.route('/my_videos')
def my_videos():
    if 'username' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    # 只查当前用户上传的视频
    videos = query_db('SELECT * FROM video WHERE user_id=? ORDER BY id DESC', [user_id])
    return render_template('my_videos.html', username=session['username'], videos=videos)

# 删除自己的某个视频
@app.route('/delete/<int:video_id>')
def delete(video_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    db = get_db()
    # 只允许删除自己的
    db.execute('DELETE FROM video WHERE id=? AND user_id=?', (video_id, user_id))
    db.commit()
    flash('视频删除成功！', "info")
    return redirect(url_for('my_videos'))

# 隐藏/显示自己的某个视频
@app.route('/toggle_hide/<int:video_id>')
def toggle_hide(video_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    # 只允许操作自己的
    video = query_db('SELECT * FROM video WHERE id=? AND user_id=?', (video_id, user_id), one=True)
    if video:
        new_hide_status = 0 if video['is_hidden'] else 1  # 切换隐藏状态
        db = get_db()
        db.execute('UPDATE video SET is_hidden=? WHERE id=?', (new_hide_status, video_id))
        db.commit()
        flash('操作成功', 'success')
    else:
        flash('无权限操作', 'danger')
    return redirect(url_for('my_videos'))

# 按用户名搜索所有可见视频
@app.route('/search')
def search():
    search_user = request.args.get('username')
    videos = []
    if search_user:
        user = query_db('SELECT * FROM user WHERE username=?', [search_user], one=True)
        if user:
            # 只查该用户已公开（未隐藏）的视频
            videos = query_db(
                'SELECT video.*, user.username FROM video JOIN user ON video.user_id=user.id WHERE user.username=? AND video.is_hidden=0', [search_user]
            )
    return render_template('index.html', username=session.get('username'), videos=videos)

# 视频唯一详情页，已隐藏则不可访问
@app.route('/videos/<int:video_id>')
def detail(video_id):
    video = query_db('SELECT video.*, user.username FROM video JOIN user ON video.user_id = user.id WHERE video.id=?', [video_id], one=True)
    if (not video) or video['is_hidden']:
        # 视频不存在或已被隐藏
        return render_template('notfound.html', message="视频不存在或已被隐藏")
    return render_template('detail.html', video=video, username=session.get('username'))

# 项目启动入口
if __name__ == '__main__':
    # 若数据库文件不存在则初始化
    if not os.path.exists(DATABASE):
        init_db()
    app.run(debug=True)

## 1. `base.html`（所有页面继承自这里）


<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <title>极简视频平台</title>
    <!-- 引入Bootstrap样式 -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background: #f7fafc; }
        .video-card { margin-bottom: 1em; }
    </style>
</head>
<body>
<!-- 顶部导航栏，含登录、退出、我的视频等 -->
<nav class="navbar navbar-expand-lg navbar-light bg-light mb-4">
  <div class="container">
    <!-- 网站名点击返回首页 -->
    <a class="navbar-brand" href=" 'index') }}">极简视频平台</a >
    <div class="collapse navbar-collapse">
      <ul class="navbar-nav me-auto">
        {% if username %}
        <!-- 登录后展示“我的视频”“上传”入口 -->
        <li class="nav-item"><a class="nav-link" href="{{ url_for('my_videos') }}">我的视频</a ></li>
        <li class="nav-item"><a class="nav-link" href="{{ url_for('upload') }}">上传</a ></li>
        {% endif %}
      </ul>
      <ul class="navbar-nav ms-auto">
        {% if username %}
        <!-- 登录态显示问候和退出 -->
        <li class="nav-item"><span class="navbar-text">你好，{{ username }}</span></li>
        <li class="nav-item"><a class="nav-link" href="{{ url_for('logout') }}">退出</a ></li>
        {% else %}
        <!-- 未登录显示登录/注册入口 -->
        <li class="nav-item"><a class="nav-link" href="{{ url_for('login') }}">登录</a ></li>
        <li class="nav-item"><a class="nav-link" href="{{ url_for('register') }}">注册</a ></li>
        {% endif %}
      </ul>
    </div>
  </div>
</nav>

<div class="container">
    <!-- 消息提示区 -->
    {% with messages = get_flashed_messages(with_categories=true) %}
      {% if messages %}
        {% for category, message in messages %}
          <div class="alert alert-{{ category }} alert-dismissible fade show" role="alert">
            {{ message }}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
          </div>
        {% endfor %}
      {% endif %}
    {% endwith %}
    <!-- 渲染子页面内容 -->
    {% block content %}{% endblock %}
</div>
<!-- 引入Bootstrap脚本 -->
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>

---

## 2. `index.html`（首页/搜索结果页）


{% extends "base.html" %}
{% block content %}
<h2 class="mb-3">全部视频</h2>
<!-- 用户名搜索表单 -->
<form class="row row-cols-lg-auto g-3 align-items-center mb-4" action="{{ url_for('search') }}" method="get">
    <div class="col-12">
        <input name="username" class="form-control" placeholder="按用户名搜索" required>
    </div>
    <div class="col-12">
        <button type="submit" class="btn btn-primary">搜索</button>
    </div>
</form>
<!-- 视频卡片循环区 -->
<div>
    {% for video in videos %}
      <div class="card video-card">
        <div class="card-body">
          <!-- 视频标题，点开进入详情页 -->
          <h5 class="card-title">
            <a href="{{ url_for('detail', video_id=video['id']) }}">{{ video['title'] }}</a >
          </h5>
          <p class="mb-2">by <span class="badge bg-info text-dark">{{ video['username'] }}</span></p >
          <!-- 跳转详情页和原始外链 -->
          <a href="{{ url_for('detail', video_id=video['id']) }}" class="btn btn-outline-secondary btn-sm">详情页</a >
          <a href="{{ video['url'] }}" target="_blank" class="btn btn-primary btn-sm">跳转外链</a >
        </div>
      </div>
    {% else %}
      <!-- 如果没有可见视频，提示 -->
      <div class="alert alert-warning">暂无视频</div>
    {% endfor %}
</div>
{% endblock %}


---

## 3. `detail.html`（视频详情唯一页）


{% extends "base.html" %}
{% block content %}
<!-- 视频详情卡片，唯一链接 -->
<div class="card" style="max-width: 480px; margin: 0 auto">
    <div class="card-body">
        <h3 class="card-title">{{ video['title'] }}</h3>
        <hr>
        <p class="card-text">上传者：<b>{{ video['username'] }}</b></p >
        <p>
            <!-- 原始外链跳转按钮 -->
            <a href="{{ video['url'] }}" target="_blank" class="btn btn-success">跳转到原始外链</a >
        </p >
        <!-- 展示本详情页URL，可复制 -->
        <p class="text-muted">本视频唯一页面地址：
            <input type="text" class="form-control mb-1" readonly value="{{ request.url }}">
            <small>可复制分享此链接</small>
        </p >
    </div>
</div>
{% endblock %}


---

## 4. `notfound.html`（视频404等情况）


{% extends "base.html" %}
{% block content %}
<div class="alert alert-danger">
    {{ message or "未找到" }}
</div>
{% endblock %}


---

## 5. `login.html`（登录页）


{% extends "base.html" %}
{% block content %}
<h2>登录</h2>
<!-- 登录表单 -->
<form method="post" class="p-4 rounded shadow-sm bg-white" style="max-width:400px;">
    <div class="mb-3">
      <label>用户名</label>
      <input type="text" name="username" class="form-control" required>
    </div>
    <div class="mb-3">
      <label>密码</label>
      <input type="password" name="password" class="form-control" required>
    </div>
    <button type="submit" class="btn btn-primary w-100">登录</button>
</form>
{% endblock %}

---

## 6. `register.html`（注册页）


{% extends "base.html" %}
{% block content %}
<h2>注册</h2>
<!-- 注册表单 -->
<form method="post" class="p-4 rounded shadow-sm bg-white" style="max-width:400px;">
    <div class="mb-3">
      <label>用户名</label>
      <input type="text" name="username" class="form-control" required>
    </div>
    <div class="mb-3">
      <label>密码</label>
      <input type="password" name="password" class="form-control" required>
    </div>
    <button type="submit" class="btn btn-success w-100">注册</button>
</form>
{% endblock %}


---

## 7. `upload.html`（上传页）


{% extends "base.html" %}
{% block content %}
<h2>上传新视频</h2>
<!-- 上传视频表单 -->
<form method="post" class="p-4 rounded shadow-sm bg-white" style="max-width:500px;">
    <div class="mb-3">
      <label>标题</label>
      <input type="text" name="title" class="form-control" required>
    </div>
    <div class="mb-3">
      <label>视频链接（如任意视频网站url）</label>
      <input type="url" name="url" class="form-control" required>
    </div>
    <button type="submit" class="btn btn-success w-100">上传</button>
</form>
{% endblock %}

---

## 8. `my_videos.html`（我的视频管理）


{% extends "base.html" %}
{% block content %}
<h2>我的视频</h2>
<!-- 我的上传视频列表 -->
<div>
    {% for video in videos %}
      <div class="card video-card {% if video['is_hidden'] %}border-warning{% endif %}">
        <div class="card-body">
          <h5 class="card-title">
            <!-- 标题可跳到详情页 -->
            <a href="{{ url_for('detail', video_id=video['id']) }}">{{ video['title'] }}</a >
            {% if video['is_hidden'] %}
              <span class="badge bg-warning text-dark">已隐藏</span>
            {% endif %}
          </h5>
          <!-- 详情页、原外链、隐藏切换和删除 -->
          <a href="{{ url_for('detail', video_id=video['id']) }}" class="btn btn-outline-secondary btn-sm">详情页</a >
          <a href="{{ video['url'] }}" target="_blank" class="btn btn-primary btn-sm">跳转外链</a >
          <a href="{{ url_for('toggle_hide', video_id=video['id']) }}" class="btn btn-outline-warning btn-sm">
            {{ "取消隐藏" if video['is_hidden'] else "隐藏" }}
          </a >
          <a href="{{ url_for('delete', video_id=video['id']) }}" class="btn btn-outline-danger btn-sm" onclick="return confirm('确定删除吗？')">删除</a >
        </div>
      </div>
    {% else %}
      <div class="alert alert-info">你还没有上传任何视频。</div>
    {% endfor %}
</div>
{% endblock %}
