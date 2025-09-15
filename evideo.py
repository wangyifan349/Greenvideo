# -*- coding: utf-8 -*-
"""
单文件 Flask 视频平台（app.py）
功能：
- SQLite 存储用户与视频
- 注册 / 登录 / 退出（密码使用 SHA-256 哈希存储）
- 视频上传到 static/uploads/
- 用户可在个人管理页切换视频的公开/隐藏状态（隐藏的视频不在首页或创作者页显示）
- 首页支持按查询关键字对标题计算 LCS 长度并降序排序
- 创作者搜索（用户名模糊匹配）
- 所有模板内嵌并通过 render_template_string 渲染
保存为 app.py，确保同目录下有 static/uploads/（程序会自动创建），然后运行：python app.py
"""
import os
import sqlite3
import hashlib
from pathlib import Path
from flask import (
    Flask, request, redirect, url_for, session, flash,
    send_from_directory, render_template_string, g
)
from werkzeug.utils import secure_filename
# 配置
app = Flask(__name__)
app.secret_key = os.urandom(24)
BASE_DIR = Path(__file__).parent
DB_PATH = BASE_DIR / "videos.db"
UPLOAD_FOLDER = BASE_DIR / "static" / "uploads"
UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
app.config["UPLOAD_FOLDER"] = str(UPLOAD_FOLDER)
ALLOWED_EXTENSIONS = {"mp4", "avi", "mov", "mkv"}
# 数据库连接
def get_conn():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn
def init_db():
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS videos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT,
                filename TEXT NOT NULL,
                uploader_id INTEGER NOT NULL,
                is_public INTEGER NOT NULL DEFAULT 1,
                FOREIGN KEY (uploader_id) REFERENCES users(id)
            )
        """)
        conn.commit()
@app.before_request
def before_request():
    g.db = get_conn()
@app.teardown_request
def teardown_request(exception):
    db = getattr(g, "db", None)
    if db is not None:
        db.close()
# 工具函数
def sha256_hash(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()
def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
def lcs_length(a: str, b: str) -> int:
    m, n = len(a), len(b)
    if m == 0 or n == 0:
        return 0
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(m):
        for j in range(n):
            if a[i] == b[j]:
                dp[i + 1][j + 1] = dp[i][j] + 1
            else:
                dp[i + 1][j + 1] = max(dp[i][j + 1], dp[i + 1][j])
    return dp[m][n]
def sort_videos_by_lcs(videos, query):
    enriched = []
    for v in videos:
        score = lcs_length(v["title"].lower(), query.lower()) if query else 0
        enriched.append((score, v))
    enriched.sort(key=lambda x: x[0], reverse=True)
    return [v for _, v in enriched]
def current_user():
    uname = session.get("username")
    if not uname:
        return None
    cur = g.db.execute("SELECT * FROM users WHERE username = ?", (uname,))
    return cur.fetchone()
# 模板（Bootstrap 主题：淡绿色与淡金色）
BASE_TEMPLATE = """
<!doctype html>
<html lang="zh">
<head>
    <meta charset="utf-8">
    <title>{% block title %}视频平台{% endblock %}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
      :root{
        --bg-soft:#f7fff7;       /* 淡绿背景 */
        --primary-soft:#c7f9cc;  /* 淡绿 */
        --accent-soft:#fff7d6;   /* 淡金 */
        --muted:#6b6b47;
      }
      body{ background:var(--bg-soft); }
      .navbar{ background: linear-gradient(90deg,var(--primary-soft),var(--accent-soft)); }
      .card{ border-color: rgba(107,107,71,0.12); }
      .btn-primary{ background:var(--muted); border-color:var(--muted); }
      .btn-outline-primary{ color:var(--muted); border-color:var(--muted); }
      .alert-info{ background: var(--accent-soft); color:var(--muted); border:1px solid rgba(107,107,71,0.08); }
    </style>
</head>
<body>
<nav class="navbar navbar-expand-lg mb-4">
  <div class="container-fluid">
    <a class="navbar-brand" href="{{ url_for('index') }}">VideoHub</a>
    <div class="collapse navbar-collapse">
      <ul class="navbar-nav ms-auto">
        {% if session.get('username') %}
          <li class="nav-item"><a class="nav-link" href="{{ url_for('upload') }}">上传视频</a></li>
          <li class="nav-item"><a class="nav-link" href="{{ url_for('manage') }}">个人管理</a></li>
          <li class="nav-item"><a class="nav-link" href="{{ url_for('logout') }}">退出 ({{ session.username }})</a></li>
        {% else %}
          <li class="nav-item"><a class="nav-link" href="{{ url_for('login') }}">登录</a></li>
          <li class="nav-item"><a class="nav-link" href="{{ url_for('register') }}">注册</a></li>
        {% endif %}
        <li class="nav-item"><a class="nav-link" href="{{ url_for('search_creator') }}">创作者搜索</a></li>
      </ul>
    </div>
  </div>
</nav>

<div class="container">
  {% with messages = get_flashed_messages() %}
    {% if messages %}
      <div class="alert alert-info">
        {% for msg in messages %}{{ msg }}{% endfor %}
      </div>
    {% endif %}
  {% endwith %}
  {% block content %}{% endblock %}
</div>
</body>
</html>
"""

REGISTER_TEMPLATE = """
{% extends base %}
{% block title %}注册{% endblock %}
{% block content %}
<h2 class="mb-4">注册</h2>
<form method="post" class="col-md-6">
  <div class="mb-3"><input class="form-control" name="username" placeholder="用户名" required></div>
  <div class="mb-3"><input type="password" class="form-control" name="password" placeholder="密码" required></div>
  <button type="submit" class="btn btn-primary">注册</button>
</form>
{% endblock %}
"""

LOGIN_TEMPLATE = """
{% extends base %}
{% block title %}登录{% endblock %}
{% block content %}
<h2 class="mb-4">登录</h2>
<form method="post" class="col-md-6">
  <div class="mb-3"><input class="form-control" name="username" placeholder="用户名" required></div>
  <div class="mb-3"><input type="password" class="form-control" name="password" placeholder="密码" required></div>
  <button type="submit" class="btn btn-primary">登录</button>
</form>
{% endblock %}
"""

UPLOAD_TEMPLATE = """
{% extends base %}
{% block title %}上传视频{% endblock %}
{% block content %}
<h2 class="mb-4">上传视频</h2>
<form method="post" enctype="multipart/form-data" class="col-md-8">
  <div class="mb-3"><input class="form-control" name="title" placeholder="标题" required></div>
  <div class="mb-3"><textarea class="form-control" name="description" placeholder="描述（可选）"></textarea></div>
  <div class="mb-3"><input type="file" class="form-control" name="file" accept="video/*" required></div>
  <div class="form-check mb-3"><input class="form-check-input" type="checkbox" id="is_public" name="is_public" checked><label class="form-check-label" for="is_public">公开显示此视频</label></div>
  <button type="submit" class="btn btn-success">上传</button>
</form>
{% endblock %}
"""

INDEX_TEMPLATE = """
{% extends base %}
{% block title %}首页{% endblock %}
{% block content %}
<h2 class="mb-3">视频列表</h2>
<form method="get" class="row g-2 mb-4">
  <div class="col-auto"><input class="form-control" name="q" placeholder="搜索标题（LCS 排序）" value="{{ query }}"></div>
  <div class="col-auto"><button class="btn btn-outline-primary" type="submit">搜索</button></div>
</form>

{% if videos %}
  <div class="row">
    {% for v in videos %}
      <div class="col-md-4 mb-4">
        <div class="card h-100">
          <video class="card-img-top" controls>
            <source src="{{ url_for('uploaded_file', filename=v.filename) }}">
            您的浏览器不支持视频播放。
          </video>
          <div class="card-body">
            <h5 class="card-title">{{ v.title }}</h5>
            <p class="card-text">{{ v.description or '' }}</p>
            <p class="card-text"><small class="text-muted">创作者：{{ v.username }}</small></p>
          </div>
        </div>
      </div>
    {% endfor %}
  </div>
{% else %}
  <p>暂无视频。</p>
{% endif %}
{% endblock %}
"""

MANAGE_TEMPLATE = """
{% extends base %}
{% block title %}个人管理{% endblock %}
{% block content %}
<h2 class="mb-4">个人管理 — {{ user.username }}</h2>

<h4>我的视频</h4>
{% if videos %}
  <table class="table">
    <thead><tr><th>预览</th><th>标题</th><th>状态</th><th>操作</th></tr></thead>
    <tbody>
    {% for v in videos %}
      <tr>
        <td style="width:160px;">
          <video width="150" controls>
            <source src="{{ url_for('uploaded_file', filename=v.filename) }}">
          </video>
        </td>
        <td>{{ v.title }}</td>
        <td>{{ '公开' if v.is_public else '隐藏' }}</td>
        <td>
          <form method="post" action="{{ url_for('toggle_visibility', video_id=v.id) }}">
            <button class="btn btn-sm btn-outline-primary" type="submit">{{ '隐藏' if v.is_public else '公开' }}</button>
          </form>
        </td>
      </tr>
    {% endfor %}
    </tbody>
  </table>
{% else %}
  <p>您还没有上传视频。</p>
{% endif %}
{% endblock %}
"""

SEARCH_CREATOR_TEMPLATE = """
{% extends base %}
{% block title %}创作者搜索{% endblock %}
{% block content %}
<h2 class="mb-4">创作者搜索</h2>
<form method="get" class="row g-2 mb-4">
  <div class="col-auto"><input class="form-control" name="q" placeholder="用户名模糊匹配" value="{{ query }}"></div>
  <div class="col-auto"><button class="btn btn-outline-primary" type="submit">搜索</button></div>
</form>

{% if creators %}
  <ul class="list-group">
    {% for c in creators %}
      <li class="list-group-item d-flex justify-content-between align-items-center">
        {{ c.username }}
        <a class="btn btn-sm btn-secondary" href="{{ url_for('creator_videos', username=c.username) }}">查看作品</a>
      </li>
    {% endfor %}
  </ul>
{% else %}
  <p>未找到创作者。</p>
{% endif %}
{% endblock %}
"""

CREATOR_VIDEOS_TEMPLATE = """
{% extends base %}
{% block title %}{{ username }} 的作品{% endblock %}
{% block content %}
<h2 class="mb-3">{{ username }} 的作品</h2>
{% if videos %}
  <div class="row">
    {% for v in videos %}
      <div class="col-md-4 mb-4">
        <div class="card h-100">
          <video class="card-img-top" controls>
            <source src="{{ url_for('uploaded_file', filename=v.filename) }}">
            您的浏览器不支持视频播放。
          </video>
          <div class="card-body">
            <h5 class="card-title">{{ v.title }}</h5>
            <p class="card-text">{{ v.description or '' }}</p>
          </div>
        </div>
      </div>
    {% endfor %}
  </div>
{% else %}
  <p>该创作者暂无作品。</p>
{% endif %}
{% endblock %}
"""
# 路由
@app.route("/")
def index():
    query = request.args.get("q", "").strip()
    cur = g.db.execute("""
        SELECT videos.*, users.username FROM videos
        JOIN users ON videos.uploader_id = users.id
        WHERE videos.is_public = 1
    """)
    videos = cur.fetchall()
    videos_list = [dict(v) for v in videos]
    if query:
        videos_list = sort_videos_by_lcs(videos_list, query)
    return render_template_string(INDEX_TEMPLATE, base=BASE_TEMPLATE, videos=videos_list, query=query)
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            flash("用户名和密码不能为空。")
            return redirect(url_for("register"))
        cur = g.db.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cur.fetchone():
            flash("用户名已存在。")
            return redirect(url_for("register"))
        pw_hash = sha256_hash(password)
        g.db.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, pw_hash))
        g.db.commit()
        flash("注册成功，请登录。")
        return redirect(url_for("login"))
    return render_template_string(REGISTER_TEMPLATE, base=BASE_TEMPLATE)
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        cur = g.db.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cur.fetchone()
        if not user or user["password_hash"] != sha256_hash(password):
            flash("用户名或密码错误。")
            return redirect(url_for("login"))
        session["username"] = user["username"]
        flash("登录成功。")
        return redirect(url_for("index"))
    return render_template_string(LOGIN_TEMPLATE, base=BASE_TEMPLATE)
@app.route("/logout")
def logout():
    session.pop("username", None)
    flash("已退出登录。")
    return redirect(url_for("index"))
@app.route("/upload", methods=["GET", "POST"])
def upload():
    user = current_user()
    if not user:
        flash("请先登录。")
        return redirect(url_for("login"))
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        file = request.files.get("file")
        is_public = 1 if request.form.get("is_public") else 0
        if not title or not file:
            flash("标题和文件为必填项。")
            return redirect(url_for("upload"))
        filename = secure_filename(file.filename)
        if not filename or not allowed_file(filename):
            flash("不支持的文件类型。")
            return redirect(url_for("upload"))
        base, ext = os.path.splitext(filename)
        counter = 0
        final_name = filename
        while os.path.exists(os.path.join(app.config["UPLOAD_FOLDER"], final_name)):
            counter += 1
            final_name = f"{base}_{counter}{ext}"
        save_path = os.path.join(app.config["UPLOAD_FOLDER"], final_name)
        file.save(save_path)
        g.db.execute(
            "INSERT INTO videos (title, description, filename, uploader_id, is_public) VALUES (?, ?, ?, ?, ?)",
            (title, description, final_name, user["id"], is_public)
        )
        g.db.commit()
        flash("上传成功。")
        return redirect(url_for("index"))
    return render_template_string(UPLOAD_TEMPLATE, base=BASE_TEMPLATE)
@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename, as_attachment=False)
@app.route("/search_creator")
def search_creator():
    query = request.args.get("q", "").strip()
    if query:
        like = f"%{query}%"
        cur = g.db.execute("SELECT id, username FROM users WHERE username LIKE ? ORDER BY username", (like,))
    else:
        cur = g.db.execute("SELECT id, username FROM users ORDER BY username")
    creators = cur.fetchall()
    return render_template_string(SEARCH_CREATOR_TEMPLATE, base=BASE_TEMPLATE, creators=creators, query=query)
@app.route("/creator/<username>")
def creator_videos(username):
    cur = g.db.execute("SELECT id FROM users WHERE username = ?", (username,))
    user = cur.fetchone()
    if not user:
        flash("未找到该创作者。")
        return redirect(url_for("search_creator"))
    cur2 = g.db.execute("SELECT * FROM videos WHERE uploader_id = ? AND is_public = 1 ORDER BY id DESC", (user["id"],))
    videos = cur2.fetchall()
    return render_template_string(CREATOR_VIDEOS_TEMPLATE, base=BASE_TEMPLATE, videos=videos, username=username)
@app.route("/manage")
def manage():
    user = current_user()
    if not user:
        flash("请先登录。")
        return redirect(url_for("login"))
    cur = g.db.execute("SELECT * FROM videos WHERE uploader_id = ? ORDER BY id DESC", (user["id"],))
    videos = cur.fetchall()
    return render_template_string(MANAGE_TEMPLATE, base=BASE_TEMPLATE, videos=videos, user=user)
@app.route("/toggle_visibility/<int:video_id>", methods=["POST"])
def toggle_visibility(video_id):
    user = current_user()
    if not user:
        flash("请先登录。")
        return redirect(url_for("login"))
    cur = g.db.execute("SELECT * FROM videos WHERE id = ? AND uploader_id = ?", (video_id, user["id"]))
    v = cur.fetchone()
    if not v:
        flash("未找到视频或无权限。")
        return redirect(url_for("manage"))
    new_state = 0 if v["is_public"] else 1
    g.db.execute("UPDATE videos SET is_public = ? WHERE id = ?", (new_state, video_id))
    g.db.commit()
    flash("已更新视频显示状态。")
    return redirect(url_for("manage"))
# 启动
if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="127.0.0.1", port=5000)
