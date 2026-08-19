#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Google Account Manager — Flask + SQLite."""
import sqlite3, os, io, csv
from datetime import date, datetime
from pathlib import Path
from functools import wraps

from flask import (Flask, g, request, session, redirect, url_for,
                   render_template, flash, send_file, Response, jsonify)

import pyotp
from passlib.hash import bcrypt

# ----- config -----
DATABASE = Path(__file__).parent / "google_accounts.db"
SECRET_KEY = os.environ.get("FLASK_SECRET", "change-me-1234567890")
UPLOAD_DIR = Path(__file__).parent / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

STATUSES = ["new","warmup","active","ready","blocked","suspended","archived"]
STATUS_LABELS = dict(zip(STATUSES, ["Новый","Прогрев","Активный","Готов","Заблокирован","Приостановлен","Архив"]))
STATUS_COLORS = dict(zip(STATUSES, ["#6366f1","#f59e0b","#10b981","#0ea5e9","#ef4444","#8b5cf6","#6b7280"]))

# Дополнительный статус — прогресс обработки аккаунта
STATUSES2 = ["untouched","phone_added","twofa_added"]
STATUS_LABELS2 = {"untouched":"Не тронут","phone_added":"Добавлен номер","twofa_added":"Добавлен 2FA"}
STATUS_COLORS2 = {"untouched":"#64748b","phone_added":"#22d3ee","twofa_added":"#818cf8"}

def parse_status2(val):
    """Разбирает status2 из БД в множество активных значений."""
    if not val:
        return set()
    return {v.strip() for v in val.split(",") if v.strip() in STATUSES2}

def format_status2(vals):
    """Собирает множество значений status2 в строку для хранения."""
    valid = [v for v in vals if v in STATUSES2]
    return ",".join(valid) if valid else "untouched"

PERMS = {"view":"Просмотр","edit":"Редактирование","share":"Передача"}

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

@app.context_processor
def inject_css_version():
    """Версия CSS для сброса кэша браузера при обновлении стилей."""
    import hashlib
    css_path = Path(__file__).parent / "static" / "style.css"
    ver = "0"
    if css_path.exists():
        ver = hashlib.md5(css_path.read_bytes()).hexdigest()[:8]
    return {"css_v": ver}

@app.template_filter("parse_status2")
def parse_status2_filter(val):
    return parse_status2(val)


# ----- DB helpers -----
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(str(DATABASE))
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA foreign_keys=ON")
        # Ленивая инициализация таблиц (на случай, если БД удалили)
        g.db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                is_admin INTEGER DEFAULT 0,
                is_active INTEGER DEFAULT 1,
                created_at TEXT DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                first_name TEXT, second_name TEXT, address TEXT,
                sex TEXT, date_of_birth TEXT, number TEXT,
                mail TEXT NOT NULL, mailPass TEXT, reMail TEXT,
                proxy TEXT, file_path TEXT, auth TEXT,
                status TEXT DEFAULT 'new',
                status2 TEXT DEFAULT 'new',
                notes TEXT,
                owner_id INTEGER REFERENCES users(id),
                created_at TEXT DEFAULT (datetime('now')),
                updated_at TEXT DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS account_access (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account_id INTEGER REFERENCES accounts(id) ON DELETE CASCADE,
                user_id INTEGER REFERENCES users(id),
                permission TEXT DEFAULT 'view',
                granted_by INTEGER,
                granted_at TEXT DEFAULT (datetime('now')),
                UNIQUE(account_id, user_id)
            );
        """)
        # Миграция для существующих БД: добавляем status2, если нет
        cols = [r[1] for r in g.db.execute("PRAGMA table_info(accounts)")]
        if "status2" not in cols:
            g.db.execute("ALTER TABLE accounts ADD COLUMN status2 TEXT DEFAULT 'untouched'")
        # Сбрасываем старые значения status2 (new/warmup/active и т.п.) в "untouched"
        g.db.execute("UPDATE accounts SET status2='untouched' WHERE status2 NOT IN ('untouched','phone_added','twofa_added') AND status2 NOT LIKE '%,%'")
        g.db.commit()
    return g.db

def close_db(e=None):
    db = g.pop("db", None)
    if db: db.close()
app.teardown_appcontext(close_db)


# ----- auth helpers -----
def hash_pass(pw): return bcrypt.hash(pw)
def verify_pass(pw, h): return bcrypt.verify(pw, h)

def login_required(f):
    @wraps(f)
    def wrap(*a, **kw):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*a, **kw)
    return wrap

def admin_required(f):
    @wraps(f)
    def wrap(*a, **kw):
        if not session.get("is_admin"):
            flash("Только администратор", "error")
            return redirect(url_for("index"))
        return f(*a, **kw)
    return wrap


# ----- helpers: доступ -----
def can_view(acc_id):
    """Может ли текущий пользователь просматривать аккаунт?"""
    if session.get("is_admin"): return True
    uid = session["user_id"]
    db = get_db()
    row = db.execute("SELECT owner_id FROM accounts WHERE id=?", (acc_id,)).fetchone()
    if not row: return False
    if row["owner_id"] == uid: return True
    r = db.execute("SELECT id FROM account_access WHERE account_id=? AND user_id=?", (acc_id, uid)).fetchone()
    return r is not None

def has_perm(acc_id, perms_list):
    """Есть ли у текущего пользователя одно из указанных прав на аккаунт?"""
    if session.get("is_admin"): return True
    uid = session["user_id"]
    db = get_db()
    row = db.execute("SELECT owner_id FROM accounts WHERE id=?", (acc_id,)).fetchone()
    if not row: return False
    if row["owner_id"] == uid: return True  # владелец = все права
    r = db.execute("SELECT permission FROM account_access WHERE account_id=? AND user_id=?", (acc_id, uid)).fetchone()
    return r is not None and r["permission"] in perms_list


# ----- routes -----
@app.route("/setup", methods=["GET","POST"])
def setup():
    db = get_db()
    if db.execute("SELECT COUNT(*) FROM users").fetchone()[0] > 0:
        return redirect(url_for("login"))
    if request.method == "POST":
        u = request.form["username"].strip()
        p = request.form["password"]
        p2 = request.form.get("password2")
        if p != p2 or len(p) < 4:
            flash("Пароли не совпадают или слишком короткие", "error")
            return render_template("setup.html")
        db.execute("INSERT INTO users (username,password,is_admin) VALUES(?,?,1)", (u, hash_pass(p)))
        db.commit()
        flash("Администратор создан! Теперь войдите.", "ok")
        return redirect(url_for("login"))
    return render_template("setup.html")


@app.route("/login", methods=["GET","POST"])
def login():
    db = get_db()
    if db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        return redirect(url_for("setup"))
    if request.method == "POST":
        u = request.form["username"].strip()
        p = request.form["password"]
        db = get_db()
        row = db.execute("SELECT * FROM users WHERE username=? AND is_active=1", (u,)).fetchone()
        if row and verify_pass(p, row["password"]):
            session["user_id"] = row["id"]
            session["username"] = row["username"]
            session["is_admin"] = bool(row["is_admin"])
            return redirect(url_for("index"))
        flash("Неверный логин или пароль", "error")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    db = get_db()
    if db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        return redirect(url_for("setup"))
    uid = session["user_id"]
    is_admin = session["is_admin"]

    if is_admin:
        total = db.execute("SELECT COUNT(*) FROM accounts").fetchone()[0]
        by_status = {s: db.execute("SELECT COUNT(*) FROM accounts WHERE status=?", (s,)).fetchone()[0] for s in STATUSES}
        accounts = db.execute("""SELECT a.*, u.username owner_name FROM accounts a
            LEFT JOIN users u ON a.owner_id=u.id ORDER BY a.updated_at DESC""").fetchall()
    else:
        total = db.execute("""SELECT COUNT(*) FROM accounts a
            LEFT JOIN account_access ac ON ac.account_id=a.id AND ac.user_id=?
            WHERE a.owner_id=? OR ac.user_id IS NOT NULL""", (uid, uid)).fetchone()[0]
        by_status = {}
        for s in STATUSES:
            by_status[s] = db.execute("""SELECT COUNT(*) FROM accounts a
                LEFT JOIN account_access ac ON ac.account_id=a.id AND ac.user_id=?
                WHERE (a.owner_id=? OR ac.user_id IS NOT NULL) AND a.status=?""", (uid, uid, s)).fetchone()[0]
        accounts = db.execute("""SELECT a.*, u.username owner_name FROM accounts a
            LEFT JOIN users u ON a.owner_id=u.id
            LEFT JOIN account_access ac ON ac.account_id=a.id AND ac.user_id=?
            WHERE a.owner_id=? OR ac.user_id IS NOT NULL
            ORDER BY a.updated_at DESC""", (uid, uid)).fetchall()

    users = db.execute("SELECT id,username,is_admin,is_active FROM users ORDER BY username").fetchall() if is_admin else []
    return render_template("index.html", total=total, by_status=by_status,
                           accounts=accounts, users=users,
                           STATUSES=STATUSES, STATUS_LABELS=STATUS_LABELS, STATUS_COLORS=STATUS_COLORS, STATUSES2=STATUSES2, STATUS_LABELS2=STATUS_LABELS2, STATUS_COLORS2=STATUS_COLORS2)


@app.route("/accounts/<int:acc_id>")
@login_required
def account_detail(acc_id):
    if not can_view(acc_id):
        flash("Нет доступа", "error"); return redirect(url_for("index"))
    db = get_db()
    acc = db.execute("""SELECT a.*, u.username owner_name FROM accounts a
        LEFT JOIN users u ON a.owner_id=u.id WHERE a.id=?""", (acc_id,)).fetchone()
    if not acc:
        flash("Аккаунт не найден", "error"); return redirect(url_for("index"))

    can_edit = has_perm(acc_id, ["edit","share"])
    can_share = has_perm(acc_id, ["share"])
    accesses = db.execute("""SELECT ac.*, u.username FROM account_access ac
        JOIN users u ON ac.user_id=u.id WHERE ac.account_id=?""", (acc_id,)).fetchall()
    all_users = db.execute("SELECT id,username FROM users WHERE is_active=1 ORDER BY username").fetchall() if can_share else []

    totp_code = ""
    if acc["auth"]:
        try: totp_code = pyotp.TOTP(acc["auth"]).now()
        except: pass

    return render_template("detail.html", acc=acc, can_edit=can_edit, can_share=can_share,
                           accesses=accesses, users=all_users, totp_code=totp_code,
                           STATUSES=STATUSES, STATUS_LABELS=STATUS_LABELS, STATUS_COLORS=STATUS_COLORS, STATUSES2=STATUSES2, STATUS_LABELS2=STATUS_LABELS2, STATUS_COLORS2=STATUS_COLORS2, PERMS=PERMS)


@app.route("/accounts/new", methods=["GET","POST"])
@login_required
def account_new():
    """Создание аккаунта доступно всем авторизованным пользователям."""
    if request.method == "POST":
        db = get_db()
        f = request.form
        dob = f.get("date_of_birth") or None
        # файл
        fp = None
        file = request.files.get("file")
        if file and file.filename:
            safe = f"{int(datetime.utcnow().timestamp())}_{file.filename}"
            file.save(str(UPLOAD_DIR / safe))
            fp = str(UPLOAD_DIR / safe)
        st = f.get("status", "new")
        if st not in STATUSES: st = "new"
        st2_list = f.getlist("status2")
        st2 = format_status2(st2_list)
        cur = db.execute("""INSERT INTO accounts (first_name,second_name,address,sex,date_of_birth,
            number,mail,mailPass,reMail,proxy,file_path,auth,status,status2,notes,owner_id)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (f.get("first_name"), f.get("second_name"), f.get("address"), f.get("sex"), dob,
             f.get("number"), f.get("mail"), f.get("mailPass"), f.get("reMail"), f.get("proxy"),
             fp, f.get("auth") or None, st, st2, f.get("notes"), session["user_id"]))
        db.commit()
        return redirect(url_for("account_detail", acc_id=cur.lastrowid))
    return render_template("form.html", account=None, STATUSES=STATUSES, STATUS_LABELS=STATUS_LABELS, STATUSES2=STATUSES2, STATUS_LABELS2=STATUS_LABELS2, STATUS_COLORS2=STATUS_COLORS2)


@app.route("/accounts/<int:acc_id>/edit", methods=["GET","POST"])
@login_required
def account_edit(acc_id):
    if not has_perm(acc_id, ["edit","share"]):
        flash("Нет прав на редактирование", "error"); return redirect(url_for("index"))
    db = get_db()
    acc = db.execute("SELECT * FROM accounts WHERE id=?", (acc_id,)).fetchone()
    if not acc: flash("Не найден","error"); return redirect(url_for("index"))
    if request.method == "POST":
        f = request.form
        dob = f.get("date_of_birth") or None
        fp = acc["file_path"]
        file = request.files.get("file")
        if file and file.filename:
            safe = f"{int(datetime.utcnow().timestamp())}_{file.filename}"
            file.save(str(UPLOAD_DIR / safe))
            fp = str(UPLOAD_DIR / safe)
        st = f.get("status", acc["status"])
        if st not in STATUSES: st = acc["status"]
        st2_list = f.getlist("status2")
        if st2_list:
            st2 = format_status2(st2_list)
        else:
            st2 = acc["status2"] or "untouched"
        db.execute("""UPDATE accounts SET first_name=?,second_name=?,address=?,sex=?,date_of_birth=?,
            number=?,mail=?,mailPass=?,reMail=?,proxy=?,file_path=?,auth=?,status=?,status2=?,notes=?,updated_at=datetime('now')
            WHERE id=?""",
            (f.get("first_name"), f.get("second_name"), f.get("address"), f.get("sex"), dob,
             f.get("number"), f.get("mail"), f.get("mailPass"), f.get("reMail"), f.get("proxy"),
             fp, f.get("auth") or None, st, st2, f.get("notes"), acc_id))
        db.commit()
        return redirect(url_for("account_detail", acc_id=acc_id))
    return render_template("form.html", account=acc, STATUSES=STATUSES, STATUS_LABELS=STATUS_LABELS, STATUSES2=STATUSES2, STATUS_LABELS2=STATUS_LABELS2, STATUS_COLORS2=STATUS_COLORS2)


@app.route("/accounts/<int:acc_id>/status", methods=["POST"])
@login_required
def account_status(acc_id):
    if not has_perm(acc_id, ["edit","share"]):
        return ("", 403)
    db = get_db()
    st = request.form.get("status","")
    st2_list = request.form.getlist("status2")
    updates, params = [], []
    if st in STATUSES:
        updates.append("status=?")
        params.append(st)
    st2 = format_status2(st2_list)
    updates.append("status2=?")
    params.append(st2)
    if updates:
        updates.append("updated_at=datetime('now')")
        params.append(acc_id)
        db.execute(f"UPDATE accounts SET {', '.join(updates)} WHERE id=?", params)
        db.commit()
    return redirect(url_for("account_detail", acc_id=acc_id))


@app.route("/accounts/<int:acc_id>/delete", methods=["POST"])
@login_required
@admin_required
def account_delete(acc_id):
    db = get_db()
    db.execute("DELETE FROM accounts WHERE id=?", (acc_id,))
    db.commit()
    return redirect(url_for("index"))


@app.route("/accounts/<int:acc_id>/totp")
@login_required
def account_totp(acc_id):
    if not can_view(acc_id):
        return jsonify(code="")
    db = get_db()
    row = db.execute("SELECT auth FROM accounts WHERE id=?", (acc_id,)).fetchone()
    code = ""
    if row and row["auth"]:
        try: code = pyotp.TOTP(row["auth"]).now()
        except: pass
    return jsonify(code=code)


@app.route("/accounts/<int:acc_id>/share", methods=["POST"])
@login_required
def account_share(acc_id):
    if not has_perm(acc_id, ["share"]):
        flash("Нет прав на выдачу доступа","error"); return redirect(url_for("account_detail", acc_id=acc_id))
    db = get_db()
    acc = db.execute("SELECT owner_id FROM accounts WHERE id=?", (acc_id,)).fetchone()
    if not acc: return ("", 404)
    tuid = int(request.form["user_id"])
    perm = request.form.get("permission","view")
    if perm not in PERMS: perm = "view"
    if tuid == acc["owner_id"]:
        flash("Это владелец","error"); return redirect(url_for("account_detail", acc_id=acc_id))
    db.execute("INSERT OR REPLACE INTO account_access (account_id,user_id,permission,granted_by) VALUES(?,?,?,?)",
               (acc_id, tuid, perm, session["user_id"]))
    db.commit()
    return redirect(url_for("account_detail", acc_id=acc_id))


@app.route("/accounts/<int:acc_id>/share/<int:aid>/revoke", methods=["POST"])
@login_required
def account_revoke(acc_id, aid):
    if not has_perm(acc_id, ["share"]):
        return ("", 403)
    db = get_db()
    db.execute("DELETE FROM account_access WHERE id=? AND account_id=?", (aid, acc_id))
    db.commit()
    return redirect(url_for("account_detail", acc_id=acc_id))


@app.route("/accounts/<int:acc_id>/file")
@login_required
def account_file(acc_id):
    if not can_view(acc_id):
        return ("", 403)
    db = get_db()
    row = db.execute("SELECT file_path FROM accounts WHERE id=?", (acc_id,)).fetchone()
    if not row or not row["file_path"] or not os.path.exists(row["file_path"]):
        return ("", 404)
    return send_file(row["file_path"], as_attachment=True)


# ---- admin ----
@app.route("/admin/users", methods=["GET","POST"])
@login_required
@admin_required
def users():
    db = get_db()
    if request.method == "POST":
        u = request.form["username"].strip()
        p = request.form["password"]
        if len(p) < 4: flash("Пароль слишком короткий","error"); return redirect(url_for("users"))
        if db.execute("SELECT id FROM users WHERE username=?", (u,)).fetchone():
            flash("Логин занят","error"); return redirect(url_for("users"))
        is_adm = 1 if request.form.get("is_admin") else 0
        db.execute("INSERT INTO users (username,password,is_admin) VALUES(?,?,?)", (u, hash_pass(p), is_adm))
        db.commit()
        return redirect(url_for("users"))
    users = db.execute("SELECT id,username,is_admin,is_active FROM users ORDER BY id").fetchall()
    return render_template("users.html", users=users)


@app.route("/admin/users/<int:uid>/toggle", methods=["POST"])
@login_required
@admin_required
def user_toggle(uid):
    if uid == session["user_id"]: return ("", 400)
    db = get_db()
    u = db.execute("SELECT is_active FROM users WHERE id=?", (uid,)).fetchone()
    if u:
        db.execute("UPDATE users SET is_active=? WHERE id=?", (0 if u["is_active"] else 1, uid))
        db.commit()
    return redirect(url_for("users"))


@app.route("/accounts/export.csv")
@login_required
@admin_required
def export_csv():
    db = get_db()
    rows = db.execute("SELECT * FROM accounts ORDER BY id").fetchall()
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["id","first_name","second_name","address","sex","date_of_birth","number",
                 "mail","mailPass","reMail","proxy","auth","status","status2","owner_id","created_at"])
    for r in rows:
        w.writerow([r["id"],r["first_name"],r["second_name"],r["address"],r["sex"],
                     r["date_of_birth"],r["number"],r["mail"],r["mailPass"],r["reMail"],
                     r["proxy"],r["auth"],r["status"],r["status2"],r["owner_id"],r["created_at"]])
    out.seek(0)
    return Response(out.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition":"attachment; filename=accounts.csv"})


# ---- serve ----
if __name__ == "__main__":
    print("http://localhost:8000")
    app.run(host="0.0.0.0", port=8000, debug=True)