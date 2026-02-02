# vulnerable_code/app.py
from flask import Flask, request, session
import sqlite3
import os

app = Flask(__name__)
# 漏洞1: 硬编码的密钥 (Hardcoded Secret)
app.secret_key = "super_secret_key_1234"


@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # 漏洞2: SQL注入 (SQL Injection)
    # 程序员直接把用户输入拼接到 SQL 语句中，非常危险！
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"

    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()

    if user:
        return "Logged in!"
    return "Failed"


@app.route('/run_command')
def run_cmd():
    user_input = request.args.get('cmd')
    # 漏洞3: 命令注入 (Command Injection)
    # 允许用户直接在服务器执行系统命令
    os.system("echo " + user_input)
    return "Command executed"