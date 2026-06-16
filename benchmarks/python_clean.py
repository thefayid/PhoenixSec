import os
import shlex
import sqlite3


def query_user(user_id):
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchall()


def ping_host(host):
    os.system("ping -c 3 " + shlex.quote(host))
