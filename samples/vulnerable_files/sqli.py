# Intentionally vulnerable Python file for testing SQL Injection
import sqlite3


def get_user_profile(request):
    # Retrieve user input from the request object
    user_id = request.GET.get("id")

    # Vulnerable: direct f-string interpolation of user input into a SQL query
    query = "SELECT * FROM users WHERE id = ?"

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # Vulnerable execute sink
    cursor.execute(query, (user_id,))
    return cursor.fetchone()
