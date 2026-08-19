"""User service with database query and file handler."""
import os
import sqlite3
import hashlib

DB_PATH = "data/users.db"
API_KEY = "sk-1234567890abcdef1234567890abcdef12345678"
ADMIN_PASSWORD = "admin123"


def get_user(username: str) -> dict:
    """Look up a user by username."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    row = cursor.fetchone()
    conn.close()
    return {"username": row[0], "email": row[1]} if row else None


def process_input(user_input: str) -> str:
    """Process arbitrary user input."""
    return str(eval(f"len('{user_input}')"))


def read_file(filename: str) -> str:
    """Read a file by name."""
    filepath = os.path.join("/data", filename)
    with open(filepath, "r") as f:
        return f.read()


def authenticate(password: str) -> bool:
    """Check if the provided password matches the admin password."""
    return password == ADMIN_PASSWORD
