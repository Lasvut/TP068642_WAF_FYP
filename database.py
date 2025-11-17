import sqlite3
import datetime
from werkzeug.security import generate_password_hash
from flask import request

DB = "app_data.db"

def get_connection():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    c = conn.cursor()
    # users table
    c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        is_admin INTEGER DEFAULT 0,
        created_at TEXT NOT NULL
    )
    ''')
    # logs table for blocked requests
    c.execute('''
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        time TEXT,
        ip TEXT,
        type TEXT,
        payload TEXT,
        path TEXT,
        user_agent TEXT
    )
    ''')
    conn.commit()
    conn.close()

def log_attack(ip, attack_type, payload, path='', user_agent=''):
    conn = get_connection()
    c = conn.cursor()
    c.execute("INSERT INTO logs (time, ip, type, payload, path, user_agent) VALUES (?, ?, ?, ?, ?, ?)",
              (str(datetime.datetime.utcnow()), ip, attack_type, payload, path, user_agent))
    conn.commit()
    conn.close()

def get_client_ip(flask_request):
    # Try to get real IP if behind proxy (for dev this will usually be 127.0.0.1)
    if flask_request.headers.get('X-Forwarded-For'):
        return flask_request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return flask_request.remote_addr or '0.0.0.0'

def create_user(username, password_plain, is_admin=False):
    conn = get_connection()
    c = conn.cursor()
    pw_hash = generate_password_hash(password_plain)
    c.execute("INSERT INTO users (username, password_hash, is_admin, created_at) VALUES (?, ?, ?, ?)",
              (username, pw_hash, 1 if is_admin else 0, str(datetime.datetime.utcnow())))
    conn.commit()
    conn.close()

def get_user_by_username(username):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT id, username, password_hash, is_admin FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()
    if row:
        return (row['id'], row['username'], row['password_hash'], row['is_admin'])
    return None

def get_attack_stats():
    '''Get statistics about blocked attacks'''
    conn = get_connection()
    c = conn.cursor()
    
    # Total attacks
    c.execute("SELECT COUNT(*) as total FROM logs")
    total = c.fetchone()['total']
    
    # Attacks by type
    c.execute("SELECT type, COUNT(*) as count FROM logs GROUP BY type ORDER BY count DESC")
    by_type = [dict(row) for row in c.fetchall()]
    
    # Top attacking IPs
    c.execute("SELECT ip, COUNT(*) as count FROM logs GROUP BY ip ORDER BY count DESC LIMIT 10")
    top_ips = [dict(row) for row in c.fetchall()]
    
    # Attacks in last 24 hours
    c.execute("""
        SELECT COUNT(*) as count FROM logs 
        WHERE datetime(time) > datetime('now', '-1 day')
    """)
    last_24h = c.fetchone()['count']
    
    # Attacks by hour (last 24 hours)
    c.execute("""
        SELECT strftime('%Y-%m-%d %H:00:00', time) as hour, COUNT(*) as count 
        FROM logs 
        WHERE datetime(time) > datetime('now', '-1 day')
        GROUP BY hour 
        ORDER BY hour
    """)
    by_hour = [dict(row) for row in c.fetchall()]
    
    conn.close()
    
    return {
        'total': total,
        'by_type': by_type,
        'top_ips': top_ips,
        'last_24h': last_24h,
        'by_hour': by_hour
    }

def get_recent_logs(limit=50, offset=0, attack_type=None):
    '''Get recent attack logs'''
    conn = get_connection()
    c = conn.cursor()
    
    if attack_type:
        c.execute("""
            SELECT * FROM logs 
            WHERE type = ?
            ORDER BY id DESC 
            LIMIT ? OFFSET ?
        """, (attack_type, limit, offset))
    else:
        c.execute("SELECT * FROM logs ORDER BY id DESC LIMIT ? OFFSET ?", (limit, offset))
    
    rows = c.fetchall()
    conn.close()
    return rows

def get_logs_by_date_range(start_date, end_date):
    '''Get logs within a date range'''
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        SELECT * FROM logs 
        WHERE datetime(time) BETWEEN datetime(?) AND datetime(?)
        ORDER BY id DESC
    """, (start_date, end_date))
    rows = c.fetchall()
    conn.close()
    return rows
