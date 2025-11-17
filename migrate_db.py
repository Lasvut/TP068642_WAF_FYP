"""
Database Migration Script
Adds is_admin column to users table and creates an admin user
"""

import sqlite3
from werkzeug.security import generate_password_hash
import datetime
from database import init_db

DB = "app_data.db"

def migrate():
    print("Starting database migration...")

    # Initialize database first
    print("Initializing database...")
    init_db()
    print("✓ Database initialized")

    conn = sqlite3.connect(DB)
    cursor = conn.cursor()

    # Check if is_admin column already exists
    cursor.execute("PRAGMA table_info(users)")
    columns = [column[1] for column in cursor.fetchall()]

    if 'is_admin' not in columns:
        print("Adding 'is_admin' column to users table...")
        cursor.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0")
        conn.commit()
        print("✓ Column added successfully")
    else:
        print("✓ 'is_admin' column already exists")

    # Create admin user if it doesn't exist
    cursor.execute("SELECT * FROM users WHERE username = 'admin'")
    admin_user = cursor.fetchone()

    if not admin_user:
        print("\nCreating default admin user...")
        username = "admin"
        password = "admin123"  # Default password - CHANGE THIS!
        pw_hash = generate_password_hash(password)
        cursor.execute(
            "INSERT INTO users (username, password_hash, is_admin, created_at) VALUES (?, ?, ?, ?)",
            (username, pw_hash, 1, str(datetime.datetime.utcnow()))
        )
        conn.commit()
        print(f"✓ Admin user created successfully")
        print(f"  Username: {username}")
        print(f"  Password: {password}")
        print(f"\n⚠️  IMPORTANT: Please change the admin password after first login!")
    else:
        print("✓ Admin user already exists")

        # Update existing admin user to have admin privileges
        cursor.execute("UPDATE users SET is_admin = 1 WHERE username = 'admin'")
        conn.commit()
        print("✓ Updated admin user privileges")

    conn.close()
    print("\n✅ Migration completed successfully!")
    print("\nYou can now:")
    print("1. Run the Flask app: python app.py")
    print("2. Login with admin credentials")
    print("3. Access Admin Tools from the dashboard")

if __name__ == "__main__":
    migrate()
