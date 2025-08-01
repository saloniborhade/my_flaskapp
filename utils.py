# utils.py

import sqlite3

DB_NAME = 'db.sqlite'

def get_db_connection():
    """Creates and returns a connection to the SQLite database."""
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row  # Access columns by name
    return conn

def init_db():
    """Initializes the database using the schema.sql file."""
    try:
        with open('schema.sql', 'r') as f:
            schema_sql = f.read()
        
        conn = get_db_connection()
        conn.executescript(schema_sql)
        conn.commit()
        conn.close()
        print("✅ Database initialized successfully.")
    except Exception as e:
        print(f"❌ Failed to initialize database: {e}")

# Run this only when executing this file directly
if __name__ == '__main__':
    init_db()
