import sqlite3

conn = sqlite3.connect(r'D:\Project\billing_app\db.sqlite')
cursor = conn.cursor()

# Add payment_status column if it doesn't exist
try:
    cursor.execute("ALTER TABLE expense_shares ADD COLUMN payment_status TEXT DEFAULT 'pending'")
    print("Column 'payment_status' added successfully.")
except sqlite3.OperationalError as e:
    print("Maybe column already exists or there is an error:", e)

conn.commit()
conn.close()
