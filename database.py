import sqlite3

# Connect to SQLite database (or create it if it doesn't exist)
conn = sqlite3.connect("password_manager.db")

# Create a cursor object
cursor = conn.cursor()

# Create a table to store encrypted passwords
cursor.execute('''
CREATE TABLE IF NOT EXISTS passwords (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    website TEXT NOT NULL,
    username TEXT NOT NULL,
    password TEXT NOT NULL
)
''')

# Commit changes and close the connection
conn.commit()
conn.close()

print("Database setup complete.")
