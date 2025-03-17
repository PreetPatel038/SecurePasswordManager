import sqlite3
from encryption import encrypt, decrypt

# Connect to SQLite database
conn = sqlite3.connect("password_manager.db")
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

conn.commit()


def add_password(website, username, plain_password):
    """Encrypts and stores a new password."""
    encrypted_password = encrypt(plain_password)  # Encrypt password before storing
    cursor.execute("INSERT INTO passwords (website, username, password) VALUES (?, ?, ?)", 
                   (website, username, encrypted_password))
    conn.commit()
    print("Password stored successfully!")


def get_password(website):
    """Retrieves and decrypts the password for a given website."""
    cursor.execute("SELECT username, password FROM passwords WHERE website=?", (website,))
    result = cursor.fetchone()

    if result:
        username, encrypted_password = result
        decrypted_password = decrypt(encrypted_password)  # Decrypt password
        return f"Username: {username}, Password: {decrypted_password}"
    else:
        return "No password found for this website."


# Testing
if __name__ == "__main__":
    add_password("example.com", "testuser", "MySecurePassword123")
    print(get_password("example.com"))

# Close the database connection
conn.close()
