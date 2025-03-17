from Crypto.Cipher import AES
import base64
import os

# Generate a secure random key (32 bytes for AES-256)
SECRET_KEY = b"thisisaverysecurekey1234567890!!"  # 32 bytes


def pad(text):
    """Pads text to be a multiple of 16 bytes (AES block size)"""
    return text + (16 - len(text) % 16) * chr(16 - len(text) % 16)

def unpad(text):
    """Removes padding from decrypted text."""
    return text[:-ord(text[-1:])]


def encrypt(plain_text):
    """Encrypts a plaintext password using AES encryption"""
    iv = os.urandom(16)  # Initialization vector
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
    encrypted_bytes = cipher.encrypt(pad(plain_text).encode('utf-8'))
    return base64.b64encode(iv + encrypted_bytes).decode('utf-8')

def decrypt(encrypted_text):
    """Decrypts an encrypted password"""
    encrypted_bytes = base64.b64decode(encrypted_text)
    iv = encrypted_bytes[:16]  # Extract IV
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)  # Create cipher object
    decrypted_bytes = cipher.decrypt(encrypted_bytes[16:])
    decrypted_text = unpad(decrypted_bytes.decode('utf-8'))
    return decrypted_text


# Test the encryption and decryption
if __name__ == "__main__":
    sample_password = "MySecurePassword123"
    encrypted = encrypt(sample_password)
    decrypted = decrypt(encrypted)

    print(f"Original: {sample_password}")
    print(f"Encrypted: {encrypted}")
    print(f"Decrypted: {decrypted}")
