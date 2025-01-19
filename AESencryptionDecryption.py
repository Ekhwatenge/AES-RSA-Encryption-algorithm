from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

def generate_aes_key():
    return get_random_bytes(16)  # 128-bit key

def aes_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
    return base64.b64encode(cipher.iv + ciphertext).decode('utf-8')

def aes_decrypt(ciphertext, key):
    raw = base64.b64decode(ciphertext.encode('utf-8'))
    iv = raw[:16]
    ciphertext = raw[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode('utf-8')

# Example usage
aes_key = generate_aes_key()
message = "Hello, AES encryption!"
encrypted = aes_encrypt(message, aes_key)
decrypted = aes_decrypt(encrypted, aes_key)

print(f"Original message: {message}")
print(f"Encrypted message: {encrypted}")
print(f"Decrypted message: {decrypted}")
