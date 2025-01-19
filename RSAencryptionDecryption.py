from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii

def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def rsa_encrypt(message, public_key):
    key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(key)
    encrypted = cipher.encrypt(message.encode('utf-8'))
    return binascii.hexlify(encrypted).decode('ascii')

def rsa_decrypt(ciphertext, private_key):
    key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(key)
    decrypted = cipher.decrypt(binascii.unhexlify(ciphertext))
    return decrypted.decode('utf-8')

# Example usage
private_key, public_key = generate_rsa_keys()
message = "Hello, RSA encryption!"
encrypted = rsa_encrypt(message, public_key)
decrypted = rsa_decrypt(encrypted, private_key)

print(f"Original message: {message}")
print(f"Encrypted message: {encrypted}")
print(f"Decrypted message: {decrypted}")
