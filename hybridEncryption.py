def hybrid_encrypt(message, rsa_public_key):
    # Generate a random AES key
    aes_key = generate_aes_key()
    
    # Encrypt the message with AES
    aes_encrypted = aes_encrypt(message, aes_key)
    
    # Encrypt the AES key with RSA
    encrypted_aes_key = rsa_encrypt(aes_key.hex(), rsa_public_key)
    
    return encrypted_aes_key, aes_encrypted

def hybrid_decrypt(encrypted_aes_key, aes_encrypted, rsa_private_key):
    # Decrypt the AES key with RSA
    aes_key = bytes.fromhex(rsa_decrypt(encrypted_aes_key, rsa_private_key))
    
    # Decrypt the message with AES
    decrypted_message = aes_decrypt(aes_encrypted, aes_key)
    
    return decrypted_message

# Example usage
private_key, public_key = generate_rsa_keys()
message = "Hello, hybrid encryption!"

encrypted_key, encrypted_message = hybrid_encrypt(message, public_key)
decrypted_message = hybrid_decrypt(encrypted_key, encrypted_message, private_key)

print(f"Original message: {message}")
print(f"Encrypted AES key: {encrypted_key}")
print(f"Encrypted message: {encrypted_message}")
print(f"Decrypted message: {decrypted_message}")
