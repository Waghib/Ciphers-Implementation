import binascii
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def aes_encrypt(plaintext, key):
    key = key[:16]  # Ensure the key is 16 bytes
    iv = get_random_bytes(16)
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)
    ciphertext = iv + cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
    return ciphertext

def aes_decrypt(ciphertext, key):
    key = key[:16]  # Ensure the key is 16 bytes
    iv = ciphertext[:16]
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext[16:]), AES.block_size)
    return plaintext.decode('utf-8')

# Example usage:
plaintext = "My name is Waghib"
key = "thisisasecretkey1"  # 16 bytes for AES-128

# Encrypt the plaintext
ciphertext = aes_encrypt(plaintext, key)
print("Ciphertext (hex):", binascii.hexlify(ciphertext))

# Decrypt the ciphertext
decrypted_text = aes_decrypt(ciphertext, key)
print("Decrypted text:", decrypted_text)