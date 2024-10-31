def vigenere_cipher(message, key, mode):
    # Helper function to repeat the key until it matches the length of the message
    def repeat_key(message, key):
        return (key * (len(message) // len(key) + 1))[:len(message)]

    # Normalize message and key to uppercase
    message = message.upper()
    key = repeat_key(message, key.upper())

    result = []

    for i in range(len(message)):
        if mode == 'encrypt':
            # Encryption: (message[i] + key[i]) % 26
            shift = (ord(message[i]) - ord('A') + ord(key[i]) - ord('A')) % 26
            result.append(chr(shift + ord('A')))
        elif mode == 'decrypt':
            # Decryption: (message[i] - key[i] + 26) % 26
            shift = (ord(message[i]) - ord('A') - (ord(key[i]) - ord('A')) + 26) % 26
            result.append(chr(shift + ord('A')))
    
    return ''.join(result)

# Example usage:
plaintext = 'SECURITY'
keyword = 'KEY'
ciphertext = vigenere_cipher(plaintext, keyword, 'encrypt')
print('Ciphertext of', plaintext, 'is:', ciphertext)

decrypted_text = vigenere_cipher(ciphertext, keyword, 'decrypt')
print('Decrypted text of', ciphertext, 'is:', decrypted_text)