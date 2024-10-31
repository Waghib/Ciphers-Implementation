const crypto = require('crypto');

// AES Encryption Function
function aesEncrypt(plaintext, key) {
    // Ensure key is 16 bytes (128 bits) for AES-128
    const keyBuffer = Buffer.from(key, 'utf-8').slice(0, 16);

    // Generate a random Initialization Vector (IV)
    const iv = crypto.randomBytes(16);

    // Create the AES Cipher in CBC mode
    const cipher = crypto.createCipheriv('aes-128-cbc', keyBuffer, iv);

    // Encrypt and concatenate the ciphertext with IV
    let encrypted = cipher.update(plaintext, 'utf-8', 'hex');
    encrypted += cipher.final('hex');

    // Return IV + encrypted data
    return iv.toString('hex') + encrypted;
}

// AES Decryption Function
function aesDecrypt(ciphertext, key) {
    // Ensure key is 16 bytes
    const keyBuffer = Buffer.from(key, 'utf-8').slice(0, 16);

    // Extract IV from the ciphertext
    const iv = Buffer.from(ciphertext.slice(0, 32), 'hex');
    const actualCiphertext = ciphertext.slice(32);

    // Create the AES Decipher
    const decipher = crypto.createDecipheriv('aes-128-cbc', keyBuffer, iv);

    // Decrypt and return the plaintext
    let decrypted = decipher.update(actualCiphertext, 'hex', 'utf-8');
    decrypted += decipher.final('utf-8');
    return decrypted;
}

// Example usage
const plaintext = "My name is Waghib";
const key = "thisisasecretkey1";  // Must be 16 bytes for AES-128

// Encrypt the plaintext
const ciphertext = aesEncrypt(plaintext, key);
console.log("Ciphertext:", ciphertext);

// Decrypt the ciphertext
const decryptedText = aesDecrypt(ciphertext, key);
console.log("Decrypted text:", decryptedText);
