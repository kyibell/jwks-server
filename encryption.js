import crypto, { createCipheriv, createDecipheriv, randomBytes } from "crypto";
import dotenv from "dotenv";


dotenv.config(); // Configuration for Our Secrets

const KEY = Buffer.from(process.env.NOT_MY_KEY,'hex'); // get the env variable for the key

const algorithm = 'aes-256-cbc' //  Store the Algo for Encryption

let text = 'my key that I need to encrypt'

export function encrypt(key) {
    const iv = randomBytes(16); // Random bytes for the IV we're using to encrypt

    const cipher = createCipheriv(algorithm, KEY, iv); // Create the Cipher
    let encrypted = cipher.update(key, 'utf-8', 'hex'); 
    encrypted += cipher.final('hex');

    const result = iv.toString('hex') + ':' + encrypted; // Attach the IV to the Key
    return result;

}

export function decrypt(encryptedKey) {
    const [ ivHex, encryptdata ] = encryptedKey.split(':'); // Get the IV from the encrypted data
    const iv = Buffer.from(ivHex, 'hex'); // Convert the IV back to Buffer

    const decipher = createDecipheriv(algorithm, KEY, iv); // Create the Decipher 

    let decrypted = decipher.update(encryptdata, 'hex', 'utf-8'); //  Decrypt the Data
    decrypted += decipher.final('utf8');
    return decrypted;
}

