import { generateKeyPairSync } from "crypto";
import express from "express";


const app = express(); // Init app
const port = 8080; // Variable for Port

let keyIdCounter = 1; // For Kids when generating tokens so it's unique everytime

function generateRSAKeyPair() { // Function to generate the RSA Key Pair
    const { publicKey, privateKey } = generateKeyPairSync('rsa', {
        modulusLength: 2048, // n parameter, determines how secure it is, typically 2048 bits
        publicKeyEncoding: {
            type: 'spki', //  Subject public key information (the type of key)
            format: 'pem'
        },
        privateKeyEncoding: {
            type: 'pkcs8', // Private key encoding
            format: 'pem'
        }
    });
    const kid = keyIdCounter++; // Increment counter for unique kids
    const expiresIn = Math.floor(Date.now() / 1000) + 30 * 60; // 30 mins 

    return { // Return a key object
        kty: 'rsa',
        kid: kid.toString(),
        n: publicKey,
        e: 'AQAB',
        exp: expiresIn
    }
}

// isExpired functions so we only serve not expired keys
function isExpired(ExpirationTime) {
    const currentTime = Date.now() / 1000; 
    
    return currentTime > ExpirationTime; // Returns true if key is expired, else false if not
}

const server = app.listen(port, () => { // server start
    console.log(`App is listening and running on local host on port ${port}`); // Message if successful
});


server.on('error', (error) => { // Error handling
    console.log('Error starting server', error);
});

