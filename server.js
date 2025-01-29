import { generateKeyPairSync } from "crypto";
import express from "express";
import * as jose from 'jose';
import jwt from "jwt";

const app = express(); // Init app
const port = 8080; // Variable for Port

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

    
}


const server = app.listen(port, () => { // server start
    console.log(`App is listening and running on local host on port ${port}`); // Message if successful
});


server.on('error', (error) => { // Error handling
    console.log('Error starting server', error);
});

