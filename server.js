import { generateKeyPairSync } from "crypto";
import express from "express";
import * as jwt from "jsonwebtoken";

const app = express(); // Init app
const port = 8080; // Variable for Port
let keyIdCounter = 1; // For Kids when generating tokens so it's unique everytime
let keys = []; // Place to store keys

function generateRSAKeyPair() {
  // Function to generate the RSA Key Pair
  const { publicKey, privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048, // n parameter, determines how secure it is, typically 2048 bits
    publicKeyEncoding: {
      type: "spki", //  Subject public key information (the type of key)
      format: "pem",
    },
    privateKeyEncoding: {
      type: "pkcs8", // Private key encoding
      format: "pem",
    },
  });

  const kid = keyIdCounter++; // Increment counter for unique kids
  const expiresIn = Math.floor(Date.now() / 1000) + 30 * 60; // 30 mins

  // Extract public key info
  const publicKeyObject = crypto.createPublicKey(publicKey);
  const { n, e } = crypto
    .createPublicKey(publicKey)
    .export({ type: "pcks1", format: "der" });

  // Convert modulus and exponent to base64
  const base64Modulus = n.toString("base64");
  const base64Exponent = e.toString("base64");

  const newKey = {
    kty: "RSA",
    n: base64Modulus,
    e: base64Exponent,
    alg: "RS256",
    kid: kid.toString(),
    use: "sig",
    exp: expiresIn,
  };

  keys.push(newKey);
  //return newKey;
}

// isExpired functions so we only serve not expired keys
function isExpired(expirationTime) {
  const currentTime = Date.now() / 1000;
  return currentTime > expirationTime; // Returns true if key is expired, else false if not
}

const server = app.listen(port, () => {
  // server start
  console.log(`App is listening and running on local host on port ${port}`); // Message if successful
});

app.get("/jwks", (req, res) => {
  // JWKS Endpoint that only Serves Valid Keys
  const validKeys = keys.filter((key) => !isExpired(key.exp)); //filters the key based on if the exp value returns false
  return res.json({ keys: validKeys }); // return the valid keys
});

app.post("/auth", (req, res) => {
  let expired = req.query;

  if (expired) {
  }
});

server.on("error", (error) => {
  // Error handling
  console.log("Error starting server", error);
});
