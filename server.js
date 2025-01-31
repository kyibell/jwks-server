import { generateKeyPairSync } from "crypto";
import express from "express";
import jwt from "jsonwebtoken";
const forgeModule = await import("node-forge");
const forge = forgeModule.default; // Fixes ES6 Import Issue

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

  const forgePublicKey = forge.pki.publicKeyFromPem(publicKey);
  const base64Modulus = Buffer.from(forgePublicKey.n.toByteArray()).toString(
    "base64url"
  );
  const base64Exponent = Buffer.from(forgePublicKey.e.toByteArray()).toString(
    "base64url"
  );

  const newKey = {
    // create a newKey object
    kid: kid.toString(),
    publicKey,
    privateKey,
    use: "sig",
    exp: expiresIn,
    n: base64Modulus,
    e: base64Exponent,
    alg: "RS256",
    kty: "RSA",
  };

  keys.push(newKey); // Add the new Key to the list of keys
  return newKey;
}

function generateExpiredKey() {
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
  const expiresIn = Math.floor(Date.now() / 1000) - 30 * 60; // -30 mins

  const forgePublicKey = forge.pki.publicKeyFromPem(publicKey);
  const base64Modulus = Buffer.from(forgePublicKey.n.toByteArray()).toString(
    "base64url"
  );
  const base64Exponent = Buffer.from(forgePublicKey.e.toByteArray()).toString(
    "base64url"
  );

  const expiredKey = {
    // create a newKey object
    kid: kid.toString(),
    publicKey,
    privateKey,
    use: "sig",
    exp: expiresIn,
    n: base64Modulus,
    e: base64Exponent,
    alg: "RS256",
    kty: "RSA",
  };

  keys.push(expiredKey); // Add the new Key to the list of keys
  return expiredKey;
}

// isExpired function so we only serve not expired keys
function isExpired(key) {
  const currentTime = Date.now() / 1000;
  return currentTime > key.exp; // Returns true if key is expired, else false if not
}

function getActiveKey() {
  const activeKey = keys.find((key) => Date.now() < key.exp * 1000);
  return activeKey;
}

function getExpiredKey() {
  const expiredKey = keys.find((key) => Date.now() > key.exp * 1000);
  return expiredKey;
}

app.get("/.well-known/jwks.json", (req, res) => {
  // JWKS Endpoint that only Serves Valid Keys
  const validKeys = keys.filter((key) => Date.now() < key.exp * 1000); //filters the key based on if the exp value returns false
  const jwksKeys = validKeys.map((key) => ({
    kid: key.kid,
    kty: "RSA",
    use: "sig",
    n: key.n,
    e: key.e,
  }));

  return res.status(200).json({ keys: jwksKeys });
});

app.post("/auth", (req, res) => {
  let expired = req.query.expired === "true";

  const key = expired ? getExpiredKey() : getActiveKey();

  const payload = {
    exp: expired
      ? Math.floor(Date.now() / 1000) - 60
      : Math.floor(Date.now() / 1000) + 60 * 5,
    iat: Date.now() / 1000,
    jti: key.kid,
  };

  const signedJWT = jwt.sign(payload, key.privateKey, {
    algorithm: "RS256",
    header: {
      alg: "RS256",
      typ: "JWT",
      kid: key.kid,
    },
  });

  return res.json({ token: signedJWT });
});

app.all("/auth", (req, res) => {
  // Checking
  return res.status(405).send("Method not Allowed");
});

generateRSAKeyPair();
generateExpiredKey();

const server = app.listen(port, () => {
  // server start
  console.log(`App is listening and running on local host on port ${port}`); // Message if successful
});

server.on("error", (error) => {
  // Error handling
  console.log("Error starting server", error);
});
