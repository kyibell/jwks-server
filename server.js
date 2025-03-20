import { generateKeyPairSync } from "crypto";
import express from "express";
import jwt from "jsonwebtoken";
import db from "./db.js";
import exp from "constants";
const forgeModule = await import("node-forge");
const forge = forgeModule.default; // Fixes ES6 Import Issue

const app = express(); // Init app
const port = 8080; // Variable for Port

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
  const expiresIn = Math.floor(Date.now() / 1000) + 60 * 60; // 60 mins

  const sql = `INSERT INTO keys(key, exp) VALUES(?,?)`;

  db.run(sql, [privateKey, expiresIn], function (error) {
    if (error) {
      console.error(error.message);
      return;
    }
  }); // Insertion Query for inserting keys in the DB.
}

function generateExpiredKey() {
  // Function to generate the Expired RSA Key Pair
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

  const expiresIn = Math.floor(Date.now() / 1000) - 30 * 60; // -30 mins
  const sql = `INSERT INTO keys(key, exp) VALUES (?,?)`;

  db.run(sql, [privateKey, expiresIn], function (error) {
    if (error) {
      console.error(error.message);
    }
  });
}

export function getActiveKey() {
  const activeKey = keys.find((key) => Date.now() < key.exp * 1000); // Finds a key in keys array that is not expired
  return activeKey; // return the Active key
}

export function getExpiredKey() {
  const expiredKey = keys.find((key) => Date.now() > key.exp * 1000); // Checks if the key in keys array is expired
  return expiredKey; // returns the expired key
}

app.get("/.well-known/jwks.json", (req, res) => {
  // JWKS Endpoint that only Serves Valid Keys
  const validKeys = keys.filter((key) => Date.now() < key.exp * 1000); //filters the key based on if the exp value returns false
  const jwksKeys = validKeys.map((key) => ({
    // Map the keys in JWKS format
    kid: key.kid,
    kty: "RSA",
    use: "sig",
    n: key.n,
    e: key.e,
  }));

  return res.status(200).json({ keys: jwksKeys }); // return the valid keys
});

app.post("/auth", (req, res) => {
  let expired = req.query.expired === "true"; // If the expired query is there set to true

  const key = expired ? getExpiredKey() : getActiveKey(); // determines what key should be fetched for JWT

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

  return res.json({
    expiry: payload.exp,
    token: signedJWT,
  });
});

app.all("/auth", (req, res) => {
  // Checking for valid methods
  if (req.method != "POST") {
    return res.status(405).send("Method not Allowed");
  }
});

app.all("/.well-known/jwks.json", (req, res) => {
  // Checking for valid methods
  if (req.method != "GET") {
    return res.status(405).send("Method not Allowed");
  }
});

//generateRSAKeyPair();
generateExpiredKey();

const server = app.listen(port, () => {
  // server start
  console.log(`App is listening and running on local host on port ${port}`); // Message if successful
});

server.on("error", (error) => {
  // Error handling
  console.log("Error starting server", error);
});
