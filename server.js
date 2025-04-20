import { generateKeyPairSync } from "crypto";
import crypto from "crypto";
import express from "express";
import jwt from "jsonwebtoken";
import db from "./db.js";
const forgeModule = await import("node-forge");
const forge = forgeModule.default; // Fixes ES6 Import Issue

const app = express(); // Init app
const port = 8080; // Variable for Port

function generateRSAKeyPair() {
  // Function to generate the RSA Key Pair
  const { privateKey } = generateKeyPairSync("rsa", {
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
  const { privateKey } = generateKeyPairSync("rsa", {
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
    // Run the db query to insert private key and expiration parameters
    if (error) {
      // display error if error
      console.error(error.message);
    }
  });
}

export async function getActiveKey() {
  const sql = `SELECT * FROM keys WHERE exp > ?`;
  const currentTime = Date.now() / 1000;
  return new Promise((resolve, reject) => {
    db.get(sql, [currentTime], (error, row) => {
      if (error) {
        reject(error);
        return;
      }
      resolve(row);
    });
  });
}

export async function getExpiredKey() {
  const sql = `SELECT * FROM keys WHERE exp < ?`;
  const currentTime = Date.now() / 1000;
  return new Promise((resolve, reject) => {
    db.get(sql, [currentTime], (error, row) => {
      if (error) {
        reject(error);
        return;
      }
      resolve(row);
    });
  });
}

app.get("/.well-known/jwks.json", (req, res) => {
  // JWKS Endpoint that only Serves Valid Keys
  const sql = `SELECT * FROM keys WHERE exp > ?`;
  const currentTime = Date.now() / 1000;
  db.all(sql, [currentTime], (error, rows) => {
    if (error) {
      console.error(error.message);
    }
    const jwks = rows.map((row) => {
      const privateKey = row.key;
      const publicKey = crypto.createPublicKey(privateKey);
      const jwk = publicKey.export({ format: "jwk" }); // Extract modulus and Exponent from the public key

      return {
        kid: row.kid.toString(),
        kty: "RSA",
        use: "sig",
        n: jwk.n,
        e: jwk.e,
      };
    });

    return res.status(200).json({ keys: jwks }); // return the valid keys
  });
});

app.post("/auth", async (req, res) => {
  let expired = req.query.expired === "true"; // If the expired query is there set to true

  const key = expired ? await getExpiredKey() : await getActiveKey(); // determines what key should be fetched for JWT

  if (!key) {
    return res.status(404).json({ message: "Key not Found." });
  }
  const privateKey = key.key; // Variable to store the private key
  const publicKeyObject = crypto.createPublicKey({
    key: privateKey,
    format: "pem",
  });
  const publicKey = publicKeyObject.export({ format: "pem", type: "spki" });
  const { n, e } = publicKeyObject.export({ format: "jwk" });
  const jwk = {
    kid: key.kid.toString(),
    privateKey,
    publicKey,
    kty: "RSA",
    use: "sig",
    n: n,
    e: e,
  };

  const payload = {
    exp: expired
      ? Math.floor(Date.now() / 1000) - 60
      : Math.floor(Date.now() / 1000) + 60 * 5,
    iat: Date.now() / 1000,
    jti: jwk.kid,
  };

  const signedJWT = jwt.sign(payload, jwk.privateKey, {
    algorithm: "RS256",
    header: {
      alg: "RS256",
      typ: "JWT",
      kid: jwk.kid,
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

export default app; // For Testing
