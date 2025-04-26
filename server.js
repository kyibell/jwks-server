import { generateKeyPairSync } from "crypto";
import crypto from "crypto";
import express from "express";
import jwt from "jsonwebtoken";
import db from "./db.js";
import { encrypt, decrypt } from "./encryption.js"
import { v4 as uuidv4 } from 'uuid';
import * as argon2 from "argon2";

const app = express(); // Init app
const port = 8080; // Variable for Port
app.use(express.json()); // for parsing json bodies
app.enable('trust proxy');

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

  const encrypedPrivateKey = encrypt(privateKey); // Encrypt the Private Key
  const expiresIn = Math.floor(Date.now() / 1000) + 60 * 60; // 60 mins

  const sql = `INSERT INTO keys(key, exp) VALUES(?,?)`;

  db.run(sql, [encrypedPrivateKey, expiresIn], function (error) {
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

  const encryptedPrivateKey = encrypt(privateKey); // Encrypt the Private Key

  const expiresIn = Math.floor(Date.now() / 1000) - 30 * 60; // -30 mins
  const sql = `INSERT INTO keys(key, exp) VALUES (?,?)`;

  db.run(sql, [encryptedPrivateKey, expiresIn], function (error) {
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

export async function getUserId(username) {
  return new Promise ((resolve, reject) => {
    db.get(`SELECT id FROM users WHERE username = ?`, [username], (error, row) => {
      if (error) { 
        reject(error) 
        return; 
      }
      if (!row) {
        resolve(null);
      } else {
        resolve(row.id)
      }
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
      const privateKey = decrypt(row.key); // Return the Decryped Key
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

  const IP = req.ip; // Get the IP from the request
  const username  = req.body.username; // Get the Username from the body
  const user_id = await getUserId(username); // Use helper function to get the user_id from username
  const request_timestamp = new Date() 
  const isoString = request_timestamp.toISOString(); // Create the request Timestamp

  if (!user_id) {
    return res.status(404).json({"message": 'User not found'});
  }

  const sql = `INSERT INTO auth_logs(request_ip, user_id, request_timestamp) VALUES (?, ?, ?)`


  db.run(sql, [IP, user_id, isoString], function(error) {
     if (error) {
     console.error(error.message);
  }
  });

  let expired = req.query.expired === "true"; // If the expired query is there set to true

  const key = expired ? await getExpiredKey() : await getActiveKey(); // determines what key should be fetched for JWT

  if (!key) {
    return res.status(404).json({ message: "Key not Found." });
  }
  const privateKey = decrypt(key.key); // Variable to store the private key (decrypted)
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

  

  return res.status(200).json({
    expiry: payload.exp,
    token: signedJWT,
  });
});

app.post("/register", async (req, res) => {
  const { username, email } = req.body;
  
  // const registerDate = Date.now(); // Set the Date to now for registration

  const password = uuidv4();
  const hash = await argon2.hash(password); // Hash the password
  const lastLogin = new Date()
  const isoString = lastLogin.toISOString();
  const sql = `INSERT INTO users(username, email, password_hash, last_login) VALUES (?, ?, ?, ?)`

  db.serialize(() => {
    db.run(sql, [username, email, hash, isoString], function(error) {
      if (error) {
        console.log(error.message);
        return;
      }
    });
  })
 
  return res.status(201).json({"password": password })
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
