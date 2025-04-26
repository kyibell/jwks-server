import sqlite3 from "sqlite3";
sqlite3.verbose();

const db = new sqlite3.Database("./totally_not_my_privateKeys.db", (err) => {
  // Connect to the database
  if (err) {
    console.error("Error opening the database.", err.message); // send a message if there's an error connecting
  } else {
    console.log("Database Connected");
  }
});

db.serialize(() => {
  // Create the keys table
  db.run(`CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
    )`);

  // Create Users Table
  db.run(`CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    email TEXT UNIQUE,
    date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP
    )`);

  // Create Auth_Logs Table
  db.run(`CREATE TABLE IF NOT EXISTS auth_logs(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_ip TEXT NOT NULL,
    request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_id INTEGER,
    FOREIGN KEY(user_id) REFERENCES users(id)
    )`);
});

export default db; // For the server.js file so we can run queries.
