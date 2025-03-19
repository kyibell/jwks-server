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
    key BLOB NOT NULL
    exp INTEGER NOT NULL
    )`);
});

export default db; // For the server.js file so we can run queries.
