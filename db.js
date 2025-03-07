import sqlite from "node:sqlite";
import { DatabaseSync } from "node:sqlite";

export const db = new DatabaseSync(":memory:");

// Create keys table
db.exec(`
    CREATE TABLE keys(
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL
    )
    `);

// Insertion into the Database

function insertKey(kid, key, exp) {
  const insert = db.prepare("INSERT INTO keys (kid, key, exp) VALUES (?,?,?)");
  insert.run(kid, key, exp);
}

function GetActiveKeys() {
  const query = db.prepare("SELECT * FROM keys WHERE exp > CURRENT_TIMESTAMP");
  return query;
}
