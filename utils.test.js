// TESTS
import jest from 'jest';
import request from 'supertest';
import jwt from 'jsonwebtoken';
import app from './server.js'
import db from './db.js'
import { getExpiredKey, getActiveKey } from './server.js';
import { promisify } from 'util'

// Server Tests
describe('Server Tests', () => {
  let server;

  beforeAll((done) => {
    
    server = app.listen(0, () => { // 0 tells it to use a random free port
      done();
    });
  });

  afterAll((done) => {
    server.close(done); // Close the server after the test
  });


  test('Server should respond without error', async () => {
    const res = await request(server).get('/');
    expect(res.status).toBe(404);
  });


  test('Error handling for server should work', async () => {
    const badPortServer = app.listen(999);
    badPortServer.on('error', (error) => {
      expect(error).toBeTruthy();
    })
    badPortServer.close();
  });
});

// JWT Validication
test('POST /auth should return a valid JWT', async () => {
  const res = await request(app).post('/auth');
  expect(res.status).toBe(200);
  expect(res.body.token).toBeDefined();

  //JWT Verification
  const decoded = jwt.decode(res.body.token, { complete: true });
  expect(decoded).not.toBeNull();
  expect(decoded.header.kid).toBeDefined();
});

// Auth Expired Returns Expired JWT
test('POST /auth?expired=true should return an expired JWT', async () => {
  const res = await request(app).post('/auth?expired=true');
  expect(res.status).toBe(200); 
  expect(res.body.token).toBeDefined();

  // JWT Verification
  const decoded = jwt.decode(res.body.token, { complete: true});
  expect(decoded).not.toBeNull();
  expect(decoded.payload.exp).toBeLessThan(Math.floor(Date.now() / 1000));
});

// JWKS Endpoint Only Returns Valid Keys
test('GET /.well-known/jwks.json should return only valid keys', async () => {
    const res = await request(app).get('/.well-known/jwks.json');
    expect(res.status).toBe(200);
    expect(res.body.keys).toBeInstanceOf(Array);

    res.body.keys.forEach((key)=> {
      expect(key.kid).toBeDefined();
      expect(key.kty).toBe("RSA");
      expect(key.n).toBeDefined();
      expect(key.e).toBeDefined();
    })
});

// POST Auth Endpoint Rejects other methods
test('GET /auth returns Method Not Allowed', async () => {
  const res = await request(app).get('/auth');
  expect(res.status).toBe(405);
});

// GET JWKS rejects other methods
test('POST /.well-known/jwks.json should return only valid keys', async () => {
  const res = await request(app).post('/.well-known/jwks.json');
  expect(res.status).toBe(405);
});

// getActiveKey returns an Active Key from DB

test('getActiveKey() returns an active key from the DB', async () => {
  const row = await getActiveKey();
  expect(row.kid).toBeDefined();
  expect(row.key).toBeDefined();
  expect(row.exp).toBeGreaterThan(Date.now() / 1000);
});

// getExpiredKey returns an Expired Key from DB
test('getActiveKey() returns an active key from the DB', async () => {
  const row = await getExpiredKey();
  expect(row.kid).toBeDefined();
  expect(row.key).toBeDefined();
  expect(row.exp).toBeLessThan(Date.now() / 1000);
});


// No expired keys in the database
test('getExpiredKey should return undefined when there are no expired keys', async () => {
  // Clear all keys from the database to simulate no expired keys
  await promisify(db.run.bind(db))('DELETE FROM keys');

  const key = await getExpiredKey();
  expect(key).toBe(undefined);
});
// Active Key should Return Undefined
test('getActiveKey should return undefined when there are no active keys', async () => {
  // Clear all keys from the database to simulate no expired keys
  await promisify(db.run.bind(db))('DELETE FROM keys');

  const key = await getActiveKey();
  expect(key).toBe(undefined);
});

// If Auth Endpoint Detects no Key, returns 404
test('POST /auth should return 404 if no key is found', async () => {
  // Clear Keys from DB
  await promisify(db.run.bind(db))('DELETE FROM keys');

  const key = await getActiveKey();

  const res = await request(app).post('/auth');
  expect(res.status).toBe(404);
});

// JWKS Endpoint returns [] if no Active Keys
test('GET /.well-known/jwks.json should empty jwks when no active keys are available', async () => {
  await promisify(db.run.bind(db))('DELETE FROM keys');

  const res = await request(app).get('/.well-known/jwks.json');

  expect(res.status).toBe(200);
  expect(res.body.keys).toEqual([]);
 
});
