import { getActiveKey, getExpiredKey } from "./server.js";

describe("Get Key helper functions", () => {
  test("getActiveKey() returns an active non-expired key", () => {
    const key = getActiveKey();
    expect(key).toHaveProperty("kid");
    expect(key).toHaveProperty("exp");
    expect(typeof key.exp).toBe("number");
    expect(key.exp).toBeGreaterThan(Date.now() / 1000);
  });
  test("getExpiredKey() returns an expired key", () => {
    const key = getExpiredKey();
    expect(key).toHaveProperty("kid");
    expect(key).toHaveProperty("exp");
    expect(typeof key.exp).toBe("number");
    expect(key.exp).toBeLessThan(Date.now() / 1000);
  });
});
