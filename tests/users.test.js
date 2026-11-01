// Security tests for the user routes. They need a local MongoDB (the same one `npm start` uses)
// and work in a separate database, kambaz_test, that is dropped afterwards.
// Run with: npm test
import { after, before, beforeEach, describe, it } from "node:test";
import assert from "node:assert/strict";
import mongoose from "mongoose";
import request from "supertest";

process.env.SESSION_SECRET = "test-secret-only-for-tests";
process.env.SERVER_ENV = "development";
process.env.AUTH_RATE_LIMIT = "1000"; // the rate limit has its own test below

const { default: createApp } = await import("../app.js");
const { default: model } = await import("../Kambaz/Users/model.js");
const { hashPassword } = await import("../Kambaz/auth.js");
const { migratePasswords } = await import("../scripts/migrate-passwords.js");

const TEST_DB = process.env.MONGO_TEST_URL || "mongodb://127.0.0.1:27017/kambaz_test";

const seed = async () => {
  await model.deleteMany({});
  await model.create([
    { _id: "admin", username: "ada", password: await hashPassword("admin-pass-1"), role: "ADMIN" },
    { _id: "alice", username: "alice", password: await hashPassword("alice-pass-1"), role: "STUDENT" },
    { _id: "bob", username: "bob", password: await hashPassword("bob-pass-12"), role: "STUDENT" },
  ]);
};

const signedIn = async (app, username, password) => {
  const agent = request.agent(app);
  const res = await agent.post("/api/users/signin").send({ username, password });
  assert.equal(res.status, 200, `sign-in as ${username} failed`);
  return agent;
};

describe("user routes", () => {
  let app;

  before(async () => {
    await mongoose.connect(TEST_DB);
    app = createApp();
  });
  beforeEach(seed);
  after(async () => {
    await mongoose.connection.dropDatabase();
    await mongoose.disconnect();
  });

  describe("operator injection", () => {
    it("rejects a sign-in with {$ne: null} as the password", async () => {
      const res = await request(app).post("/api/users/signin").send({ username: "ada", password: { $ne: null } });
      assert.equal(res.status, 401);
    });

    it("rejects a sign-in with operators in both fields", async () => {
      const res = await request(app)
        .post("/api/users/signin")
        .send({ username: { $gt: "" }, password: { $gt: "" } });
      assert.equal(res.status, 401);
    });

    it("sanitizeFilter neutralizes operators that reach a query", async () => {
      // {$ne: null} becomes the literal value {$eq: {$ne: null}}, which isn't a valid username.
      await assert.rejects(model.findOne({ username: { $ne: null } }), { name: "CastError" });
    });

    it("treats a name search as literal text", async () => {
      const agent = await signedIn(app, "alice", "alice-pass-1");
      const res = await agent.get("/api/users").query({ name: ".*" });
      assert.equal(res.status, 200);
      assert.deepEqual(res.body, []);
    });
  });

  describe("authentication and authorization", () => {
    it("requires a login for every user route", async () => {
      const anon = request(app);
      for (const [method, path] of [
        ["get", "/api/users"],
        ["get", "/api/users/alice"],
        ["post", "/api/users"],
        ["put", "/api/users/alice"],
        ["delete", "/api/users/alice"],
        ["post", "/api/users/profile"],
        ["get", "/api/courses/RS101/users"],
      ]) {
        const res = await anon[method](path).send({});
        assert.equal(res.status, 401, `${method.toUpperCase()} ${path}`);
      }
    });

    it("stops a user from editing or deleting someone else", async () => {
      const alice = await signedIn(app, "alice", "alice-pass-1");
      assert.equal((await alice.put("/api/users/bob").send({ firstName: "Hacked" })).status, 403);
      assert.equal((await alice.delete("/api/users/bob")).status, 403);
      assert.ok(await model.findById("bob"));
    });

    it("stops a user from making themselves an admin", async () => {
      const alice = await signedIn(app, "alice", "alice-pass-1");
      const res = await alice.put("/api/users/alice").send({ firstName: "Alice", role: "ADMIN" });
      assert.equal(res.status, 200);
      assert.equal((await model.findById("alice")).role, "STUDENT");
    });

    it("lets an admin edit and delete other users", async () => {
      const admin = await signedIn(app, "ada", "admin-pass-1");
      assert.equal((await admin.put("/api/users/bob").send({ role: "FACULTY" })).status, 200);
      assert.equal((await model.findById("bob")).role, "FACULTY");
      assert.equal((await admin.delete("/api/users/bob")).status, 200);
      assert.equal(await model.findById("bob"), null);
    });

    it("only admins can create users", async () => {
      const alice = await signedIn(app, "alice", "alice-pass-1");
      const body = { username: "mallory", password: "mallory-pass" };
      assert.equal((await alice.post("/api/users").send(body)).status, 403);
    });

    it("never returns password hashes", async () => {
      const admin = await signedIn(app, "ada", "admin-pass-1");
      const list = await admin.get("/api/users");
      assert.ok(list.body.length >= 3);
      assert.ok(list.body.every((u) => u.password === undefined));
      assert.equal((await admin.get("/api/users/alice")).body.password, undefined);
    });

    it("ignores a role sent at sign-up", async () => {
      const res = await request(app)
        .post("/api/users/signup")
        .send({ username: "eve", password: "eve-password", role: "ADMIN" });
      assert.equal(res.status, 200);
      assert.notEqual((await model.findOne({ username: "eve" })).role, "ADMIN");
    });
  });

  describe("passwords", () => {
    it("stores new passwords as bcrypt hashes", async () => {
      await request(app).post("/api/users/signup").send({ username: "carol", password: "carol-password" });
      const stored = await model.findOne({ username: "carol" }).select("+password");
      assert.match(stored.password, /^\$2[aby]\$/);
    });

    it("upgrades a legacy plain-text password and forces a reset", async () => {
      await model.collection.insertOne({ _id: "legacy", username: "legacy", password: "old-plain-text", role: "STUDENT" });
      const agent = request.agent(app);
      const res = await agent.post("/api/users/signin").send({ username: "legacy", password: "old-plain-text" });
      assert.equal(res.status, 200);
      assert.equal(res.body.mustResetPassword, true);
      assert.match((await model.findById("legacy").select("+password")).password, /^\$2[aby]\$/);

      // Until a new password is set, only the profile routes work.
      assert.equal((await agent.get("/api/users")).status, 403);
      assert.equal((await agent.put("/api/users/legacy").send({ password: "brand-new-pass" })).status, 200);
      assert.equal((await agent.get("/api/users")).status, 200);
    });

    it("migration script hashes plain-text passwords in bulk", async () => {
      await model.collection.insertOne({ _id: "old", username: "old", password: "plain", role: "STUDENT" });
      const { migrated } = await migratePasswords();
      assert.equal(migrated, 1);
      const old = await model.findById("old").select("+password");
      assert.match(old.password, /^\$2[aby]\$/);
      assert.equal(old.mustResetPassword, true);
    });
  });

  describe("rate limiting", () => {
    it("blocks repeated sign-in attempts from one IP", async () => {
      process.env.AUTH_RATE_LIMIT = "3";
      const limited = createApp();
      process.env.AUTH_RATE_LIMIT = "1000";
      const statuses = [];
      for (let i = 0; i < 4; i++) {
        statuses.push((await request(limited).post("/api/users/signin").send({ username: "ada", password: "wrong" })).status);
      }
      assert.deepEqual(statuses, [401, 401, 401, 429]);
    });
  });

  describe("startup", () => {
    it("refuses to build the app without SESSION_SECRET", () => {
      const saved = process.env.SESSION_SECRET;
      delete process.env.SESSION_SECRET;
      assert.throws(() => createApp(), /SESSION_SECRET/);
      process.env.SESSION_SECRET = saved;
    });
  });
});
