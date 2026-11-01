// Write access to course content: modules and assignments. Reads stay open for the course pages;
// creating, updating and deleting need a signed-in FACULTY or ADMIN user.
// Uses its own database (kambaz_test_content) because node --test runs test files in parallel.
import { after, before, beforeEach, describe, it } from "node:test";
import assert from "node:assert/strict";
import mongoose from "mongoose";
import request from "supertest";

process.env.SESSION_SECRET = "test-secret-only-for-tests";
process.env.SERVER_ENV = "development";
process.env.AUTH_RATE_LIMIT = "1000";

const { default: createApp } = await import("../app.js");
const { default: userModel } = await import("../Kambaz/Users/model.js");
const { default: courseModel } = await import("../Kambaz/Courses/model.js");
const { default: assignmentModel } = await import("../Kambaz/Assignments/model.js");
const { hashPassword } = await import("../Kambaz/auth.js");

const TEST_DB = process.env.MONGO_TEST_CONTENT_URL || "mongodb://127.0.0.1:27017/kambaz_test_content";
const COURSE = "RS101";

const seed = async () => {
  await Promise.all([userModel.deleteMany({}), courseModel.deleteMany({}), assignmentModel.deleteMany({})]);
  const password = await hashPassword("password-123");
  await userModel.create([
    { _id: "prof", username: "prof", password, role: "FACULTY" },
    { _id: "admin", username: "admin", password, role: "ADMIN" },
    { _id: "stu", username: "stu", password, role: "STUDENT" },
  ]);
  await courseModel.create({ _id: COURSE, name: "Rocket Propulsion", modules: [{ _id: "m1", name: "Week 1" }] });
  await assignmentModel.create({ _id: "a1", title: "A1", course: COURSE });
};

describe("modules and assignments", () => {
  let app;
  const as = async (username) => {
    const agent = request.agent(app);
    const res = await agent.post("/api/users/signin").send({ username, password: "password-123" });
    assert.equal(res.status, 200);
    return agent;
  };

  // Every write route, with a body that would succeed for an allowed user.
  const writes = [
    ["post", `/api/courses/${COURSE}/modules`, { name: "Week 2" }],
    ["put", `/api/courses/${COURSE}/modules/m1`, { name: "Week 1 (edited)" }],
    ["delete", `/api/courses/${COURSE}/modules/m1`, undefined],
    ["post", `/api/courses/${COURSE}/assignments`, { title: "A2" }],
    ["put", "/api/assignments/a1", { title: "A1 (edited)" }],
    ["delete", "/api/assignments/a1", undefined],
  ];

  before(async () => {
    await mongoose.connect(TEST_DB);
    app = createApp();
  });
  beforeEach(seed);
  after(async () => {
    await mongoose.connection.dropDatabase();
    await mongoose.disconnect();
  });

  it("reads stay open without a login", async () => {
    assert.equal((await request(app).get(`/api/courses/${COURSE}/modules`)).status, 200);
    assert.equal((await request(app).get(`/api/courses/${COURSE}/assignments`)).status, 200);
    assert.equal((await request(app).get("/api/assignments/a1")).status, 200);
  });

  it("every write needs a login", async () => {
    for (const [method, path, body] of writes) {
      const res = await request(app)[method](path).send(body);
      assert.equal(res.status, 401, `${method.toUpperCase()} ${path}`);
    }
  });

  it("students can't create, change or delete content", async () => {
    const stu = await as("stu");
    for (const [method, path, body] of writes) {
      const res = await stu[method](path).send(body);
      assert.equal(res.status, 403, `${method.toUpperCase()} ${path}`);
    }
    // nothing changed
    assert.equal((await courseModel.findById(COURSE)).modules.length, 1);
    assert.equal((await assignmentModel.findById("a1")).title, "A1");
  });

  for (const role of ["prof", "admin"]) {
    it(`${role === "prof" ? "faculty" : "admins"} can create, change and delete content`, async () => {
      const agent = await as(role);
      for (const [method, path, body] of writes) {
        if (method === "delete") continue; // deletes are checked below, after the edits
        const res = await agent[method](path).send(body);
        assert.equal(res.status, 200, `${method.toUpperCase()} ${path}`);
      }
      assert.equal((await assignmentModel.findById("a1")).title, "A1 (edited)");
      assert.equal((await agent.delete(`/api/courses/${COURSE}/modules/m1`)).status, 200);
      assert.equal((await agent.delete("/api/assignments/a1")).status, 200);
      assert.equal(await assignmentModel.findById("a1"), null);
    });
  }
});
