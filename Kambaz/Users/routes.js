import { timingSafeEqual } from "node:crypto";
import bcrypt from "bcryptjs";
import UsersDao from "./dao.js";
import db from "../Database/index.js";
import {
  authRateLimit,
  currentUserOf,
  hashPassword,
  isAdmin,
  isHashed,
  requireAdmin,
  requireLogin,
  requireSelfOrAdmin,
} from "../auth.js";

// Fields a user may set on their own account. Role and reset status are only set by an admin or the server.
const PROFILE_FIELDS = ["username", "password", "firstName", "lastName", "email", "dob", "section"];
const ADMIN_FIELDS = [...PROFILE_FIELDS, "role", "loginId"];
const MIN_PASSWORD_LENGTH = 8;

const pick = (body, fields) =>
  Object.fromEntries(fields.filter((f) => body?.[f] !== undefined).map((f) => [f, body[f]]));

// Cast to a string so a JSON object such as {"$ne": null} can't reach a query as an operator.
const toText = (value) => (value === undefined || value === null ? "" : String(value));

// Never send a password (hash or legacy plain text) back to the browser.
const safeUser = (user) => {
  const obj = user.toObject ? user.toObject() : { ...user };
  delete obj.password;
  return obj;
};

const sameText = (a, b) => {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
};

// A fresh session id at sign-in, so a session id planted before login can't be reused.
const startSession = (req, user) =>
  new Promise((resolve, reject) => {
    req.session.regenerate((err) => {
      if (err) return reject(err);
      req.session["currentUser"] = user;
      resolve();
    });
  });

export default function UserRoutes(app) {
  const dao = UsersDao();
  
  const addEnrolledCourses = (user) => {
    const { enrollments } = db;
    const userEnrollments = enrollments
      .filter((e) => e.user === user._id)
      .map((e) => e.course);
    return { ...user, enrolledCourses: userEnrollments };
  };
  
  // Admin only. The new user must choose their own password at first sign-in.
  const createUser = async (req, res) => {
    const fields = pick(req.body, ADMIN_FIELDS);
    const username = toText(fields.username);
    const password = toText(fields.password);
    if (!username || password.length < MIN_PASSWORD_LENGTH) {
      res.status(400).json({ message: `Username and a password of at least ${MIN_PASSWORD_LENGTH} characters are required` });
      return;
    }
    if (await dao.findUserByUsername(username)) {
      res.status(400).json({ message: "Username already taken" });
      return;
    }
    const user = await dao.createUser({
      ...fields,
      username,
      password: await hashPassword(password),
      mustResetPassword: true,
    });
    res.json(safeUser(user));
  };
  
  const deleteUser = async (req, res) => {
    const userId = req.params.userId;
    const status = await dao.deleteUser(userId);
    if (currentUserOf(req)._id === userId) {
      req.session.destroy(() => {});
    }
    res.json(status);
  };
  
  const findAllUsers = async (req, res) => {
    const { role, name } = req.query;
    
    if (role) {
      const users = await dao.findUsersByRole(toText(role));
      res.json(users.map(safeUser));
      return;
    }
    
    if (name) {
      const users = await dao.findUsersByPartialName(toText(name));
      res.json(users.map(safeUser));
      return;
    }
    
    const users = await dao.findAllUsers();
    res.json(users.map(safeUser));
  };
  
  const findUserById = async (req, res) => {
    const user = await dao.findUserById(req.params.userId);
    if (!user) {
      res.status(404).json({ message: "User not found" });
      return;
    }
    res.json(safeUser(user));
  };
  
  const updateUser = async (req, res) => {
    const userId = req.params.userId;
    const currentUser = currentUserOf(req);
    const editingSelf = currentUser._id === userId;
    const userUpdates = pick(req.body, isAdmin(currentUser) ? ADMIN_FIELDS : PROFILE_FIELDS);

    if (userUpdates.password !== undefined) {
      const password = toText(userUpdates.password);
      if (!password) {
        delete userUpdates.password; // an empty password field means "keep the current one"
      } else if (password.length < MIN_PASSWORD_LENGTH) {
        res.status(400).json({ message: `Passwords need at least ${MIN_PASSWORD_LENGTH} characters` });
        return;
      } else {
        userUpdates.password = await hashPassword(password);
        // Setting your own password clears a pending reset; an admin setting someone else's forces one.
        userUpdates.mustResetPassword = !editingSelf;
      }
    }
    await dao.updateUser(userId, userUpdates);
  
    const updatedUser = await dao.findUserById(userId);
    if (!updatedUser) {
      res.status(404).json({ message: "User not found" });
      return;
    }
    const userWithCourses = addEnrolledCourses(safeUser(updatedUser));
  
    // Only update session if user is editing themselves
    if (editingSelf) {
      req.session["currentUser"] = userWithCourses;
    }
  
    res.json(userWithCourses);
  };
  
  const signup = async (req, res) => {
    const username = toText(req.body?.username);
    const password = toText(req.body?.password);
    if (!username || password.length < MIN_PASSWORD_LENGTH) {
      res.status(400).json({ message: `Choose a username and a password of at least ${MIN_PASSWORD_LENGTH} characters` });
      return;
    }
    const user = await dao.findUserByUsername(username);
    if (user) {
      res.status(400).json({ message: "Username already taken" });
      return;
    }
    // role is not accepted from the request, so nobody can sign up as an admin
    const currentUser = await dao.createUser({
      ...pick(req.body, PROFILE_FIELDS),
      username,
      password: await hashPassword(password),
    });
    const userWithCourses = addEnrolledCourses(safeUser(currentUser));
    await startSession(req, userWithCourses);
    res.json(userWithCourses);
  };
  
  const signin = async (req, res) => {
    const username = toText(req.body?.username);
    const password = toText(req.body?.password);
    const user = username && password ? await dao.findUserWithPassword(username) : null;

    let passwordOk = false;
    if (user && isHashed(user.password)) {
      passwordOk = await bcrypt.compare(password, user.password);
    } else if (user) {
      // Account created before passwords were hashed: accept the old password once,
      // hash it, and require the user to choose a new one.
      passwordOk = sameText(password, toText(user.password));
      if (passwordOk) {
        await dao.updateUser(user._id, { password: await hashPassword(password), mustResetPassword: true });
        user.mustResetPassword = true;
      }
    }

    if (!passwordOk) {
      res.status(401).json({ message: "Unable to login. Try again later." });
      return;
    }
    const userWithCourses = addEnrolledCourses(safeUser(user));
    await startSession(req, userWithCourses);
    res.json(userWithCourses);
  };
  
  const signout = (req, res) => {
    req.session.destroy(() => res.sendStatus(200));
  };
  
  const profile = (req, res) => {
    const userWithCourses = addEnrolledCourses(currentUserOf(req));
    res.json(userWithCourses);
  };

  const findUsersForCourse = (req, res) => {
    const { courseId } = req.params;
    const { enrollments, users } = db;
    
    const enrolledUserIds = enrollments
      .filter((e) => e.course === courseId)
      .map((e) => e.user);
    
    const enrolledUsers = users.filter((user) =>
      enrolledUserIds.includes(user._id)
    );
    
    res.json(enrolledUsers.map(safeUser));
  };
  
  const loggedIn = requireLogin();
  const loggedInEvenDuringReset = requireLogin(true);
  const authLimit = authRateLimit();

  app.post("/api/users", loggedIn, requireAdmin, createUser);
  app.get("/api/users", loggedIn, findAllUsers);
  app.get("/api/users/:userId", loggedIn, findUserById);
  app.put("/api/users/:userId", loggedInEvenDuringReset, requireSelfOrAdmin, updateUser);
  app.delete("/api/users/:userId", loggedIn, requireSelfOrAdmin, deleteUser);
  app.post("/api/users/signup", authLimit, signup);
  app.post("/api/users/signin", authLimit, signin);
  app.post("/api/users/signout", signout);
  app.post("/api/users/profile", loggedInEvenDuringReset, profile);
  app.get("/api/courses/:courseId/users", loggedIn, findUsersForCourse);
}
