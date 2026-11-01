import express from "express";
import mongoose from "mongoose";
import session from "express-session";
import cors from "cors";
import Hello from "./Hello.js";
import Lab5 from "./Lab5/index.js";
import db from "./Kambaz/Database/index.js";
import UserRoutes from "./Kambaz/Users/routes.js";
import CourseRoutes from "./Kambaz/Courses/routes.js";
import ModulesRoutes from "./Kambaz/Modules/routes.js";
import AssignmentsRoutes from "./Kambaz/Assignments/routes.js";
import EnrollmentsRoutes from "./Kambaz/Enrollments/routes.js";

// Treat any "$..." key that arrives inside a query filter as a plain value, so a request
// body like {"password": {"$ne": null}} can never turn into a MongoDB operator.
mongoose.set("sanitizeFilter", true);

// Builds the Express app without connecting to MongoDB or listening, so tests can use it.
export default function createApp() {
  const sessionSecret = process.env.SESSION_SECRET;
  if (!sessionSecret) {
    throw new Error("SESSION_SECRET is not set. Generate one with: openssl rand -hex 32");
  }
  const isDevelopment = process.env.SERVER_ENV === "development";

  const app = express();

  // CLIENT_URL can list several origins separated by commas (e.g. production and a preview URL).
  const allowedOrigins = (process.env.CLIENT_URL || "http://localhost:3000")
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean);
  app.use(cors({ credentials: true, origin: allowedOrigins }));

  const sessionOptions = {
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true, // page scripts can't read the session cookie
      sameSite: "lax",
      secure: false, // plain http on localhost
      maxAge: 1000 * 60 * 60 * 24 * 7, // one week
    },
  };
  if (!isDevelopment) {
    // Render terminates HTTPS in front of the app, so trust its proxy for secure cookies
    // and for the client IP the rate limiter uses.
    app.set("trust proxy", 1);
    sessionOptions.proxy = true;
    sessionOptions.cookie = {
      ...sessionOptions.cookie,
      sameSite: "none", // the Vercel frontend is on a different site
      secure: true, // only sent over HTTPS
    };
  }

  app.disable("x-powered-by");
  app.use(session(sessionOptions));
  app.use(express.json({ limit: "100kb" }));

  Lab5(app);
  Hello(app);
  UserRoutes(app);
  CourseRoutes(app);
  ModulesRoutes(app);
  AssignmentsRoutes(app);
  EnrollmentsRoutes(app, db);

  // Last: unexpected errors get a generic message, never a stack trace.
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    console.error(err);
    res.status(err.status || 500).json({ message: err.expose ? err.message : "Something went wrong" });
  });

  return app;
}
