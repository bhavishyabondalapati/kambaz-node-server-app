import bcrypt from "bcryptjs";
import { rateLimit } from "express-rate-limit";

const BCRYPT_ROUNDS = 12;

export const hashPassword = (password) => bcrypt.hash(password, BCRYPT_ROUNDS);

// Hashes from bcrypt start with $2a$, $2b$ or $2y$. Anything else is a legacy plain-text password.
export const isHashed = (stored) => typeof stored === "string" && /^\$2[aby]\$/.test(stored);

export const currentUserOf = (req) => req.session["currentUser"];

export const isAdmin = (user) => user?.role === "ADMIN";

// 401 when nobody is signed in. A user whose password must be reset may only reach the
// routes that let them set a new one (see allowDuringReset).
export const requireLogin = (allowDuringReset = false) => (req, res, next) => {
  const user = currentUserOf(req);
  if (!user) {
    res.status(401).json({ message: "Sign in first" });
    return;
  }
  if (user.mustResetPassword && !allowDuringReset) {
    res.status(403).json({ message: "Set a new password on your profile first" });
    return;
  }
  next();
};

export const requireAdmin = (req, res, next) => {
  if (!isAdmin(currentUserOf(req))) {
    res.status(403).json({ message: "Admins only" });
    return;
  }
  next();
};

// Course content (modules, assignments) is edited by faculty in the UI; admins may too.
export const requireRole = (...roles) => (req, res, next) => {
  if (!roles.includes(currentUserOf(req)?.role)) {
    res.status(403).json({ message: `Only ${roles.join(" or ").toLowerCase()} can do this` });
    return;
  }
  next();
};

export const requireFacultyOrAdmin = requireRole("FACULTY", "ADMIN");

// Users may change or delete only their own account; admins may change anyone's.
export const requireSelfOrAdmin = (req, res, next) => {
  const user = currentUserOf(req);
  if (user._id !== req.params.userId && !isAdmin(user)) {
    res.status(403).json({ message: "You can only change your own account" });
    return;
  }
  next();
};

// Sign-in and sign-up: 10 attempts per IP per 15 minutes, to slow down password guessing.
export const authRateLimit = () =>
  rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: Number(process.env.AUTH_RATE_LIMIT) || 10,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    message: { message: "Too many attempts. Try again in 15 minutes." },
  });
