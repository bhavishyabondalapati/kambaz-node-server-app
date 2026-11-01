import mongoose from "mongoose";

const userSchema = new mongoose.Schema(
  {
    _id: String,
    username: { type: String, required: true, unique: true },
    // bcrypt hash. select: false keeps it out of every query result unless asked for.
    password: { type: String, required: true, select: false },
    mustResetPassword: { type: Boolean, default: false },
    firstName: String,
    email: String,
    lastName: String,
    dob: Date,
    role: {
      type: String,
      enum: ["STUDENT", "FACULTY", "ADMIN", "USER"],
      default: "USER",
    },
    loginId: String,
    section: String,
    lastActivity: Date,
    totalActivity: String,
  },
  { collection: "users" }
);

export default userSchema;