// One-off migration: hash every plain-text password and force those users to pick a new one.
// Usage: DATABASE_CONNECTION_STRING=... node scripts/migrate-passwords.js
// Safe to run more than once: already-hashed passwords are skipped.
// Sign-in also upgrades legacy accounts one at a time, so running this is optional;
// it just stops plain-text passwords from sitting in the database until each user next logs in.
import "dotenv/config";
import mongoose from "mongoose";
import model from "../Kambaz/Users/model.js";
import { hashPassword, isHashed } from "../Kambaz/auth.js";

const CONNECTION_STRING = process.env.DATABASE_CONNECTION_STRING || "mongodb://127.0.0.1:27017/kambaz";

export async function migratePasswords() {
  const users = await model.find().select("+password");
  let migrated = 0;
  for (const user of users) {
    if (isHashed(user.password)) continue;
    await model.updateOne(
      { _id: user._id },
      { $set: { password: await hashPassword(String(user.password ?? "")), mustResetPassword: true } }
    );
    migrated += 1;
  }
  return { total: users.length, migrated };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  await mongoose.connect(CONNECTION_STRING);
  const { total, migrated } = await migratePasswords();
  console.log(`Hashed ${migrated} of ${total} user passwords; those users must set a new password at next sign-in.`);
  await mongoose.disconnect();
}
