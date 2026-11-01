import mongoose from "mongoose";
import model from "./model.js";
import { v4 as uuidv4 } from "uuid";

// Escape regex special characters so a search string is matched literally
// (no injected patterns, no catastrophic backtracking).
const literal = (text) => new RegExp(text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i");

// sanitizeFilter is on (see app.js), so operators we add on purpose must be marked trusted.
const nameMatches = (regex) => ({
  $or: [
    { firstName: mongoose.trusted({ $regex: regex }) },
    { lastName: mongoose.trusted({ $regex: regex }) },
  ],
});

export default function UsersDao() {
  const createUser = (user) => {
    const newUser = { ...user, _id: uuidv4() };
    return model.create(newUser);
  };
  
  const findAllUsers = () => model.find();
  
  const findUserById = (userId) => model.findById(userId);
  
  const findUserByUsername = (username) => 
    model.findOne({ username: username });
  
  // The only query that returns the password hash, for checking it at sign-in.
  const findUserWithPassword = (username) =>
    model.findOne({ username: username }).select("+password");
  
  const findUsersByRole = (role) => model.find({ role: role });
  
  const findUsersByPartialName = (partialName) => {
    const trimmed = partialName.trim();
    
    // If single word, search firstName OR lastName
    if (!trimmed.includes(' ')) {
      return model.find(nameMatches(literal(trimmed)));
    }
    
    // If multiple words, search firstName AND lastName
    const words = trimmed.split(/\s+/);
    return model.find({
      $and: [nameMatches(literal(words[0])), nameMatches(literal(words[words.length - 1]))],
    });
  };
  
  const updateUser = (userId, user) => 
    model.updateOne({ _id: userId }, { $set: user });
  
  const deleteUser = (userId) => model.findByIdAndDelete(userId);
  
  return { 
    createUser, 
    findAllUsers, 
    findUserById, 
    findUserByUsername, 
    findUserWithPassword,
    findUsersByRole,
    findUsersByPartialName,
    updateUser, 
    deleteUser 
  };
}
