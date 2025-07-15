const mongoose = require("mongoose");

const refreshTokenSchema = new mongoose.Schema(
  {
    token: String,
    userEmail: String,
    expiresAt: Date,
  },
  { timestamps: true }
);

module.exports = mongoose.model("refresh_tokens", refreshTokenSchema);
