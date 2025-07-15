const authenticateToken = require("../middlewares/auth");
const RefreshToken = require("../models/refreshTokens");
const jwt = require("jsonwebtoken");
const express = require("express");
const router = express.Router();

const JWT_PRIVATE_KEY = process.env.JWT_PRIVATE_KEY;
const JWT_REFRESH_KEY = process.env.JWT_REFRESH_KEY;

router.post("/refresh-token", async (req, res, next) => {
  // Vérifier le cookie refresh token
  const token = req.cookies.refresh_token;
  if (!token) return next(Object.assign(new Error("Refresh token is missing"), { status: 401 }));

  // Vérifier que le token est bien en base (non révoqué)
  const storedToken = await RefreshToken.findOne({ token });
  if (!storedToken) return next(Object.assign(new Error("Invalid refresh token"), { status: 403 }));

  try {
    // Vérifier validité du token
    const decoded = jwt.verify(token, JWT_REFRESH_KEY);

    // Génération d'un nouveau access_token
    const access_token = jwt.sign({ email: decoded.email }, JWT_PRIVATE_KEY, { expiresIn: "20s" });
    res.json({ result: true, access_token });
  } catch (error) {
    await RefreshToken.deleteOne({ token });
    next(error);
  }
});

router.get("/protected", authenticateToken, (_, res) => {
  res.json({ result: true });
});

module.exports = router;
