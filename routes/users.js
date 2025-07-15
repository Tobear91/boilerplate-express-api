const RefreshToken = require("../models/refreshTokens");
const { checkBody } = require("../modules/helpers");
const User = require("../models/users");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const express = require("express");
const moment = require("moment");
const router = express.Router();

const JWT_PRIVATE_KEY = process.env.JWT_PRIVATE_KEY;
const JWT_REFRESH_KEY = process.env.JWT_REFRESH_KEY;

router.post("/signup", async (req, res, next) => {
  try {
    // Check fields are missing
    if (!checkBody(req.body, ["email", "password"])) throw Object.assign(new Error("Missing or empty fields"), { status: 400 });
    const { email, password } = req.body;

    // Check user in database
    let user = await User.findOne({ email });
    if (user) throw Object.assign(new Error("User already exist"), { status: 409 });

    // Add user in database
    user = await User.create({
      email,
      password: bcrypt.hashSync(password, 10),
    });

    res.json({ result: true, user });
  } catch (error) {
    next(error);
  }
});

router.post("/login", async (req, res, next) => {
  try {
    // Check fields are missing
    if (!checkBody(req.body, ["email", "password"])) throw Object.assign(new Error("Missing or empty fields"), { status: 400 });
    const { email, password } = req.body;

    // Check user in database
    let user = await User.findOne({ email });
    if (!user || (user && !bcrypt.compareSync(password, user.password))) throw Object.assign(new Error("Unauthorized"), { status: 401 });

    // Generate tokens
    const access_token = jwt.sign({ email }, JWT_PRIVATE_KEY, { expiresIn: "20s" });
    const refreshToken = jwt.sign({ email }, JWT_REFRESH_KEY, { expiresIn: "1m" });

    const expiresAt = moment().add(7, "days").toDate();
    await RefreshToken.create({ token: refreshToken, userEmail: email, expiresAt });

    // Save le refresh token en cookie HTTP-only
    res.cookie("refresh_token", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: moment().add(7, "days").diff(moment()),
    });

    user = {
      email,
      access_token,
    };

    res.json({ result: true, user });
  } catch (error) {
    next(error);
  }
});

module.exports = router;
