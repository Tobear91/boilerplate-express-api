const jwt = require("jsonwebtoken");

const JWT_PRIVATE_KEY = process.env.JWT_PRIVATE_KEY;

const authenticateToken = (req, _, next) => {
  try {
    const authHeader = req.headers.authorization;
    const bearer = authHeader && authHeader.split(" ")[1];
    if (!bearer) throw Object.assign(new Error("Access token missing"), { status: 401 });

    jwt.verify(bearer, JWT_PRIVATE_KEY);

    next();
  } catch (error) {
    next(error);
  }
};

module.exports = authenticateToken;
