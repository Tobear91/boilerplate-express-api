const errorHandler = (err, req, res, next) => {
  res.status(err.status || 500).json({ result: false, error: err.message || "Server Error" });
};

module.exports = errorHandler;
