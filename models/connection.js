const mongoose = require("mongoose");

const CONNECTION_STRING = process.env.CONNECTION_STRING;

mongoose.set("strictQuery", false);
mongoose
  .connect(CONNECTION_STRING, { connectTimeoutMS: 2000 })
  .then(() => console.log("Database connected"))
  .catch((error) => console.error(error));
