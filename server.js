//Importing packages and modules
require("dotenv/config");
const express = require("express");
const path = require("path");
const mongoose = require("mongoose");
const User = require("./model/user");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

//Connecting to mongo database
mongoose.connect(
  process.env.URL,
  { useNewUrlParser: true, useUnifiedTopology: true, useCreateIndex: true },
  () => {
    console.log("Connected to the database");
  }
);

//Initializaing express apps
const app = express();

//Middlewares for static view pages
app.use("/", express.static(path.join(__dirname, "static")));
app.use(express.json());

//POST request for changing the user password from database
app.post("/api/change-password", async (req, res) => {
  const { token, newPassword } = req.body;

  if (!newPassword || typeof newPassword !== "string") {
    return res.json({ status: "error", error: "Invalid password" });
  }

  if (newPassword.length < 5) {
    return res.json({
      status: "error",
      error: "Password to small. Should be at least 6 characters",
    });
  }
  try {
    const user = jwt.verify(token, process.env.JWT_SECRET);
    const _id = user.id;
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    //Updating user data in the database
    await User.updateOne(
      { _id },
      {
        $set: { password: hashedPassword },
      }
    );
    res.json({ status: "ok" });
  } catch (err) {
    res.json({ status: "error", error: err });
  }
});

//POST request for user to log in
app.post("/api/login", async (req, res) => {
  const { username, loginpassword } = req.body;
  //Finding user from the database based on user's email
  const user = await User.findOne({ username }).lean();

  if (!user) {
    return res.json({
      status: "error",
      error: "Invalid username/password",
    });
  }

  //Comparing hashed password in the database with provided plain password
  if (await bcrypt.compare(loginpassword, user.password)) {
    //Signing the payload and creating a token
    const token = jwt.sign(
      { id: user._id, username: user.username },
      process.env.JWT_SECRET
    );
    return res.json({ status: "ok", data: token });
  }
  res.send({ status: "ok", data: "Coming Soon" });
});

//POST request for user to register details in the database
app.post("/api/register", async (req, res) => {
  if (!req.body.username || typeof req.body.username !== "string") {
    return res.json({ status: "error", error: "Invalid username" });
  }

  if (!req.body.password || typeof req.body.username !== "string") {
    return res.json({ status: "error", error: "Invalid password" });
  }

  if (req.body.password.length < 5) {
    return res.json({
      status: "error",
      error: "Password to small. Should be at least 6 characters",
    });
  }

  //Hashing the password provided by user
  const hashedPassword = await bcrypt.hash(req.body.password, 10);
  try {
    const response = await User.create({
      username: req.body.username,
      password: hashedPassword,
    });
    console.log("User created Successfully: ", response);
  } catch (err) {
    if (err.code === 11000) {
      //Duplicate key
      return res.json({ status: "error", error: "Username already in use!" });
    }
    throw error;
  }
  res.json({ status: "ok" });
});

app.listen(3000, () => {
  console.log("Server listening on port 3000");
});
