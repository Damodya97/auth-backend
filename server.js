require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { TableClient } = require("@azure/data-tables");

const app = express();
app.use(cors());
app.use(express.json());

const tableClient = TableClient.fromConnectionString(
  process.env.AZURE_CONNECTION_STRING,
  "Users"
);

// SIGNUP
app.post("/signup", async (req, res) => {
  const { email, password } = req.body;

  const hashedPassword = await bcrypt.hash(password, 10);

  const entity = {
    partitionKey: "users",
    rowKey: email,
    email: email,
    password: hashedPassword
  };

  try {
    await tableClient.createEntity(entity);
    res.json({ message: "User registered successfully" });
  } catch (err) {
    res.status(400).json({ error: "User already exists" });
  }
});

// LOGIN
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await tableClient.getEntity("users", email);

    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword) {
      return res.status(401).json({ error: "Invalid password" });
    }

    const token = jwt.sign({ email }, process.env.JWT_SECRET, {
      expiresIn: "1h"
    });

    res.json({ token });
  } catch (err) {
    res.status(404).json({ error: "User not found" });
  }
});

app.listen(process.env.PORT, () => {
  console.log("Server running on port 5000");
});
