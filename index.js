const express = require("express");
const speakeasy = require("speakeasy");
const uuid = require("uuid");
const { JsonDB } = require("node-json-db");
const { Config } = require("node-json-db/dist/lib/JsonDBConfig");

const app = express();

app.use(express.json());

const db = new JsonDB(new Config("myDatabase", true, false, "/"));

app.get("/api", (req, res) => {
  res.json({ message: "WELCOME TO TWO FACTOR AUTHENTICATION" });
});

//Register user & create a temperaly secret

app.post("/api/register", (req, res) => {
  const id = uuid.v4();
  const temp_secret = speakeasy.generateSecret();
  try {
    const path = `/user/${id}`;

    db.push(path, { id, temp_secret });

    res.json({ id, secret: temp_secret.base32 });
  } catch (error) {
    console.log(error);

    res.status(500).json({ message: "Error Generating the secret" });
  }
});

//Verify Token and make secret permenent

app.post("/api/verify", (req, res) => {
  const { token, userId } = req.body;

  try {
    const path = `/user/${userId}`;

    const user = db.getData(path);

    const { base32: base32secret } = user.temp_secret;

    const verified = speakeasy.totp.verify({
      secret: base32secret,
      encoding: "base32",
      token: token,
    });

    if (verified) {
      db.push(path, { id: userId, secret: user.temp_secret });

      res.json({ verified: true });
    } else {
      res.json({ verified: false });
    }
  } catch (error) {
    console.log(error);

    res.status(500).json({ message: "Error Finding User" });
  }
});

//Validate token

app.post("/api/validate", (req, res) => {
  const { token, userId } = req.body;

  try {
    const path = `/user/${userId}`;

    const user = db.getData(path);

    const { base32: base32secret } = user.secret;

    const tokenValidate = speakeasy.totp.verify({
      secret: base32secret,
      encoding: "base32",
      token: token,
      window: 1,
    });

    if (tokenValidate) {
      res.json({ validated: true });
    } else {
      res.json({ validated: false });
    }
  } catch (error) {
    console.log(error);

    res.status(500).json({ message: "Error Validating User" });
  }
});

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`server running on port ${PORT}`);
});
