import bcrypt from "bcrypt";
import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import "dotenv/config";

// variables
const app = express();
const port = 3000;
const saltRounds = 11;

// db setup
const db = new pg.Client({
  user: "postgres",
  host: "localhost",
  database: "users",
  password: process.env.DB_PASS,
  port: 5432,
});
db.connect();

// middlewares
app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));
app.set("view engine", "ejs");

// endpoint
// home page
app.get("/", (req, res) => {
  try {
    res.render("home");
  } catch (err) {
    console.error("Can't render home page.", err);
    res.status(500).send("Internal Server Error.");
  }
});

// registering a user
app.get("/register/", (req, res) => {
  try {
    res.render("register");
  } catch (err) {
    console.error("Can't render register.", err);
    res.status(500).send("Internal Server Error.");
  }
});

app.post("/register/", async (req, res) => {
  try {
    bcrypt.hash(req.body.password, saltRounds, async (err, hash) => {
      await db.query(
        "INSERT INTO users (email, password)\
        VALUES ($1, $2)",
        [req.body.username, hash]
      );
      if (err) console.error("Can't hash password.", err);
    });
    res.render("secrets");
  } catch (error) {
    console.error("Can't register user.", error);
    res.status(500).send("Internal Server Error.");
  }
});

// logging a user
app.get("/login/", (req, res) => {
  try {
    res.render("login");
  } catch (err) {
    console.error("Can't render login.", err);
    res.status(500).send("Internal Server Error.");
  }
});

app.post("/login/", async (req, res) => {
  try {
    const result = await db.query("SELECT * FROM users");
    const user = result.rows.find((item) => item.email === req.body.username);

    bcrypt.compare(req.body.password, user.password, (err, result) => {
      if (result) res.render("secrets");
      else res.redirect("/login");

      if (err) console.error("Can't check password.", err);
    });
  } catch (error) {
    console.error("User doesn't exist.", error);
    res.status(500).send("Internal Server Error.");
  }
});

app.listen(port, () => {
  console.log(`Server running on port: ${port}.`);
});
