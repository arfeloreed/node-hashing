import bcrypt from "bcrypt";
import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import session from "express-session";
import passport from "passport";
import LocalStrategy from "passport-local";
import GoogleStrategy from "passport-google-oauth20";
import "dotenv/config";

// variables
const app = express();
const port = 3000;
const saltRounds = 11;

// db setup
const db = new pg.Client({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_DATABASE,
  password: process.env.DB_PASS,
  port: process.env.DB_PORT,
});
db.connect();

// middlewares
app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));
app.set("view engine", "ejs");
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
  })
);
app.use(passport.initialize());
app.use(passport.session());

// custom middlewares
function authRequired(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect("/login");
}

// passport setup
passport.use(
  new LocalStrategy(async function verify(username, password, cb) {
    let user;
    try {
      const response = await db.query("SELECT * FROM users WHERE email = $1", [username]);
      if (response.rows.length > 0) {
        user = response.rows[0];

        bcrypt.compare(password, user.password, (err, result) => {
          if (err) return cb(err);
          if (!result)
            return cb(null, false, { message: "Incorrect username or password" });

          return cb(null, user);
        });
      } else {
        bcrypt.hash(password, saltRounds, async (err, hash) => {
          const addUser = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id, email",
            [username, hash]
          );
          user = {
            id: addUser.rows[0].id,
            username: addUser.rows[0].email,
          };

          if (err) return cb(err);
          return cb(null, user);
        });
      }
    } catch (err) {
      return cb(err);
    }
  })
);
passport.serializeUser((user, cb) => {
  process.nextTick(() => {
    return cb(null, {
      id: user.id,
      username: user.username,
    });
  });
});
passport.deserializeUser((user, cb) => {
  process.nextTick(() => {
    return cb(null, user);
  });
});
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (accessToken, refreshToken, profile, cb) => {
      let user;
      try {
        const result = await db.query("SELECT * FROM users WHERE google_id = $1", [
          profile.id,
        ]);
        if (result.rows.length > 0) {
          user = result.rows[0];
          return cb(null, user);
        } else {
          const addUser = await db.query(
            "INSERT INTO users (email, google_id) VALUES ($1, $2) RETURNING id, email",
            [profile.displayName, profile.id]
          );
          user = {
            id: addUser.rows[0].id,
            username: addUser.rows[0].email,
          };
          return cb(null, user);
        }
      } catch (err) {
        return cb(err);
      }
    }
  )
);

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

app.post(
  "/register/",
  passport.authenticate("local", { failureRedirect: "/login" }),
  async (req, res) => {
    res.redirect("/secrets");
    // try {
    //   bcrypt.hash(req.body.password, saltRounds, async (err, hash) => {
    //     await db.query(
    //       "INSERT INTO users (email, password)\
    //       VALUES ($1, $2)",
    //       [req.body.username, hash]
    //     );
    //     if (err) console.error("Can't hash password.", err);
    //   });
    //   // res.render("secrets");
    //   res.redirect("/login");
    // } catch (error) {
    //   console.error("Can't register user.", error);
    //   res.status(500).send("Internal Server Error.");
    // }
  }
);

// logging a user
app.get("/login/", (req, res) => {
  try {
    res.render("login");
  } catch (err) {
    console.error("Can't render login.", err);
    res.status(500).send("Internal Server Error.");
  }
});

app.post(
  "/login/",
  passport.authenticate("local", { failureRedirect: "/login", failureMessage: true }),
  async (req, res) => {
    res.redirect("/secrets");
    // try {
    //   const result = await db.query("SELECT * FROM users");
    //   const user = result.rows.find((item) => item.email === req.body.username);
    //   bcrypt.compare(req.body.password, user.password, (err, result) => {
    //     if (result) res.render("secrets");
    //     else res.redirect("/login");
    //     if (err) console.error("Can't check password.", err);
    //   });
    // } catch (error) {
    //   console.error("User doesn't exist.", error);
    //   res.status(500).send("Internal Server Error.");
    // }
  }
);

app.get("/logout/", (req, res, next) => {
  req.logout((err) => {
    if (err) return next(err);
    res.redirect("/");
  });
});

// google Oauth
app.get("/auth/google/", passport.authenticate("google", { scope: ["profile"] }));

app.get(
  "/auth/google/secrets/",
  passport.authenticate("google", { failureRedirect: "/login" }),
  (req, res) => {
    res.redirect("/secrets");
  }
);

// secrets page
app.get("/secrets/", authRequired, async (req, res) => {
  try {
    const result = await db.query("SELECT * FROM secrets");
    const secrets = result.rows;

    res.render("secrets", {
      secrets: secrets,
    });
  } catch (err) {
    console.error("Can't render secrets.", err);
    res.status(500).send("Internal Server Error.");
  }
});

// submitting a secret
app.get("/submit/", authRequired, async (req, res) => {
  // console.log(req.user);
  try {
    res.render("submit");
  } catch (err) {
    console.error("Can't render submit.", err);
    res.status(500).send("Internal Server Error.");
  }
});

app.post("/submit/", async (req, res) => {
  try {
    await db.query("INSERT INTO secrets (user_id, secret) VALUES ($1, $2)", [
      parseInt(req.user.id),
      req.body.secret,
    ]);

    res.redirect("/secrets");
  } catch (err) {
    console.error("Can't add secret.", err);
    res.status(500).send("Internal Server Error.");
  }
});

app.listen(port, () => {
  console.log(`Server running on port: ${port}.`);
});
