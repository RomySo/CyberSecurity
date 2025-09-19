import express from "express";
import bodyParser from "body-parser"; 
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import session from "express-session";
import nodemailer from "nodemailer";
import validatePassword from "./pswd-validation.js";
import env from "dotenv";
import crypto from "crypto";
import { readFile } from "node:fs/promises";

env.config();

const app = express();
const port = 3001;
app.set("view engine", "ejs");
const saltRounds = 10;
const tryCount = 3;

app.use(
  session({
    secret: process.env.SESSION_SECRET || "dev-secret",
    currentUser: "Unknown friend",
    resave: false,
    saveUninitialized: true,
  })
);

app.use(passport.initialize());
app.use(passport.session());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

const db = new pg.Client({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PSWD,
  port: process.env.DB_PORT,
});
db.connect();
const initquery = await readFile("init_db.sql", "utf8");
const initdb = await db.query(initquery);

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/sign-in", (req, res) => {
  res.render("sign-in.ejs");
});

app.get("/change-pswd", (req, res) => {
  res.render("change-pswd.ejs");
});

app.get("/sign-up", (req, res) => {
  res.render("sign-up.ejs");
});

app.get("/sign-out", (req, res, next) => {
  req.logout(function (err) {
    if (err) return next(err);
    res.redirect("/");
  });
});

app.get("/user-screen", async (req, res) => {
  if (req.isAuthenticated()) {
    try {
      // get secret data
      const result = await db.query(
        `SELECT secret FROM users WHERE email = $1`,
        [req.user.email]
      );
      const secret = result.rows[0]?.secret;
      // get full name
      const result2 = await db.query(
        `SELECT first_name, last_name FROM users WHERE email = $1`,
        [req.user.email]
      );
      const userFullName = result2.rows[0]?.first_name + " " + result2.rows[0]?.last_name;
      res.render("user-screen.ejs", {
        currentUser: userFullName,
        secret: secret || "Store your secret data here",
      });
    } catch (err) {
      console.error(err);
      res.redirect("/sign-in");
    }
  } else {
    res.redirect("/sign-in");
  }
});

app.get("/data-update", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("data-update.ejs");
  } else {
    res.redirect("/sign-in");
  }
});

app.get("/reset-pswd", (req, res) => {
  res.render("reset-pswd.ejs");
});

app.get("/reset-confirm", (req, res) => {
  res.render("reset-confirm.ejs");
});

app.post("/reset-pswd", async (req, res) => {
  const email = req.body.email;

  try {
    // Check user existence
    const userResult = await db.query("SELECT * FROM users WHERE email = $1", [email]);
    if (userResult.rows.length === 0) {
      return res.status(400).send("User not found");
    }

    // Create token
    const token = crypto.createHash("sha1").update(Date.now().toString()).digest("hex");

    // Save token
    await db.query("UPDATE users SET reset_token = $1 WHERE email = $2", [token, email]);

    // Send email via Gmail (use app password)
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    const mailOptions = {
      from: `Comunication LTD <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "🔐 Password Reset Request",
      text: `Hi!\n\nYour password reset code is:\n\n${token}\n\nConfirm yor reset: http://localhost:3000/reset-confirm \n\n Do not share the code with third persons!`,
    };

    await transporter.sendMail(mailOptions);
    console.log("Email sent successfully to:", email);

    res.redirect("/reset-confirm");
  } catch (err) {
    console.error("Error during password reset request:", err.message);
    res.status(500).send("Internal Server Error");
  }
});

const loginAttempts = {};

app.post("/sign-in", async (req, res, next) => {
  const username = req.body.username;

  // Check cooldown
  const { unlocked, waitTimeInMinutes } = checkLoginTimeout(username);
  if (unlocked) {
    return res.status(429).render("sign-in.ejs", {
      errorMessage: `Too many attempts. Try again in ${waitTimeInMinutes} minutes.`,
    });
  }

  passport.authenticate("local", (err, user) => {
    if (err) return next(err);

    if (!user) {
      // Ensure tracking exists (extra safety)
      if (!loginAttempts[username]) {
        loginAttempts[username] = { count: 0, lastAttempt: null };
      }
      loginAttempts[username].count += 1;
      loginAttempts[username].lastAttempt = Date.now();

      if (loginAttempts[username].count >= tryCount) {
        return res.status(429).render("sign-in.ejs", {
          errorMessage: "Too many login attempts. Please try again later.",
        });
      }

      return res.redirect("/sign-in");
    }

    // Reset on success
    loginAttempts[username] = { count: 0, lastAttempt: null };
    req.logIn(user, (err) => {
      if (err) return next(err);
      return res.redirect("/user-screen");
    });
  })(req, res, next);
});

// --- Local strategy ---
passport.use(
  "local",
  new LocalStrategy(async function verify(username, password, cb) {
    try {
      const result = await db.query("SELECT * FROM get_user_by_email($1)", [username]);
      if (result.rows.length === 0) {
        console.log("User not found");
        return cb(null, false);
      }

      const user = result.rows[0];
      const storedHashedPassword = user.password;

      bcrypt.compare(password, storedHashedPassword, (err, valid) => {
        if (err) {
          console.error("Error comparing passwords:", err);
          return cb(err);
        }
        return valid ? cb(null, user) : cb(null, false);
      });
    } catch (err) {
      console.error(err);
      return cb(err);
    }
  })
);

function checkLoginTimeout(username) {
  const currentTime = Date.now();

  if (!loginAttempts[username]) {
    loginAttempts[username] = { count: 0, lastAttempt: null };
  }

  const { count, lastAttempt } = loginAttempts[username];
  const minutes = parseInt(process.env.LOGIN_LIMIT_TIMEOUT_MINS || "15", 10);
  const timeout = minutes * 60 * 1000; // ms

  if (count >= tryCount && lastAttempt && currentTime - lastAttempt < timeout) {
    const waitMs = timeout - (currentTime - lastAttempt);
    const waitTimeInMinutes = Math.floor(waitMs / 1000 / 60);
    return { unlocked: true, waitTimeInMinutes };
  }

  return { unlocked: false };
}

// --- Submit Regiter ---
app.post("/sign-up", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;
  const fname = req.body.firstname;
  const lname = req.body.lastname;

  const validationResult = validatePassword(password);
  if (!validationResult.isValid) {
    return res.render("sign-up.ejs", {
      errorMessage: validationResult.message,
    });
  }

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [email]);
    if (checkResult.rows.length > 0) {
      return res.render("sign-up.ejs", {
        errorMessage: "User already exists. Try logging in.",
      });
    }

    const hashedPassword = await bcrypt.hash(password, saltRounds);

    const result = await db.query(
      "INSERT INTO users (first_name, last_name, email, password, password_history) VALUES ($1, $2, $3, $4, $5) RETURNING *",
      [fname, lname, email, hashedPassword, []]
    );
    const user = result.rows[0];

    req.login(user, (err) => {
      if (err) {
        console.error("Login error after registration:", err.message);
        return res.status(500).send("Error logging in after registration");
      }
      res.redirect("/user-screen");
    });
  } catch (err) {
    console.error("Registration failed:", err.message);
    res.status(500).send("Registration failed");
  }
});

// --- Submit Secret ---
app.post("/data-update", async (req, res) => {
  const submittedSecret = req.body.secret;
  try {
    await db.query(`UPDATE users SET secret = $1 WHERE email = $2`, [
      submittedSecret,
      req.user.email,
    ]);
    res.redirect("/user-screen");
  } catch (err) {
    console.log(err);
    res.redirect("/sign-in");
  }
});

// ------- Change password ----------
app.post("/change-pswd", async (req, res) => {
  const { username, currentPassword, newPassword } = req.body;
  
  console.log(username)
  console.log(currentPassword)
  console.log(newPassword)

  const userEmail = username;

  const validationResult = validatePassword(newPassword);
  if (!validationResult.isValid) {
    return res.render("change-pswd.ejs", {
      errorMessage: validationResult.message,
    });
  }

  try {
    const result = await db.query(
      "SELECT password, password_history FROM users WHERE email = $1",
      [userEmail]
    );
    if (result.rows.length === 0) {
      return res.status(404).render("change-pswd.ejs", { errorMessage: "User not found." });
    }

    const { password, password_history } = result.rows[0];
    const currentHashedPassword = password;

    const isMatch = await bcrypt.compare(currentPassword, currentHashedPassword);
    if (!isMatch) {
      return res.status(400).render("change-pswd.ejs", {
        errorMessage: "Current password is incorrect.",
      });
    }

    for (const hashedPassword of password_history) {
      if (await bcrypt.compare(newPassword, hashedPassword)) {
        return res.status(400).render("change-pswd.ejs", {
          errorMessage:
            "New password cannot be the same as one of your recent passwords.",
        });
      }
    }

    const hashedNewPassword = await bcrypt.hash(newPassword, saltRounds);
    const updatedPasswordHistory = [currentHashedPassword, ...password_history].slice(0, 2);

    await db.query(
      "UPDATE users SET password = $1, password_history = $2 WHERE email = $3",
      [hashedNewPassword, updatedPasswordHistory, userEmail]
    );

    res.status(201).render("change-pswd.ejs", {
      successMessage: "Password updated successfully.",
    });
  } catch (err) {
    console.error("Error updating password:", err);
    res.status(500).render("change-pswd.ejs", {
      errorMessage: "An error occurred while updating your password.",
    });
  }
});

// --- Passport session ---
passport.serializeUser((user, cb) => {
  cb(null, user);
});
passport.deserializeUser((user, cb) => {
  cb(null, user);
});

// --- Auth guard ---
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect("/sign-in");
}

// --- Customer portal (still protected) ---
app.get("/customers", ensureAuthenticated, async (req, res) => {
  const search = req.query.search || "";
  try {
    const result = await db.query(
      "SELECT * FROM customers WHERE LOWER(name) LIKE LOWER($1) ORDER BY id DESC",
      [`%${search}%`]
    );
    res.render("customers/add-new", { customers: result.rows, search });
  } catch (err) {
    console.error("Error fetching customers:", err);
    res.status(500).send("Failed to load customers list");
  }
});

app.post("/customers/add-new", ensureAuthenticated, async (req, res) => {
  const { name, lastName, email, phone } = req.body;
  try {
    await db.query(
      "INSERT INTO customers (name, email, phone) VALUES ($1, $2, $3)",
      [`${name} ${lastName}`, email, phone]
    );
    res.redirect("/customers");
  } catch (err) {
    console.error("Error adding customer:", err.message);
    res.status(500).send("Error saving customer");
  }
});

app.post("/reset-confirm", async (req, res) => {
  const { email, token, newPassword } = req.body;
  console.log(`'${email}' + '${token}'`)
  try {
    // Verify the token
    const result = await db.query("SELECT * FROM users WHERE email = $1 AND reset_token = $2", [email, token]);

    if (result.rows.length === 0) {
      return res.status(400).send("Invalid reset token.");
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

    // Update the password in the database
    await db.query("UPDATE users SET password = $1, reset_token = NULL WHERE email = $2", [hashedPassword, email]);

    res.redirect("/sign-in");
  } catch (err) {
    console.error("Error resetting password:", err);
    res.status(500).send("Internal Server Error");
  }
});


app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
