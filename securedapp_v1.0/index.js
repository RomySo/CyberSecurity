import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import session from "express-session";
import nodemailer from "nodemailer"
import env from "dotenv";
import crypto from "crypto";
import { readFile } from "node:fs/promises";

env.config();

const app = express();
const port = 3000;
app.set("view engine", "ejs");
const saltRounds = 10;

app.use(
  session({
    secret: process.env.SESSION_SECRET,
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

app.get("/sign-out", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.get("/user-screen", async (req, res) => {
  if (!req.isAuthenticated() || !req.user || !req.user.email) {
    console.log("Unauthorized access to /user-screen");
    return res.redirect("/sign-in");
  }

  try {
    // get secret data
    const email = req.user.email;
    const result = await db.query(`SELECT secret FROM users WHERE email = '${email}'`);
    

    const secret = result.rows[0]?.secret || "Store your secret data here";
    
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
    console.error("Error loading /user-screen:", err);
    res.status(500).send("Internal Server Error");
  }
});

app.get("/data-update", function (req, res) {
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

app.post("/sign-in", async (req, res) => {
  const email = req.body.username;

  try {
    const result = await db.query(
      `SELECT * FROM users WHERE email = '${email}'`
    );

    if (result.rows.length === 0) {
      return res.status(400).send("User not found");
    }

    const user = result.rows[0];

    // Skip password check — vulnerable login
    req.login(user, (err) => {
      if (err) {
        console.error("Error logging in:", err);
        return res.status(500).send("Internal Server Error");
      }
      console.log("User successfully logged in (SQLi bypass)");
      res.redirect("/user-screen");
    });
  } catch (err) {
    console.error("Error during login:", err);
    res.status(500).send("Internal Server Error");
  }
});


app.post("/sign-up", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;
  
  try {
    const checkResult = await db.query(`SELECT * FROM users WHERE email = '${email}'`);

    if (checkResult.rows.length > 0) {
      req.redirect("/sign-in");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          const result = await db.query(`INSERT INTO users (email, password) VALUES ('${email}', '${hash}') RETURNING *`);
          const user = result.rows[0];
          req.login(user, (err) => {
            console.log("success");
            res.redirect("/user-screen");
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});


app.post("/data-update", async function (req, res) {
  const submittedSecret = req.body.secret;
  const userEmail = req.user.email;

  console.log(`Data submitted: ${submittedSecret}`);

  try {
    // This is vulnerable to XSS because it saves raw HTML/JS to the DB
    await db.query(`UPDATE users SET secret = '${submittedSecret}' WHERE email = '${userEmail}'`);
    res.redirect("/user-screen");
  } catch (err) {
    console.log("Error submitting secret:", err);
    res.status(500).send("Internal Server Error");
  }
});


app.post("/change-pswd", async (req, res) => {
  const email = req.body.username;
  const currentPassword = req.body.password;
  const newPassword = req.body.newPassword;

  try {
    // Check if user exists
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      const user = checkResult.rows[0];
      const storedHashedPassword = user.password;

      // Compare current password
      const isValid = await bcrypt.compare(currentPassword, storedHashedPassword);
      if (isValid) {
        // Hash the new password
        const hashedNewPassword = await bcrypt.hash(newPassword, 10);

        // Update the password in the database
        await db.query("UPDATE users SET password = $1 WHERE email = $2", [
          hashedNewPassword,
          email,
        ]);

        console.log("Password updated successfully");
        res.redirect("/sign-in"); // Redirect to login page after successful password change
      } else {
        console.log("Incorrect current password");
        res.status(401).send("Incorrect current password");
      }
    } else {
      console.log("User not found");
      res.status(404).send("User not found");
    }
  } catch (err) {
    console.error("Error changing password:", err);
    res.status(500).send("An error occurred");
  }
});

passport.serializeUser((user, cb) => {
  cb(null, user);
});

passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect("/sign-in");
}

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
    res.status(500).send("Failed to load customer portal");
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
