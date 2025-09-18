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
const app = express();
const port = 3000;
app.set("view engine", "ejs");
const saltRounds = 10;
env.config();




app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
  })
);
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});
db.connect();

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/change", (req, res) => {
  res.render("change.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/reset", (req, res) => {
  res.render("reset.ejs");
});

app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.get("/secrets", async (req, res) => {
  if (!req.isAuthenticated() || !req.user || !req.user.email) {
    console.log("Unauthorized access to /secrets");
    return res.redirect("/login");
  }

  try {
    const email = req.user.email;
    const result = await db.query(`SELECT secret FROM users WHERE email = '${email}'`);
    

    const secret = result.rows[0]?.secret || "Keep you secret information here";
    res.render("secrets.ejs", { secret });
  } catch (err) {
    console.error("Error loading /secrets:", err);
    res.status(500).send("Internal Server Error");
  }
});



app.get("/submit", function (req, res) {
  if (req.isAuthenticated()) {
    res.render("submit.ejs");
  } else {
    res.redirect("/login");
  }
});

app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

app.get("/reset", (req, res) => {
  res.render("reset.ejs");
});

app.get("/reset-fin", (req, res) => {
  res.render("reset-fin.ejs");
});

app.post("/reset", async (req, res) => {
  const email = req.body.email;

  try {
    // Check if the user exists
    const userResult = await db.query("SELECT * FROM users WHERE email = $1", [email]);

    if (userResult.rows.length === 0) {
      return res.status(400).send("User not found");
    }

    // Generate a SHA-1 reset token
    const token = crypto.createHash("sha1").update(Date.now().toString()).digest("hex");

    // Save the token in the database
    await db.query("UPDATE users SET reset_token = $1 WHERE email = $2", [token, email]);

    // Send the token to the user's email
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Password Reset Request",
      text: `Your password reset code is: ${token}\nUse this to reset your password at: http://localhost:3000/reset-fin`
    };

    await transporter.sendMail(mailOptions);

    res.redirect("/reset-fin");
  } catch (err) {
    console.error("Error handling forgot password:", err);
    res.status(500).send("Internal Server Error");
  }
});

app.post("/reset-fin", async (req, res) => {
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

    res.redirect("/login");
  } catch (err) {
    console.error("Error resetting password:", err);
    res.status(500).send("Internal Server Error");
  }
});

////////////////SUBMIT LOG IN/////////////////
app.post("/login", async (req, res) => {
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
      res.redirect("/secrets");
    });
  } catch (err) {
    console.error("Error during login:", err);
    res.status(500).send("Internal Server Error");
  }
});






////////////////SUBMIT REGISTER/////////////////
app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;
  
  try {
    const checkResult = await db.query(`SELECT * FROM users WHERE email = '${email}'`);

    if (checkResult.rows.length > 0) {
      req.redirect("/login");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          const result = await db.query(`INSERT INTO users (email, password) VALUES ('${email}', '${hash}') RETURNING *`);
          const user = result.rows[0];
          req.login(user, (err) => {
            console.log("success");
            res.redirect("/secrets");
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});


////////////////SUBMIT SECRET/////////////////
app.post("/submit", async function (req, res) {
  const submittedSecret = req.body.secret;
  const userEmail = req.user.email;

  console.log(`Secret submitted: ${submittedSecret}`);

  try {
    // This is vulnerable to XSS because it saves raw HTML/JS to the DB
    await db.query(`UPDATE users SET secret = '${submittedSecret}' WHERE email = '${userEmail}'`);
    res.redirect("/secrets");
  } catch (err) {
    console.log("Error submitting secret:", err);
    res.status(500).send("Internal Server Error");
  }
});





////////////////SUBMIT CHANGE PASSWORD/////////////////
app.post("/change", async (req, res) => {
  const email = req.body.username;
  const currentPassword = req.body.password;
  const newPassword = req.body.newpassword;

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
        res.redirect("/login"); // Redirect to login page after successful password change
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
  res.redirect("/login");
}

app.get("/customer-portal", ensureAuthenticated, async (req, res) => {
  const search = req.query.search || "";
  try {
    const result = await db.query(
      "SELECT * FROM customers WHERE LOWER(name) LIKE LOWER($1) ORDER BY id DESC",
      [`%${search}%`]
    );
    res.render("customer-portal/new-customer", { customers: result.rows, search });
  } catch (err) {
    console.error("Error fetching customers:", err);
    res.status(500).send("Failed to load customer portal");
  }
});

app.post("/customer-portal/add", ensureAuthenticated, async (req, res) => {
  const { name, lastName, email, phone } = req.body;
  try {
    await db.query(
      "INSERT INTO customers (name, email, phone) VALUES ($1, $2, $3)",
      [`${name} ${lastName}`, email, phone]
    );
    res.redirect("/customer-portal");
  } catch (err) {
    console.error("Error adding customer:", err.message);
    res.status(500).send("Error saving customer");
  }
});
