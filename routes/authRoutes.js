const express = require("express");
const passport = require("passport");
const bcrypt = require("bcryptjs");
const User = require("../models/user");
const rateLimit = require("express-rate-limit");
const sanitizeHtml = require("sanitize-html");
const { body, validationResult } = require("express-validator");
const csrf = require("csurf");

const router = express.Router();
const csrfProtection = csrf({ cookie: true });

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, 
  max: 10, 
  message: "Too many login/signup attempts. Please try again later.",
});


const validateUserInput = [
  body("name").trim().isLength({ min: 3 }).escape().withMessage("Name must be at least 3 characters."),
  body("email").isEmail().normalizeEmail().withMessage("Invalid email format."),
  body("password").isLength({ min: 8 }).withMessage("Password must be at least 8 characters."),
];


router.post("/signup", authLimiter, csrfProtection, validateUserInput, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  let { name, email, password } = req.body;

  name = sanitizeHtml(name);
  email = sanitizeHtml(email);

  let user = await User.findOne({ email });
  if (user) return res.redirect("/login");

  const hashedPassword = await bcrypt.hash(password, 12);
  user = new User({ name, email, password: hashedPassword });

  await user.save();
  res.redirect("/auth/login");
});
router.post("/login", authLimiter, csrfProtection, (req, res, next) => {
  passport.authenticate("local", (err, user, info) => {
    if (err) return next(err);
    if (!user) return res.redirect("/auth/login");

    req.logIn(user, (err) => {
      if (err) return next(err);
      req.session.regenerate(() => {  
        res.redirect("/auth/dashboard");
      });
    });
  })(req, res, next);
});

// router.post("/login", authLimiter, csrfProtection, (req, res, next) => {
//   passport.authenticate("local", (err, user, info) => {
//     if (err) {
//       console.error("Login error:", err);
//       return res.status(500).json({ error: "Internal server error. Please try again." });
//     }
//     if (!user) {
//       console.log("Login failed:", info.message);
//       return res.status(401).json({ error: info.message || "Invalid credentials" });
//     }

//     req.logIn(user, (err) => {
//       if (err) {
//         console.error("Session error:", err);
//         return res.status(500).json({ error: "Session error. Please try again." });
//       }

//       req.session.regenerate((err) => {  
//         if (err) {
//           console.error("Session regeneration error:", err);
//           return res.status(500).json({ error: "Failed to create session." });
//         }

//         console.log(`User ${user.email} logged in successfully.`);
//         res.redirect("/auth/dashboard");
//       });
//     });
//   })(req, res, next);
// });
router.get("/google", csrfProtection, passport.authenticate("google", { scope: ["profile", "email"] }));
router.get("/google/callback", csrfProtection, passport.authenticate("google", { successRedirect: "/auth/dashboard", failureRedirect: "/auth/login" }));


router.get("/logout", csrfProtection, (req, res) => {
  req.logout(() => {
    req.session.destroy((err) => {
      if (err) return res.status(500).json({ error: "Logout failed" });
      res.clearCookie("connect.sid"); 
      res.redirect("/auth/login");
    });
  });
});

module.exports = router;
