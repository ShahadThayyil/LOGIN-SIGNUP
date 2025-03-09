require("dotenv").config();
const express = require("express");
const session = require("express-session");
const helmet = require("helmet");
const cors = require("cors");
const flash = require("connect-flash");
const rateLimit = require("express-rate-limit");
const passport = require("passport");
const methodOverride = require("method-override");
const mongoConnect = require("./config/mongoDbconnectoin");
const sanitizeHtml = require("sanitize-html");
const mongoSanitize = require("express-mongo-sanitize"); // Prevent NoSQL Injection
const xssClean = require("xss-clean"); // Additional XSS Protection
const hpp = require("hpp"); // Prevent HTTP Parameter Pollution
const compression = require("compression"); // Improve performance
const csurf = require("csurf"); // CSRF Protection
const cookieParser = require("cookie-parser"); // Needed for CSRF token handling

require("./config/passport")(passport);

const app = express();
mongoConnect();


app.use(express.static("public", { dotfiles: "deny" }));


app.set("view engine", "ejs");


app.use(express.urlencoded({ extended: true }));
app.use(express.json());


app.use(compression());

app.use(helmet());
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "trusted-cdn.com"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: [],
    },
  })
);

app.use(hpp());


app.use(mongoSanitize());


app.use(xssClean());

app.use(cookieParser());


app.use(
  session({
    secret: process.env.SECRET_KEY,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === "production", 
      httpOnly: true, 
      sameSite: "strict", 
    },
  })
);


app.use(flash());


app.use(passport.initialize());
app.use(passport.session());


const csrfProtection = csurf({ cookie: true });
app.use(csrfProtection);


app.use((req, res, next) => {
  res.locals.csrfToken = req.csrfToken(); 
  next();
});

app.use(
  cors({
    origin: process.env.ALLOWED_ORIGINS || "https://yourdomain.com",
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true,
  })
);
app.use((req, res, next) => {
  if (req.path.startsWith("/api")) {
    return next(); 
  }
  csrfProtection(req, res, next);
});


const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, 
  max: 50, 
  message: "Too many requests, please try again later.",
});
app.use(limiter);


app.use(methodOverride("_method"));


app.use((req, res, next) => {
  res.setHeader("X-XSS-Protection", "1; mode=block");
  next();
});


app.use((req, res, next) => {
  if (req.body) {
    for (let key in req.body) {
      if (typeof req.body[key] === "string") {
        req.body[key] = sanitizeHtml(req.body[key]);
      }
    }
  }
  next();
});


app.use("/auth", require("./routes/staticRoutes"));
app.use("/auth", require("./routes/authRoutes"));
app.use((err, req, res, next) => {
  if (err.code === "EBADCSRFTOKEN") {
    return res.status(403).json({ error: "Invalid CSRF token. Please try again." });
  }
  next(err);
});
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: "Something went wrong. Please try again later." });
});
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server Running on port ${PORT}`);
});
