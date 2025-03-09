const express = require("express");
const router = express.Router();

router.get('/signup',(req,res)=>{
    res.render('signup');
})
router.get('/login',(req,res)=>{
    res.render('login');
})
function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
      return next(); // User is authenticated, proceed to dashboard
    }
    res.redirect("/auth/login"); // Redirect to login if not authenticated
  }
  
  router.get("/dashboard", ensureAuthenticated, (req, res) => {
    res.render("dashboard", { user: req.user });
  });
  
module.exports = router;