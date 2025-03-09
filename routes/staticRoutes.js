const express = require("express");
const router = express.Router();

router.get('/signup',(req,res)=>{
    res.render('signup');
})
router.get('/login',(req,res)=>{
    res.render('login',{message:req.flash("error")});
})
router.get('/dashboard',(req,res)=>{
    res.render('dashboard',{user:req.user});
})
module.exports = router;