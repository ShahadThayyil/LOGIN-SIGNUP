
    const GoogleStrategy = require('passport-google-oauth20').Strategy;
    const LocalStrategy = require('passport-local').Strategy;
    const bcrypt = require('bcryptjs');
    const User = require("../models/user");

    module.exports = (passport) => {
        // Local Strategy
        passport.use(
            new LocalStrategy({ usernameField: 'email' }, async (email, password, done) => {
                try {
                    console.log("🔹 Attempting login for:", email);
        
                    // Check if user exists
                    const user = await User.findOne({ email });
                   
                    if (!user) {
                        console.log("❌ User not found!");
                        return done(null, false, { message: "User not found" });
                    }
        
                    console.log("✅ User found:", user.email);
        
                    // Compare hashed password
                    const isMatch = await bcrypt.compare(password, user.password);
                    if (!isMatch) {
                        console.log("❌ Invalid password for:", user.email);
                        return done(null, false, { message: "Invalid password" });
                    }
        
                    console.log("✅ Password matched! Logging in...");
                    return done(null, user);
        
                } catch (err) {
                    console.error("🚨 Error in Local Strategy:", err);
                    return done(err);
                }
            })
        );
        
        // Google Strategy
        passport.use(
            new GoogleStrategy(
                {
                    clientID: process.env.GOOGLE_CLIENT_ID,
                    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
                    callbackURL: process.env.GOOGLE_CALLBACK_URL,
                },
                async (accessToken, refreshToken, profile, done) => {
                    let user = await User.findOne({ googleId: profile.id });
                    if (!user) {
                        user = await User.create({
                            name: profile.displayName,
                            email: profile.emails[0].value,
                            googleId: profile.id
                        });
                    }
                    return done(null, user);
                }
            )
        );

        // Serialize and Deserialize User
        passport.serializeUser((user, done) => {
            done(null, user.id);
        });

        passport.deserializeUser(async (id, done) => {
            const user = await User.findById(id);
            done(null, user);
        });
    };


