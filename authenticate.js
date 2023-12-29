const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const User = require("./models/user");
const JwtStrategy = require("passport-jwt").Strategy;
const ExtractJwt = require("passport-jwt").ExtractJwt;
const jwt = require("jsonwebtoken"); 
const config = require("./config.js");

// Use the LocalStrategy within Passport.
exports.local = passport.use(new LocalStrategy(User.authenticate()));
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

// Function to get a token.
exports.getToken = function (user) {
  return jwt.sign(user, config.secretKey, { expiresIn: 3600 });
};

const opts = {};
opts.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken();
opts.secretOrKey = config.secretKey;

// Setup the JWT Passport strategy.
exports.jwtPassport = passport.use(
  new JwtStrategy(opts, (jwt_payload, done) => {
    console.log("JWT payload:", jwt_payload);
    User.findOne({ _id: jwt_payload._id }, (err, user) => {
      if (err) {
        return done(err, false);
      } else if (user) {
        return done(null, user);
      } else {
        return done(null, false);
      }
    });
  })
);

// Middleware to verify a user.
exports.verifyUser = passport.authenticate("jwt", { session: false });

// Middleware to verify an admin user.
exports.verifyAdmin = function (req, res, next) {
  if (req.user && req.user.admin) {
    // User is admin, pass control to the next middleware
    next();
  } else {
    // User is not admin or not authenticated
    const err = new Error("You are not authorized to perform this operation!");
    err.status = 403;
    next(err);
  }
};
