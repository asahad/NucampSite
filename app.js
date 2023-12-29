var createError = require("http-errors");
var express = require("express");
var path = require("path");
var logger = require("morgan");
var passport = require("passport");
var config = require("./config");

var indexRouter = require("./routes/index");
var usersRouter = require("./routes/users");
const campsiteRouter = require("./routes/campsiteRouter");
const promotionRouter = require("./routes/promotionRouter");
const partnerRouter = require("./routes/partnerRouter");
const favoriteRouter = require("./routes/favoriteRouter");
const uploadRouter = require("./routes/uploadRouter");
var app = express();

app.all("*", (req, res, next) => {
  if (req.secure) {
    return next();
  } else {
    console.log(
      `Redirecting to: https://${req.hostname}:${app.get("secPort")}${req.url}`
    );
    res.redirect(
      301,
      `https://${req.hostname}:${app.get("secPort")}${req.url}`
    );
  }
});

const mongoose = require("mongoose");
const url = config.mongoUrl;
const connect = mongoose.connect(url, {
  useCreateIndex: true,
  useFindAndModify: false,
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

connect.then(
  () => console.log("Connected correctly to server"),
  (err) => console.log(err)
);

app.set("views", path.join(__dirname, "views"));
app.set("view engine", "jade");

app.use(logger("dev"));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(passport.initialize());

app.use("/", indexRouter);
app.use("/users", usersRouter);

app.use(express.static(path.join(__dirname, "public")));

function auth(req, res, next) {
  console.log(req.session);

  if (!req.session.user) {
    const err = new Error("You are not authenticated!");
    err.status = 401;
    return next(err);
  } else {
    if (req.session.user === "authenticated") {
      return next();
    } else {
      const err = new Error("You are not authenticated!");
      err.status = 401;
      return next(err);
    }
  }
}

app.use("/campsites", campsiteRouter);
app.use("/promotions", promotionRouter);
app.use("/partners", partnerRouter);
app.use("/favorites", favoriteRouter);
app.use("/imageUpload", uploadRouter);

app.use(function (req, res, next) {
  next(createError(404));
});

app.use(function (err, req, res, next) {
  res.locals.message = err.message;
  res.locals.error = req.app.get("env") === "development" ? err : {};

  res.status(err.status || 500);
  res.render("error");
});

module.exports = app;
