//jshint esversion:6
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const _ = require("lodash");
const app = express();
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const secret = process.env.SECRET;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require("mongoose-findorcreate")
// App setup
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(
  session({
    secret: secret,
    resave: false,
    saveUninitialized: false,
  })
);
app.use(passport.initialize());
app.use(passport.session());


// Mongoose setup
const mongoose = require("mongoose");
mongoose.connect("mongodb://localhost:27017/userDB", { useNewUrlParser: true });

// Database features
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret : String
});
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate)
const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, cb) {
  process.nextTick(function() {
    cb(null, { id: user.id, username: user.username, name: user.displayName });
  });
});

passport.deserializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, user);
  });
});

passport.use(new GoogleStrategy({
  clientID: process.env.CLIENT_ID,
  clientSecret:process.env.CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/google/secrets",
  userProfileURL:"https://www.googleapis.com/oauth2/v3/userinfo"
},
(accessToken, refreshToken, profile, cb)=>{
  User.findOrCreate({ googleId: profile.id }, function (err, user) {
    return cb(err, user);
  });
}
));

// App features
app.get("/", (req, res) => {
  res.render("home");
});

// Register with google
app.get("/auth/google",passport.authenticate("google",{ scope: ["profile"] })
)

app.get("/auth/google/secrets", 
  passport.authenticate("google", { failureRedirect: "/login" }),
  (req, res)=> {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get("/login", (req, res) => {
  res.render("login");
});

app.get("/register", (req, res) => {
  res.render("register");
});

app.get("/secrets", (req, res) => {
  User.find({"secret":{$ne : null}},(err,foundUsers)=>{
    if(err){
      console.log(err)
    }else{
      if(foundUsers){
        res.render("secrets",{usersWithSecrets : foundUsers})
      }
    }
  })
});

app.get("/submit", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

app.get("/logout", (req, res) => {
  req.logout((err) => {
    if (!err) {
      res.redirect("/");
    }
  });
});
app.post("/submit",(req,res)=>{
  const submittedSecret = req.body.secret
  //Check if there is a user 
  User.findById(req.user.id,(err,foundUser)=>{
    if(err){
      console.log()
    }else{
      if(foundUser){
        foundUser.secret = submittedSecret
        foundUser.save(()=>{
          res.redirect("/secrets")
        })
      }
    }
  })
})

// Register with password and username
app.post("/register", (req, res) => {
  User.register(
    { username: req.body.username },
    req.body.password,
    (err, newUser) => {
      if (err) {
        console.log(err);
        res.redirect("/register");
      } else {
        passport.authenticate("local")(req, res, () => {
          res.redirect("/secrets");
        });
      }
    }
  );
});

app.post("/login", (req, res) => {
  const user = new User({
    username: req.body.username,
    password: req.body.password,
  });
  req.login(user, (err) => {
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, () => {
        res.redirect("/secrets");
      });
    }
  });
});
// App listen
let port = process.env.PORT;
if (port == null || port == "") {
  port = 3000;
}
app.listen(port, ()=> {
  console.log("Server started on host");
});

// With this app, I learnt how to use hashing methods such as MD5, bcrypt and passport.js
// The methods I learnt about was encryption, hashing and salting, and the use of environment variables
