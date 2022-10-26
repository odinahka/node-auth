require('dotenv').config();
const express = require('express');
const ejs = require('ejs');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const findOrCreate = require('mongoose-findorcreate');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
//const bcrypt = require('bcrypt');
//const saltRound = 10;
//const md5 = require('md5');
//const encrypt = require('mongoose-encryption');

const app = express();
app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static('public'));
app.set('view engine', 'ejs');

const secret = process.env.SECRET;

app.use(session({
    secret,
    resave:false,
    saveUninitialized:false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect('mongodb://localhost:27017/userDB');
const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    googleId: String,
    secret: String
});
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
//userSchema.plugin(encrypt, {secret, encryptedFields:['password']});

const User = mongoose.model('User', userSchema);

passport.use(User.createStrategy());
passport.serializeUser((user, done) => {
    done(null, user.id);
});
passport.deserializeUser((id, done) => {
    User.findById(id, (err, user) => {
        done(err, user);
    })
});

const callbackURL = 'http://localhost:3000/auth/google/secrets';
//userProfileUrl:'https://www.google.com/oauth2/v3/userinfo'
passport.use(new GoogleStrategy({

    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL

}, (accessToken, refreshToken, profile, cb) => {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
        return cb(err, user);
});

}));

app.post('/register', (req, res) => {
 User.register({username: req.body.username, active: false}, req.body.password, (err, data) => {
    if(err){
        console.log(err);
        res.redirect('/register');
    } 
    else res.redirect('/login');
 })
})

app.post('/login', (req, res) => {

    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, (err) => {
        if(err) console.log(err);
        else {
            passport.authenticate('local')(req, res, () => {
                res.redirect('/secrets');
            })
        }
    })

});

app.post('/submit', (req, res) => {
  const secret = req.body.secret;
  User.findById(req.user.id, (err, user) => {
    if(err) console.log(err)
    else if(user){
        user.secret = secret;
        user.save(() => res.redirect('/secrets'));
    }
  })
});

app.get('/', (req, res) => {
    res.render('home');
});

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));

app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });


app.get('/login', (req, res) => {
    res.render('login', {message: null});
});

app.get('/register', (req, res) => {
    res.render('register');
});
app.get('/logout', (req, res) => {
    req.logout(() => res.redirect('/')); 
});
app.get('/secrets', (req, res) => {
User.find({secret: {$ne: null}}, (err, users) => {
    if(err) console.log(err);
    else{
         const secrets = []
    for (const user of users){
        secrets.push(user.secret);
    } 
    res.render('secrets', {secrets})  
    }

})
});

app.get('/submit', (req, res) => {
    if(req.isAuthenticated()){
        res.render('submit');
    }
    else res.redirect('/login');
});



app.listen(3000, () => console.log('Listening on port 3000'));
