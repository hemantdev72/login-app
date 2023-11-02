//jshint esversion:6
const express=require('express');
const app=express();
const ejs=require('ejs');
const mongoose=require('mongoose');
const encrypt=require('mongoose-encryption');
const md5=require('md5');
// const bcrypt=require('bcrypt');
const saltRounds=2;
const session=require('express-session');
const passport=require('passport');
const passportLocalMongoose=require('passport-local-mongoose');
const clientId='15886';
const clientSecret='GOCS';
const GoogleStrategy=require('passport-google-oauth20').Strategy;
const findorcreate=require('mongoose-findorcreate');

app.use(express.static('public'));
app.set('view engine','ejs');
app.use(express.urlencoded({extended:true}));

app.use(session({
    secret:'Out little Secret',
    resave:false,
    saveUninitialized:false,
}))


app.use(passport.initialize());
app.use(passport.session());

mongoose.connect('mongodb://127.0.0.1:27017/loginapp',{
    useNewUrlParser:true,useUnifiedTopology:true})
    .then(()=>{console.log('connection established')})
    .catch((err)=>{
        console.log(err);
    })

const userSchema= new mongoose.Schema({
    email:String,
    password:String,
    googleid:String
});

const secret='Thisisourlittlesecret';

// userSchema.plugin(encrypt,{secret:secret, encryptedFields:['password']});
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findorcreate);

const User=new mongoose.model('User',userSchema);

passport.use(User.createStrategy());
passport.serializeUser(function(user,done){
    done(null,user.id);
});
passport.deserializeUser(function(id, done) {
    User.findById(id)
        .then(user => {
            done(null, user);
        })
        .catch(err => {
            done(err, null);
        });
});

passport.use(new GoogleStrategy({
    clientID: clientId,
    clientSecret: clientSecret,
    callbackURL: 'http://localhost:3000/auth/google/secrets',
    userProfileURL: 'https://www.googleapis.com/oauth2/v3/userinfo',
    passReqToCallback: true, // Add this line
},
function (req, accessToken, refreshToken, profile, cb) {
    console.log(profile); // Output profile data for debugging
    User.findOrCreate({ googleid: profile.id }, function (err, user) {
        return cb(err, user);
    });
}));

app.get('/',(req,res)=>{
    res.render('home');
})

app.get('/auth/google', (req, res) => {
    passport.authenticate('google', { scope: ["profile"] })(req, res); // Call passport.authenticate
});

// Add a route for the Google callback URL
app.get('/auth/google/secrets',
    passport.authenticate('google', { failureRedirect: '/login' }), // Use passport.authenticate
    function (req, res) {
        // Successful authentication, redirect to a suitable page
        res.redirect('/secrets');
    }
);



app.get('/login',(req,res)=>{
    res.render('login');
})

app.get('/register',(req,res)=>{
    res.render('register');
});

app.get('/secrets',(req,res)=>{
    if(req.isAuthenticated()){
        res.render('secrets');
    } else{
        res.redirect('/login');
    }
})

app.get('/logout',(req,res)=>{
    req.logout((err)=>{
        if(err){
            console.log(err);
        }
    });
    res.redirect('/');
})

app.post('/register', (req,res)=>{
    User.register({username:req.body.username},req.body.password,function(err,user){
        if(err){
            console.log(err);
            res.redirect('/register');
        } else{
            passport.authenticate('local')(req,res,function(){
                res.redirect('/secrets');
            })
        }
    })
});

app.post('/login', (req, res) => {
    const user=new User({
        username:req.body.username,
        password:req.body.password
    })

    req.login(user,function(err){
        if(err){
            console.log(err);
        } else{
            passport.authenticate('local')(req,res,function(){
                res.redirect('/secrets');
            })
        }
    })

});
    


app.listen(3000,()=>{
    console.log('server running successfully');
})
