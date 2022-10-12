require('dotenv').config();

const passport = require('passport');
const LocalStrategy = require('passport-local');
var GitHubStrategy = require('passport-github').Strategy;
const bcrypt = require('bcrypt');
const ObjectID = require('mongodb').ObjectID;

module.exports = function(app, myDataBase) {
  // Serialization and deserialization here...
  passport.serializeUser((user, done) => {
    done(null, user._id);
  });
  passport.deserializeUser((id, done) => {
    myDataBase.findOne({ _id: new ObjectID(id) }, (err, doc) => {
      done(null, doc);
    });
  });
  
  // Authentication

  // LocalStrategy
  passport.use(new LocalStrategy(
    function(username, password, done) {
      myDataBase.findOneAndUpdate(
        { name: username },
        {
        $set: {
            last_login: new Date()
          },
          $inc: {
            login_count: 1
          }
        },
        { upsert: true, new: true },
        (err, user)=>{
          
        if (err) { return done(err); }
        if (!user) { return done(null, false); }
        // Check the password entered against the hash
        if (!bcrypt.compareSync(password, user.value.password)) {
          return done(null, false);
        }
         return done(null, user.value);
      }
          
 );    
    }
  ));

  // Passport strategy for authenticating with GitHub 
  passport.use(new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: `${process.env.GITHUB_CLIENT_CALLBACK_URL}/auth/github/callback`
  },
    function(accessToken, refreshToken, profile, cb) {
      // console.log(profile);

      myDataBase.findOneAndUpdate(
        { id: profile.id },
        {
          $setOnInsert: {
            id: profile.id,
            name: profile.displayName || 'John Doe',
            photo: profile.photos[0].value || '',
            email: Array.isArray(profile.emails)
              ? profile.emails[0].value
              : 'No public email',
            created_on: new Date(),
            provider: profile.provider || ''
          },
          $set: {
            last_login: new Date()
          },
          $inc: {
            login_count: 1
          }
        },
        { upsert: true, new: true },
        (err, doc) => {
          // console.log(doc);
          return cb(null, doc.value);
        }
      );
    }
  ));

}