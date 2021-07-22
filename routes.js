const passport = require('passport');
const bcrypt = require('bcrypt');
const moment = require('moment');
module.exports = function(app, myDataBase) {
  // middle to check if user is Authenticated before render '/profile'
  const ensureAuthenticated = (req, res, next) => {
    if (req.isAuthenticated()) {
      return next();
    }
    res.redirect('/');
  };


  // Social Authentication
  app.route('/auth/github').get(passport.authenticate('github'));

  app.route('/auth/github/callback').get(
    passport.authenticate('github', { failureRedirect: '/' }),
    (req, res) => {
      // Successful authentication, redirect /chat.
      req.session.user_id = req.user.id
      res.redirect('/chat');

      // // Successful authentication, redirect profile.
      // res.redirect('/profile');
    });

  // Your page will not load until you correctly render the index file in the views/pug directory.
  app.route('/').get((req, res) => {
    // Change the response to render the Pug template
    res.render('pug', {
      showLogin: true,
      showRegistration: false,
    });
  });

  // Change the response to render the signup template
  app.route('/signup').get((req, res) => {
    res.render('pug', {
      showLogin: false,
      showRegistration: true,
    });
  });

  // Change the response to render the signin template
  app.route('/signin').get((req, res) => {
    res.render('pug', {
      showLogin: true,
      showRegistration: false,
    });
  });

  // set up to accept the POST and authenticate the user.
  app.route('/login').post(
    passport.authenticate('local', { failureRedirect: '/' }),
    (req, res) => {
      res.redirect('/chat');
    });

  // Logging a User Out
  app.route('/logout').get(
    (req, res) => {
      req.logout();
      res.redirect('/');
    });

  // Registration of New Users
  app.route('/register')
    .post((req, res, next) => {
      console.log(req.body);
      // Query database 
      myDataBase.findOne(
        { username: req.body.username },
        (err, user) => {
          // handel db errors 
          if (err) next(err);
          // handle user exist
          else if (user) res.redirect('/');
          // handel new user 
          else {
            // Hashing Passwords
            const hashed = bcrypt.hashSync(req.body.password, 12);
            console.log(hashed);
            myDataBase.insertOne({
              created_on: new Date(),
              email: 'No public email',
              last_login: new Date(),
              login_count: 0,
              name: req.body.username,
              password: hashed,
              photo: 'https://avatars.githubusercontent.com/u/66945410?v=4',

            }, (err, doc) => {
              if (err) { res.redirect('/'); }
              else {
                // The inserted document is held within
                // the ops property of the doc
                next(null, doc.ops[0]);
              }
            });
          }


        }
      )
    },//next()  authenticating the new user to allow him to access to /profile

      passport.authenticate('local', { failureRedirect: '/' }),
      (req, res, next) => {
        res.redirect('/chat');
      }

    );


  // render the view profile.pug after A successful authentication
  app.route('/profile').get(
    ensureAuthenticated,
    (req, res) => {
      console.log();
      res.render(
        __dirname + '/views/pug/profile',
        {
          name: req.user.name,
          photo: req.user.photo,
          email: req.user.email,
          login_count: req.user.login_count,
          joined: moment(req.user.created_on).subtract('days').calendar()
        }
      );
    });

  app.route('/chat')
    .get(ensureAuthenticated,
      (req, res) => {
        res.render(
          __dirname + '/views/pug/chat',
          { user: req.user }

        )
      });




  // handling 404 error by following middleware
  app.use((req, res, next) => {
    res.status(404)
      .type('text')
      .send('Not Found');
  });

}
