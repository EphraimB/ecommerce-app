const express = require('express')
const app = express()
const passport = require('passport');
const LocalStrategy = require('passport-local');
const crypto = require('crypto');
const { Pool, Client } = require('pg');
const config = require('./config');

const port = 3000;

const pool = new Pool(config);

pool.on('error', function (err, client) {
  console.error('idle client error', err.message, err.stack);
});

passport.use(new LocalStrategy(function verify(username, password, cb) {
  db.get('SELECT * FROM users WHERE username = ?', [username], function (err, user) {
    if (err) { return cb(err); }
    if (!user) { return cb(null, false, { message: 'Incorrect username or password.' }); }

    crypto.pbkdf2(password, user.salt, 310000, 32, 'sha256', function (err, hashedPassword) {
      if (err) { return cb(err); }
      if (!crypto.timingSafeEqual(user.hashed_password, hashedPassword)) {
        return cb(null, false, { message: 'Incorrect username or password.' });
      }
      return cb(null, user);
    });
  });
})
);


app.get('/', (req, res) => {
  res.send('Hello World!')
})

app.get('/login',
  function (req, res, next) {
    res.render('login');
  });

app.post('/login/password',
  passport.authenticate('local', { failureRedirect: '/login', failureMessage: true }),
  function (req, res) {
    res.redirect('/~' + req.user.username);
  });

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})