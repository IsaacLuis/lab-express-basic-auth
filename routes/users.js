var express = require('express');
var router = express.Router();

const mongoose = require('mongoose');

const bcryptjs = require('bcryptjs');
const saltRounds = 10;

const User = require('../models/User.model') 

const { isLoggedIn, isLoggedOut } = require('../middleware/route-guard.js');
 
// 
router.get('/userProfile', isLoggedIn, (req, res) => {
  res.render('users/user-profile', { userInSession: req.session.currentUser });
});

/* GET users listing. */
// Sign up 
router.get('/signup', (req, res, next)=>{
  res.render('signup.hbs')
})

router.post('/signup', (req, res, next)=>{
  //console.log('logged in');
  const {username, password} = req.body;

// Empty
  if (!username || !password) {
    res.render('signup.hbs', { errorMessage: 'All fields are mandatory. Please provide your username, email and password.' });
    return;
  }


  bcryptjs
  .genSalt(saltRounds)
    .then(salt => bcryptjs.hash(password, salt))
    .then(hashedPassword => {
      return User.create({
        username,
        password: hashedPassword
      });
    })
    .then(userFromDB => {
      console.log('Newly created user is: ', userFromDB);
      res.redirect('/users/login')
    })
    .catch(error => {
      if (error instanceof mongoose.Error.ValidationError) {
        res.status(500).render('signup.hbs', { errorMessage: error.message });
      } else if (error.code === 11000) {
        res.status(500).render('signup.hbs', {
           errorMessage: 'Username and email need to be unique. Either username or email is already used.'
        });
      } else {
        next(error);
      }
    });
})




// login
router.get('/login', (req, res, next)=>{
  res.render('login.hbs')
})

router.post('/login', (req, res, next)=>{
  const {username, password} = req.body;
  if (!username || !password) {
    res.render('login.hbs')
    return;
  }

  User.findOne({username})
  .then(user=>{
    if (!user) {
      res.render('login.hbs',  { errorMessage: 'Username is not registered. Try with other email.' });
      return;
    }
    else if (bcryptjs.compareSync(password, user.password)) {
      req.session.user = user;
      console.log(req.session);
      res.redirect('users/profile'); 
    }
    else {
      res.render('login.hbs', { errorMessage: 'Incorrect password.' });
    }
  })
  .catch(error => next(error));
})

// profile 

router.get('/profile', isLoggedIn, (req, res, next) => {
  const user = req.session.user
  console.log('SESSION =====> ', req.session);
  res.render('user.hbs', { user })
})



/*
router.get('/', (req, res, next) => {
  const user = req.session.user
  res.render('user.hbs', {user});
});

router.get('/main', isLoggedOut,(req, res, next) => {
 
 res.render('main.hbs')
});


router.get('/private', isLoggedIn,(req, res, next) => {
  res.render('private.hbs')
});
*/

module.exports = router;