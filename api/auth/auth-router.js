
const express = require('express')
const router = express.Router();
const Users = require('../users/users-model');

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken')

const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // use this secret!
 /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */

router.post("/register", validateRoleName, (req, res, next) => {
  const { username, password } = req.body;
  const hash = bcrypt.hashSync(password, 12)
  const newUser = {
    username,
    password: hash,
    role_name: req.role_name
  }
  
  Users.add(newUser)
    .then(user => {
      res.status(201).json(user)
    })
    .catch(next)
});
/**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */

router.post("/login", checkUsernameExists, (req, res, next) => {
  const { username, password } = req.body;
  if(bcrypt.compareSync(password, req.user.password)){
    const token = generateToken(req.user)
    res.json({message: `${username} is back!`, token})
  } else {
    next({status: 401, message: 'Invalid credentials'})
  }
});

const generateToken = user => {
  const payload = {
    subject: user.user_id,
    username: user.username,
    role_name: user.role_name
  }
  return jwt.sign(payload, JWT_SECRET, {expiresIn: '1d'})
}

module.exports = router;
