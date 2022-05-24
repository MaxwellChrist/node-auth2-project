const router = require("express").Router();
const {   restricted, checkUsernameExists, validateRoleName, only } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // use this secret!
const Users = require('../users/users-model')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')

router.post("/register", validateRoleName, (req, res, next) => {
  let result = req.body
  const hash = bcrypt.hashSync(req.body.password, 8)
  result.password = hash

  Users.add(result)
  .then(resultSuccess => {
    res.status(201).json(resultSuccess)
  })
  .catch(next)
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
});


router.post("/login", checkUsernameExists, (req, res, next) => {
  let {username, password} = req.body
  Users.findBy({username})
  .then(([result]) => {
    if (result && bcrypt.compareSync(password, result.password)) {
      const token = generateToken(result);
      res.status(200).json({ message: `${result.username} is back!`, token })
    } else {
      next({ status: 401, message: 'Invalid Credentials' })
    }
  })
  .catch(next)
  })
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

function generateToken(result) {
  const payload = {
    subject: result.user_id,
    role_name: result.role_name,
    username: result.username,
  };
  const options = { expiresIn: '1d' };
  return jwt.sign(payload, JWT_SECRET, options);
}

module.exports = router;
