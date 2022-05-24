const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets")
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
})

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